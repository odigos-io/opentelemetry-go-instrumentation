package opentelemetry

import (
	"context"
	"fmt"
	"github.com/keyval-dev/opentelemetry-go-instrumentation/pkg/instrumentors/events"
	"github.com/keyval-dev/opentelemetry-go-instrumentation/pkg/log"
	"github.com/prometheus/procfs"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.7.0"
	"go.opentelemetry.io/otel/trace"
	"google.golang.org/grpc"
	"os"
	"time"
)

const (
	otelEndpointEnvVar    = "OTEL_EXPORTER_OTLP_ENDPOINT"
	otelServiceNameEnvVar = "OTEL_SERVICE_NAME"
)

type Controller struct {
	tracerProvider trace.TracerProvider
	tracersMap     map[string]trace.Tracer
	contextsMap    map[int64]context.Context // TODO: Use LRU cache
	bootTime       int64
}

func (c *Controller) getTracer(libName string) trace.Tracer {
	t, exists := c.tracersMap[libName]
	if exists {
		return t
	}

	newTracer := c.tracerProvider.Tracer(libName)
	c.tracersMap[libName] = newTracer
	return newTracer
}

func (c *Controller) Trace(event *events.Event) {
	log.Logger.V(0).Info("got event", "attrs", event.Attributes, "goroutine", event.GoroutineUID)
	ctx := context.Background()
	//attrs := append(event.Attributes, attribute.Key("goroutine.id").Int64(event.GoroutineUID))

	if event.SpanContext == nil {
		log.Logger.V(0).Info("got event without context - dropping")
		return
	}

	// TODO: handle remote parent
	if event.ParentSpanContext != nil {
		ctx = trace.ContextWithSpanContext(ctx, *event.ParentSpanContext)
	}

	ctx = ContextWithEbpfEvent(ctx, *event)
	_, span := c.getTracer(event.Library).
		Start(ctx, event.Name,
			trace.WithAttributes(event.Attributes...),
			trace.WithSpanKind(event.Kind),
			trace.WithTimestamp(c.convertTime(event.StartTime)))
	//c.updateContext(event.GoroutineUID, newCtx)
	span.End(trace.WithTimestamp(c.convertTime(event.EndTime)))
}

func (c *Controller) convertTime(t int64) time.Time {
	return time.Unix(0, c.bootTime+t)
}

func (c *Controller) getContext(goroutine int64) context.Context {
	ctx, exists := c.contextsMap[goroutine]
	if exists {
		return ctx
	}

	newCtx := context.Background()
	c.contextsMap[goroutine] = newCtx
	return newCtx
}

func (c *Controller) updateContext(goroutine int64, ctx context.Context) {
	c.contextsMap[goroutine] = ctx
}

func NewController() (*Controller, error) {
	endpoint, exists := os.LookupEnv(otelEndpointEnvVar)
	if !exists {
		return nil, fmt.Errorf("%s env var must be set", otelEndpointEnvVar)
	}

	serviceName, exists := os.LookupEnv(otelServiceNameEnvVar)
	if !exists {
		return nil, fmt.Errorf("%s env var must be set", otelServiceNameEnvVar)
	}

	ctx := context.Background()
	res, err := resource.New(ctx,
		resource.WithAttributes(
			semconv.ServiceNameKey.String(serviceName),
			semconv.TelemetrySDKLanguageGo,
		),
	)
	if err != nil {
		return nil, err
	}

	log.Logger.V(0).Info("Establishing connection to OpenTelemetry collector ...")
	timeoutContext, cancel := context.WithTimeout(ctx, time.Second*10)
	defer cancel()
	conn, err := grpc.DialContext(timeoutContext, endpoint, grpc.WithInsecure(), grpc.WithBlock())
	if err != nil {
		log.Logger.Error(err, "unable to connect to OpenTelemetry collector", "addr", endpoint)
		return nil, err
	}

	traceExporter, err := otlptracegrpc.New(ctx,
		otlptracegrpc.WithGRPCConn(conn),
	)

	if err != nil {
		return nil, err
	}

	bsp := sdktrace.NewBatchSpanProcessor(traceExporter)
	tracerProvider := sdktrace.NewTracerProvider(
		sdktrace.WithSampler(sdktrace.AlwaysSample()),
		sdktrace.WithResource(res),
		sdktrace.WithSpanProcessor(bsp),
		sdktrace.WithIDGenerator(NewEbpfSourceIDGenerator()),
	)

	boot, err := getBootTime()
	if err != nil {
		return nil, err
	}
	bootNano := boot.UnixNano()

	return &Controller{
		tracerProvider: tracerProvider,
		tracersMap:     make(map[string]trace.Tracer),
		contextsMap:    make(map[int64]context.Context),
		bootTime:       bootNano,
	}, nil
}

func getBootTime() (*time.Time, error) {
	fs, err := procfs.NewDefaultFS()
	if err != nil {
		return nil, err
	}

	stat, err := fs.Stat()
	if err != nil {
		return nil, err
	}

	boot := time.Unix(int64(stat.BootTime), 0)
	return &boot, nil
}
