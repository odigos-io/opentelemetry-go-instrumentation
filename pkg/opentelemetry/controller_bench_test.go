package opentelemetry

import (
	"bytes"
	"context"
	"encoding/binary"
	"io"
	"testing"

	"github.com/keyval-dev/opentelemetry-go-instrumentation/pkg/instrumentors/events"
	"github.com/keyval-dev/opentelemetry-go-instrumentation/pkg/log"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/exporters/stdout/stdouttrace"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/trace"
)

func init() {
	_ = log.Init()
}

type nopExporter struct{}

func (nopExporter) ExportSpans(context.Context, []sdktrace.ReadOnlySpan) error { return nil }
func (nopExporter) Shutdown(context.Context) error                             { return nil }

func newBenchController(tb testing.TB, discardStdout bool) *Controller {
	tb.Helper()
	var sp sdktrace.SpanProcessor
	if discardStdout {
		exp, err := stdouttrace.New(stdouttrace.WithWriter(io.Discard))
		if err != nil {
			tb.Fatal(err)
		}
		sp = sdktrace.NewSimpleSpanProcessor(exp)
	} else {
		sp = sdktrace.NewSimpleSpanProcessor(nopExporter{})
	}
	tp := sdktrace.NewTracerProvider(
		sdktrace.WithSampler(sdktrace.AlwaysSample()),
		sdktrace.WithSpanProcessor(sp),
		sdktrace.WithIDGenerator(NewEbpfSourceIDGenerator()),
	)
	return &Controller{
		tracerProvider: tp,
		tracersMap:     make(map[string]trace.Tracer),
		bootTime:       0,
	}
}

func benchEvent() *events.Event {
	sc := trace.NewSpanContext(trace.SpanContextConfig{
		TraceID:    trace.TraceID{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16},
		SpanID:     trace.SpanID{1, 2, 3, 4, 5, 6, 7, 8},
		TraceFlags: trace.FlagsSampled,
	})
	return &events.Event{
		Library:     "net/http",
		Name:        "/api/v1/users",
		Kind:        trace.SpanKindServer,
		StartTime:   1_000_000,
		EndTime:     2_000_000,
		SpanContext: &sc,
		Attributes: []attribute.KeyValue{
			attribute.String("http.method", "GET"),
			attribute.String("http.target", "/api/v1/users"),
		},
	}
}

// BenchmarkTrace measures the userspace exporter hot path used once per eBPF span event.
func BenchmarkTrace(b *testing.B) {
	c := newBenchController(b, false)
	ev := benchEvent()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		c.Trace(ev)
	}
}

func BenchmarkContextWithEbpfEvent(b *testing.B) {
	ev := benchEvent()
	ctx := context.Background()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = ContextWithEbpfEvent(ctx, ev)
	}
}

// Mirrors probe event layout used by net/http and gorilla/mux instrumentors.
type httpProbeEvent struct {
	StartTime uint64
	EndTime   uint64
	Method    [100]byte
	Path      [100]byte
}

func sampleProbeBytes(b *testing.B) []byte {
	b.Helper()
	var ev httpProbeEvent
	ev.StartTime = 1_000_000
	ev.EndTime = 2_000_000
	copy(ev.Method[:], []byte("GET"))
	copy(ev.Path[:], []byte("/api/v1/users"))
	buf := new(bytes.Buffer)
	if err := binary.Write(buf, binary.LittleEndian, &ev); err != nil {
		b.Fatal(err)
	}
	return buf.Bytes()
}

// BenchmarkParsePerfEvent_NewBuffer is the pattern currently used in every probe Run loop.
func BenchmarkParsePerfEvent_NewBuffer(b *testing.B) {
	raw := sampleProbeBytes(b)
	var event httpProbeEvent
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := binary.Read(bytes.NewBuffer(raw), binary.LittleEndian, &event); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkParsePerfEvent_ReaderReset is the zero-alloc alternative (bytes.Reader.Reset).
func BenchmarkParsePerfEvent_ReaderReset(b *testing.B) {
	raw := sampleProbeBytes(b)
	var event httpProbeEvent
	r := bytes.NewReader(nil)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		r.Reset(raw)
		if err := binary.Read(r, binary.LittleEndian, &event); err != nil {
			b.Fatal(err)
		}
	}
}
