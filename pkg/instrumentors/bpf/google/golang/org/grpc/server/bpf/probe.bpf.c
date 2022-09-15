#include "arguments.h"
#include "goroutines.h"
#include "go_types.h"
#include "utils.h"

char __license[] SEC("license") = "Dual MIT/GPL";

#define MAX_SIZE 100
#define MAX_CONCURRENT 50
#define MAX_HEADERS 20
#define MAX_HEADER_STRING 50
#define W3C_KEY_LENGTH 11
#define W3C_VAL_LENGTH 55

struct grpc_request_t {
    s64 goroutine;
    u64 start_time;
    u64 end_time;
    char method[MAX_SIZE];
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, s64);
	__type(value, struct grpc_request_t);
	__uint(max_entries, MAX_CONCURRENT);
} goid_to_grpc_events SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
} events SEC(".maps");

struct hpack_header_field {
    struct go_string name;
    struct go_string value;
    bool sensitive;
};

// Injected in init
volatile const u64 stream_method_ptr_pos;
volatile const u64 frame_fields_pos;
volatile const u64 frame_stream_id_pod;


// This instrumentation attaches uprobe to the following function:
// func (s *Server) handleStream(t transport.ServerTransport, stream *transport.Stream, trInfo *traceInfo) {
SEC("uprobe/server_handleStream")
int uprobe_server_handleStream(struct pt_regs *ctx) {
    u64 stream_pos = 4;

    struct grpc_request_t grpcReq = {};
    grpcReq.start_time = bpf_ktime_get_ns();

    void* stream_ptr = get_argument(ctx, stream_pos);
    void* method_ptr = 0;
    bpf_probe_read(&method_ptr, sizeof(method_ptr), (void *)(stream_ptr+stream_method_ptr_pos));
    u64 method_len = 0;
    bpf_probe_read(&method_len, sizeof(method_len), (void *)(stream_ptr+(stream_method_ptr_pos+8)));
    u64 method_size = sizeof(grpcReq.method);
    method_size = method_size < method_len ? method_size : method_len;
    bpf_probe_read(&grpcReq.method, method_size, method_ptr);

    // Record goroutine
    grpcReq.goroutine = get_current_goroutine();

    // Write event
    bpf_map_update_elem(&goid_to_grpc_events, &grpcReq.goroutine, &grpcReq, 0);

    return 0;
}

SEC("uprobe/server_handleStream")
int uprobe_server_handleStream_ByRegisters(struct pt_regs *ctx) {
    struct grpc_request_t grpcReq = {};
    grpcReq.start_time = bpf_ktime_get_ns();
    void* stream_ptr = (void *)(ctx->rdi);
    void* method_ptr = 0;
    bpf_probe_read(&method_ptr, sizeof(method_ptr), (void *)(stream_ptr+stream_method_ptr_pos));
    u64 method_len = 0;
    bpf_probe_read(&method_len, sizeof(method_len), (void *)(stream_ptr+(stream_method_ptr_pos+8)));
    u64 method_size = sizeof(grpcReq.method);
    method_size = method_size < method_len ? method_size : method_len;
    bpf_probe_read(&grpcReq.method, method_size, method_ptr);

    // Record goroutine
    u64 current_thread = bpf_get_current_pid_tgid();
    void* goid_ptr = bpf_map_lookup_elem(&goroutines_map, &current_thread);
    s64 goid;
    bpf_probe_read(&goid, sizeof(goid), goid_ptr);
    grpcReq.goroutine = goid;

    // Write event
    bpf_map_update_elem(&goid_to_grpc_events, &goid, &grpcReq, 0);
    return 0;
}

SEC("uprobe/server_handleStream")
int uprobe_server_handleStream_Returns(struct pt_regs *ctx) {
    s64 goid = get_current_goroutine();
    void* grpcReq_ptr = bpf_map_lookup_elem(&goid_to_grpc_events, &goid);
    struct grpc_request_t grpcReq = {};
    bpf_probe_read(&grpcReq, sizeof(grpcReq), grpcReq_ptr);
    grpcReq.end_time = bpf_ktime_get_ns();
    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &grpcReq, sizeof(grpcReq));
    bpf_map_delete_elem(&goid_to_grpc_events, &goid);
    return 0;
}

// func (d *decodeState) decodeHeader(frame *http2.MetaHeadersFrame) error
SEC("uprobe/decodeState_decodeHeader")
int uprobe_decodeState_decodeHeader(struct pt_regs *ctx) {
    bpf_printk("decodeHeader called");
    u64 frame_pos = 2;
    void* frame_ptr = get_argument(ctx, frame_pos);
    struct go_slice header_fields = {};
    bpf_probe_read(&header_fields, sizeof(header_fields), (void *)(frame_ptr+frame_fields_pos));
    bpf_printk("There are %d headers, sizeof: %d", header_fields.len, sizeof(header_fields));
    char key[W3C_KEY_LENGTH] = "traceparent";
    for (s32 i = 0; i < MAX_HEADERS; i++) {
        if (i >=  header_fields.len) {
            break;
        }
        struct hpack_header_field hf = {};
        long res = bpf_probe_read(&hf, sizeof(hf), (void*)(header_fields.array+(i * sizeof(hf))));
         if (hf.name.len == W3C_KEY_LENGTH && hf.value.len == W3C_VAL_LENGTH) {
            char current_key[W3C_KEY_LENGTH];
            bpf_probe_read(current_key, sizeof(current_key), hf.name.str);
            if (bpf_memcmp(key, current_key, sizeof(key))) {
               char val[W3C_VAL_LENGTH];
               bpf_probe_read(val, W3C_VAL_LENGTH, hf.value.str);

               // Get stream id
               void* headers_frame = NULL;
               bpf_probe_read(&headers_frame, sizeof(headers_frame), frame_ptr);
               u32 stream_id = 0;
               bpf_probe_read(&stream_id, sizeof(stream_id), (void*)(headers_frame+frame_stream_id_pod));
               bpf_printk("stream id: %d traceparent value is: %s", stream_id, val);
            }
         }
    }

    return 0;
}