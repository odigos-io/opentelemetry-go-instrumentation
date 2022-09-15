#include "arguments.h"
#include "goroutines.h"
#include "go_types.h"
#include "span_context.h"
#include "go_context.h"

char __license[] SEC("license") = "Dual MIT/GPL";

#define MAX_SIZE 50
#define MAX_CONCURRENT 50

struct grpc_request_t {
    s64 goroutine;
    u64 start_time;
    u64 end_time;
    char method[MAX_SIZE];
    char target[MAX_SIZE];
    struct span_context sc;
};

struct hpack_header_field {
    struct go_string name;
    struct go_string value;
    bool sensitive;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, void*);
	__type(value, struct grpc_request_t);
	__uint(max_entries, MAX_CONCURRENT);
} context_to_grpc_events SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
} events SEC(".maps");

// Injected in init
volatile const u64 clientconn_target_ptr_pos;

// This instrumentation attaches uprobe to the following function:
// func (cc *ClientConn) Invoke(ctx context.Context, method string, args, reply interface{}, opts ...CallOption) error
SEC("uprobe/ClientConn_Invoke")
int uprobe_ClientConn_Invoke(struct pt_regs *ctx) {
    // positions
    u64 clientconn_pos = 1;
    u64 context_pos = 3;
    u64 method_ptr_pos = 4;
    u64 method_len_pos = 5;

    struct grpc_request_t grpcReq = {};
    grpcReq.start_time = bpf_ktime_get_ns();

    // Read Method
    void* method_ptr = get_argument(ctx, method_ptr_pos);
    u64 method_len = (u64) get_argument(ctx, method_len_pos);
    u64 method_size = sizeof(grpcReq.method);
    method_size = method_size < method_len ? method_size : method_len;
    bpf_probe_read(&grpcReq.method, method_size, method_ptr);

    // Read ClientConn.Target
    void* clientconn_ptr = get_argument(ctx, clientconn_pos);
    void* target_ptr = 0;
    bpf_probe_read(&target_ptr, sizeof(target_ptr), (void *)(clientconn_ptr+(clientconn_target_ptr_pos)));
    u64 target_len = 0;
    bpf_probe_read(&target_len, sizeof(target_len), (void *)(clientconn_ptr+(clientconn_target_ptr_pos+8)));
    u64 target_size = sizeof(grpcReq.target);
    target_size = target_size < target_len ? target_size : target_len;
    bpf_probe_read(&grpcReq.target, target_size, target_ptr);

    // Write event
    void *context_ptr = get_argument(ctx, context_pos);
    bpf_map_update_elem(&context_to_grpc_events, &context_ptr, &grpcReq, 0);
    return 0;
}

SEC("uprobe/ClientConn_Invoke")
int uprobe_ClientConn_Invoke_Returns(struct pt_regs *ctx) {
    u64 context_pos = 3;
    void *context_ptr = get_argument(ctx, context_pos);
    void* grpcReq_ptr = bpf_map_lookup_elem(&context_to_grpc_events, &context_ptr);
    struct grpc_request_t grpcReq = {};
    bpf_probe_read(&grpcReq, sizeof(grpcReq), grpcReq_ptr);

    grpcReq.end_time = bpf_ktime_get_ns();
    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &grpcReq, sizeof(grpcReq));
    bpf_map_delete_elem(&context_to_grpc_events, &context_ptr);

    return 0;
}

// func (t *http2Client) createHeaderFields(ctx context.Context, callHdr *CallHdr) ([]hpack.HeaderField, error)
SEC("uprobe/Http2Client_createHeaderFields")
int uprobe_Http2Client_CreateHeaderFields(struct pt_regs *ctx) {
    // TODO: Register based ABI return values on EAX,EBC ...
    // Read slice
    s32 context_pointer_pos = 3;
    u64 slice_pointer_pos = 5;
    s32 slice_len_pos = 6;
    s32 slice_cap_pos = 7;
    struct go_slice slice = {};
    slice.array = get_argument(ctx, slice_pointer_pos);
    slice.len = (s32) get_argument(ctx, slice_len_pos);
    slice.cap = (s32) get_argument(ctx, slice_cap_pos);
    //bpf_printk("createHeaderFields called, slice addr: %lx, slice len: %d, slice cap: %d", slice.array, slice.len, slice.cap);
    char key[11] = "traceparent";
    struct go_string key_str = write_user_go_string(key, sizeof(key));

    // Find context
    void *context_ptr = get_argument(ctx, context_pointer_pos);
    void *parent_ctx = find_context_in_map(context_ptr, &context_to_grpc_events);
    void* grpcReq_ptr = bpf_map_lookup_elem(&context_to_grpc_events, &parent_ctx);
    struct grpc_request_t grpcReq = {};
    bpf_probe_read(&grpcReq, sizeof(grpcReq), grpcReq_ptr);

    // Generate span context
    grpcReq.sc = generate_span_context();
    char val[SPAN_CONTEXT_STRING_SIZE];
    span_context_to_w3c_string(&grpcReq.sc, val);
    struct go_string val_str = write_user_go_string(val, sizeof(val));
    bpf_printk("generated traceid string: %s", val);
    struct hpack_header_field hf = {};
    hf.name = key_str;
    hf.value = val_str;
    append_item_to_slice(&slice, &hf, sizeof(hf));
    slice.len++;
    long success = bpf_probe_write_user((void*)ctx->rsp+(slice_len_pos*8), &slice.len, sizeof(slice.len));
    bpf_map_update_elem(&context_to_grpc_events, &parent_ctx, &grpcReq, 0);
    //bpf_printk("len success: %d, generated context: %lx trace id: %s", success, context_ptr, val);

    return 0;
}