#include "common.h"
#include "bpf_helpers.h"

char __license[] SEC("license") = "Dual MIT/GPL";

#define runningState 2

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, u64);
	__type(value, s64);
	__uint(max_entries, MAX_OS_THREADS);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} goroutines_map SEC(".maps");

//struct {
//	__uint(type, BPF_MAP_TYPE_HASH);
//	__type(key, s64);
//	__type(value, u32);
//	__uint(max_entries, MAX_GOROUTINES);
//} goroutine_to_thread SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, u32);
	__type(value, u64);
	__uint(max_entries, 1);
} offset_map SEC(".maps");

SEC("uprobe/runtime_casgstatus")
int uprobe_runtime_casgstatus(struct pt_regs *ctx) {
    s32 newval = 0;
    bpf_probe_read(&newval, sizeof(newval), (void*)(ctx->rsp+20));
//    if (newval == 2) {
//        return 0;
//    }

    u32 offset_key = 0;
    u64* offset_ptr = bpf_map_lookup_elem(&offset_map, &offset_key);
    if (!offset_ptr) {
        return 0;
    }

    u64 offset = 0;
    bpf_probe_read(&offset, sizeof(offset), offset_ptr);
    void* g_ptr;
    bpf_probe_read(&g_ptr, sizeof(g_ptr), (void *)(ctx->rsp+8));

    s64 goid = 0;
    bpf_probe_read(&goid, sizeof(goid), g_ptr+offset);

    void* m;
    bpf_probe_read(&m, sizeof(m), g_ptr + 48);
    void* curg;
    bpf_probe_read(&curg, sizeof(curg), m + 192);
    s64 curg_goid = 0;
    bpf_probe_read(&curg_goid, sizeof(curg_goid), curg+offset);
    u64 current_thread = bpf_get_current_pid_tgid();
    bpf_printk("current goid is %d, status %d, thread %d\n", goid, newval, current_thread);

    //bpf_printk("curg.goid is zero, current goid is %d, status %d, thread %d\n", goid, newval, current_thread);
    bpf_map_update_elem(&goroutines_map, &current_thread, &goid, 0);
//    if (curg_goid != 0) {
//        //bpf_map_update_elem(&goroutines_map, &current_thread, &curg_goid, 0);
//        //bpf_printk("updated goid to be %d\n", curg_goid);
//    } else {
//        //bpf_printk("curg.goid is zero");
//        bpf_printk("curg.goid is zero, current goid is %d, status %d, thread %d\n", goid, newval, current_thread);
//        bpf_map_update_elem(&goroutines_map, &current_thread, &goid, 0);
//    }
//
//    if (newval == runningState) {
//        //
//    }

    return 0;
}