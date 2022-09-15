#include "alloc.h"
#include "bpf_helpers.h"

struct go_string {
    char* str;
    s32 len;
};

struct go_slice {
    void* array;
    s32 len;
    s32 cap;
};

struct go_iface {
    void* tab;
    void* data;
};

static __always_inline struct go_string write_user_go_string(char* str, u32 len) {
    // Copy chars to userspace
    char *addr = write_target_data((void*)str, len);

    // Build string struct in kernel space
    struct go_string new_string = {};
    new_string.str = addr;
    new_string.len = len;

    // Copy new string struct to userspace
    write_target_data((void*)&new_string, sizeof(new_string));
    return new_string;
}

static __always_inline void append_item_to_slice(struct go_slice *slice, void* new_item, s32 item_size) {
    if (slice->len < slice->cap) {
        // Room available on current array
        bpf_probe_write_user(slice->array+(item_size*slice->len), new_item, item_size);

        // increase slice len on userspace
    } else {
        // No room on current array - copy to new one of size item_size * (len + 1)
        bpf_printk("todo len = cap, need to reallocate array");
    }
}