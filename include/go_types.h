struct go_string {
    char* str;
    s32 len;
};

struct go_slice {
    void* array;
    s32 len;
    s32 cap;
};

static __always_inline struct go_string* write_user_go_string(char* str, u32 len) {
    // Copy chars to userspace
    char *addr = NULL; // TODO: call to allocator

    // Build string struct in kernel space
    struct go_string new_string = {};
    new_string.str = addr;
    new_string.len = len;

    // Copy new string to userspace
    struct go_string *userspace_string = NULL // TODO: call to allocator
    return userspace_string;
}

static __always_inline void append_item_to_slice(struct go_slice *slice, void* new_item, s32 item_size) {
    if slice.len < slice.cap {
        // Room available on current array
        slice.len++;
    } else {
        // No room on current array - copy to new one of size item_size * (len + 1)
    }
}