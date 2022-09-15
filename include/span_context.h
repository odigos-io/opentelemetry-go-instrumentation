#include "utils.h"

#define SPAN_CONTEXT_STRING_SIZE 55

struct span_context {
    unsigned char TraceID[TRACE_ID_SIZE];
    unsigned char SpanID[SPAN_ID_SIZE];
};

static __always_inline struct span_context generate_span_context() {
    struct span_context context = {};
    generate_random_bytes(context.TraceID, TRACE_ID_SIZE);
    generate_random_bytes(context.SpanID, SPAN_ID_SIZE);
    return context;
}

static __always_inline void span_context_to_w3c_string(struct span_context *ctx, char* buff) {
    // W3C format: version (2 chars) - trace id (32 chars) - span id (16 chars) - sampled (2 chars)
    char *out = buff;

    // Write version
    *out++ = '0';
    *out++ = '0';
    *out++ = '-';

    // Write trace id
    bytes_to_hex_string(ctx->TraceID, TRACE_ID_SIZE, out);
    out += TRACE_ID_STRING_SIZE;
    *out++ = '-';

    // Write span id
    bytes_to_hex_string(ctx->SpanID, SPAN_ID_SIZE, out);
    out += SPAN_ID_STRING_SIZE;
    *out++ = '-';

    // Write sampled
    *out++ = '0';
    *out   = '1';
}