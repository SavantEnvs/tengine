/*
 * Chunked transfer-encoding decoder (ngx_http_parse_chunked), fed in two pieces so the
 * resumable state machine is exercised the way ngx_http_request_body_chunked_filter /
 * the upstream chunked filter drive it.
 * Input: byte0 bit0 = keep_trailers, byte1 = split position (modulo the rest), then the stream.
 */
#include "ngx_fuzz_common.h"

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    u_char               *buf;
    size_t                split;
    ngx_int_t             rc;
    ngx_buf_t             b;
    ngx_pool_t           *pool;
    ngx_http_request_t   *r;
    ngx_http_chunked_t    ctx;
    ngx_uint_t            keep_trailers;

    if (size < 3) {
        return -1;
    }

    fuzz_ngx_init();

    keep_trailers = data[0] & 1;
    split = data[1];
    data += 2;
    size -= 2;
    split %= size + 1;

    pool = ngx_create_pool(4096, &fuzz_log);
    if (pool == NULL) {
        abort();
    }

    r = ngx_pcalloc(pool, sizeof(ngx_http_request_t));
    if (r == NULL) {
        abort();
    }

    r->pool = pool;

    ngx_memzero(&ctx, sizeof(ngx_http_chunked_t));

    buf = fuzz_dup(data, split, 0);

    ngx_memzero(&b, sizeof(ngx_buf_t));
    b.start = b.pos = buf;
    b.last = b.end = buf + split;
    b.memory = 1;

    rc = ngx_http_parse_chunked(r, &b, &ctx, keep_trailers);
    free(buf);

    if (rc == NGX_AGAIN) {
        buf = fuzz_dup(data + split, size - split, 0);

        ngx_memzero(&b, sizeof(ngx_buf_t));
        b.start = b.pos = buf;
        b.last = b.end = buf + (size - split);
        b.memory = 1;

        rc = ngx_http_parse_chunked(r, &b, &ctx, keep_trailers);
        free(buf);
    }

    ngx_destroy_pool(pool);

    return rc == NGX_ERROR ? -1 : 0;
}
