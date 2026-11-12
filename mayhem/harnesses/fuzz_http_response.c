/*
 * HTTP/1.x response parsing as ngx_http_proxy_process_status_line() + ngx_http_proxy_process_header()
 * (via ngx_http_parse_status_line / ngx_http_parse_header_line) read an upstream reply.
 */
#include "ngx_fuzz_common.h"

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    u_char               *buf;
    ngx_int_t             rc;
    ngx_buf_t             b;
    ngx_pool_t           *pool;
    ngx_http_request_t   *r;
    ngx_http_status_t     status;
    ngx_uint_t            allow_underscores;

    if (size < 2) {
        return -1;
    }

    fuzz_ngx_init();

    allow_underscores = data[0] & 1;
    data++;
    size--;

    pool = ngx_create_pool(4096, &fuzz_log);
    if (pool == NULL) {
        abort();
    }

    r = ngx_pcalloc(pool, sizeof(ngx_http_request_t));
    if (r == NULL) {
        abort();
    }

    r->pool = pool;

    buf = fuzz_dup(data, size, 0);

    ngx_memzero(&b, sizeof(ngx_buf_t));
    b.start = b.pos = buf;
    b.last = b.end = buf + size;
    b.memory = 1;

    ngx_memzero(&status, sizeof(ngx_http_status_t));

    rc = ngx_http_parse_status_line(r, &b, &status);

    if (rc == NGX_OK) {

        do {
            rc = ngx_http_parse_header_line(r, &b, allow_underscores);
        } while (rc == NGX_OK);

        if (rc == NGX_HTTP_PARSE_HEADER_DONE) {
            rc = NGX_OK;
        }
    }

    free(buf);
    ngx_destroy_pool(pool);

    return rc == NGX_ERROR || rc == NGX_HTTP_PARSE_INVALID_HEADER ? -1 : 0;
}
