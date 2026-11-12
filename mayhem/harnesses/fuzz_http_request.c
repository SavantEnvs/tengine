/*
 * HTTP/1.x request parsing as ngx_http_process_request_line() + ngx_http_process_request_uri()
 * + ngx_http_process_request_headers() drive it: request line, URI normalisation, header lines,
 * host validation, cookie lookup, arg lookup and the unsafe-URI check.
 * First input byte: bit0 merge_slashes, bit1 allow underscores in header names.
 */
#include "ngx_fuzz_common.h"

static ngx_int_t
fuzz_process_uri(ngx_http_request_t *r, ngx_uint_t merge_slashes)
{
    u_char  *copy;

    if (r->args_start) {
        r->uri.len = r->args_start - 1 - r->uri_start;
    } else {
        r->uri.len = r->uri_end - r->uri_start;
    }

    copy = NULL;

    if (r->complex_uri || r->quoted_uri || r->empty_path_in_uri) {

        if (r->empty_path_in_uri) {
            r->uri.len++;
        }

        copy = malloc(r->uri.len + 1);
        if (copy == NULL) {
            abort();
        }

        r->uri.data = copy;

        if (ngx_http_parse_complex_uri(r, merge_slashes) != NGX_OK) {
            free(copy);
            return NGX_ERROR;
        }

    } else {
        r->uri.data = r->uri_start;
    }

    if (r->args_start && r->uri_end > r->args_start) {
        r->args.len = r->uri_end - r->args_start;
        r->args.data = r->args_start;
    }

    if (r->args.len) {
        ngx_str_t  v;

        (void) ngx_http_arg(r, (u_char *) "id", 2, &v);
        (void) ngx_http_arg(r, (u_char *) "a", 1, &v);
    }

    {
        ngx_str_t   uri = r->uri, args = r->args;
        ngx_uint_t  flags = 0;
        u_char     *u = malloc(uri.len + 1);

        if (u == NULL) {
            abort();
        }

        ngx_memcpy(u, uri.data, uri.len);
        uri.data = u;

        (void) ngx_http_parse_unsafe_uri(r, &uri, &args, &flags);
        free(u);
    }

    free(copy);
    return NGX_OK;
}


int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    u_char               *buf;
    ngx_int_t             rc;
    ngx_buf_t             b;
    ngx_pool_t           *pool;
    ngx_http_request_t   *r;
    ngx_table_elt_t      *head, **tail, *h;
    ngx_str_t             name, value, host;
    ngx_uint_t            merge_slashes, allow_underscores;

    if (size < 2) {
        return -1;
    }

    fuzz_ngx_init();

    merge_slashes = data[0] & 1;
    allow_underscores = (data[0] >> 1) & 1;
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

    rc = ngx_http_parse_request_line(r, &b);
    if (rc != NGX_OK) {
        goto done;
    }

    if (r->host_start && r->host_end) {
        host.len = r->host_end - r->host_start;
        host.data = r->host_start;

        if (ngx_http_validate_host(&host, NULL, pool, 0) == NGX_OK) {
            /* the host is accepted */
        }
    }

    if (fuzz_process_uri(r, merge_slashes) != NGX_OK) {
        rc = NGX_ERROR;
        goto done;
    }

    head = NULL;
    tail = &head;

    for ( ;; ) {

        rc = ngx_http_parse_header_line(r, &b, allow_underscores);

        if (rc == NGX_OK) {

            if (r->invalid_header) {
                continue;
            }

            h = ngx_pcalloc(pool, sizeof(ngx_table_elt_t));
            if (h == NULL) {
                abort();
            }

            h->hash = r->header_hash;
            h->key.len = r->header_name_end - r->header_name_start;
            h->key.data = r->header_name_start;
            h->value.len = r->header_end - r->header_start;
            h->value.data = r->header_start;

            *tail = h;
            tail = &h->next;

            if (h->key.len == 4 && ngx_strncasecmp(h->key.data, (u_char *) "host", 4) == 0) {
                (void) ngx_http_validate_host(&h->value, NULL, pool, 0);
            }

            continue;
        }

        break;
    }

    if (head) {
        name.len = head->key.len < 8 ? head->key.len : 8;
        name.data = head->key.data;

        (void) ngx_http_parse_cookie_lines(r, head, &name, &value);
        (void) ngx_http_parse_multi_header_lines(r, head, &name, &value);
        (void) ngx_http_parse_set_cookie_lines(r, head, &name, &value);
    }

done:

    free(buf);
    ngx_destroy_pool(pool);

    return rc == NGX_ERROR ? -1 : 0;
}
