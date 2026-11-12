/*
 * ngx_core string/number/address parsers that read config values and header fragments:
 * size/offset/time/HTTP-date, IPv4/IPv6/CIDR/URL, base64, URI/HTML escaping.
 * First input byte selects the parser; the rest is its text. Config-style parsers get a
 * NUL-terminated copy (as ngx_conf_read_token produces); header-style ones an exact-size buffer.
 */
#include "ngx_fuzz_common.h"

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    u_char       *p, *dst;
    size_t        n, len;
    ngx_pool_t   *pool;
    ngx_str_t     s, d;
    ngx_uint_t    sel, type;
    ngx_cidr_t    cidr;
    ngx_addr_t    addr;
    ngx_url_t     u;
    u_char        a6[16];

    if (size < 1) {
        return -1;
    }

    fuzz_ngx_init();

    sel = data[0] % 12;
    data++;
    size--;

    pool = ngx_create_pool(4096, &fuzz_log);
    if (pool == NULL) {
        abort();
    }

    p = fuzz_dup(data, size, 1);
    s.data = p;
    s.len = size;

    switch (sel) {

    case 0:
        (void) ngx_parse_size(&s);
        (void) ngx_parse_offset(&s);
        break;

    case 1:
        (void) ngx_parse_time(&s, 1);
        (void) ngx_parse_time(&s, 0);
        break;

    case 2:
        (void) ngx_parse_http_time(p, size);
        break;

    case 3:
        (void) ngx_inet_addr(p, size);
        (void) ngx_inet6_addr(p, size, a6);
        (void) ngx_parse_addr(pool, &addr, p, size);
        (void) ngx_parse_addr_port(pool, &addr, p, size);
        break;

    case 4:
        (void) ngx_ptocidr(&s, &cidr);
        break;

    case 5:
        ngx_memzero(&u, sizeof(ngx_url_t));
        u.url = s;
        u.default_port = 80;
        u.no_resolve = 1;
        u.listen = size > 0 ? (data[0] & 1) : 0;
        u.uri_part = size > 0 ? ((data[0] >> 1) & 1) : 0;
        (void) ngx_parse_url(pool, &u);
        break;

    case 6:
    case 7:
        d.len = ngx_base64_decoded_length(size);
        d.data = malloc(d.len + 1);
        if (d.data == NULL) {
            abort();
        }

        {
            u_char  *e = fuzz_dup(data, size, 0);
            ngx_str_t  src = { size, e };

            if (sel == 6) {
                (void) ngx_decode_base64(&d, &src);
            } else {
                (void) ngx_decode_base64url(&d, &src);
            }

            free(e);
        }

        free(d.data);
        break;

    case 8:
        for (type = 0; type <= NGX_ESCAPE_MAIL_XTEXT; type++) {
            u_char  *e = fuzz_dup(data, size, 0);

            n = ngx_escape_uri(NULL, e, size, type);
            len = size + n * 2;
            dst = malloc(len + 1);
            if (dst == NULL) {
                abort();
            }

            (void) ngx_escape_uri(dst, e, size, type);
            free(dst);
            free(e);
        }
        break;

    case 9:
        {
            u_char  *e = fuzz_dup(data, size, 0);
            u_char  *out = malloc(size + 1);
            u_char  *o;
            u_char  *in;

            if (out == NULL) {
                abort();
            }

            for (type = 0; type <= NGX_UNESCAPE_REDIRECT; type++) {
                o = out;
                in = e;
                ngx_unescape_uri(&o, &in, size, type);
            }

            free(out);
            free(e);
        }
        break;

    case 10:
        {
            u_char  *e = fuzz_dup(data, size, 0);

            n = ngx_escape_html(NULL, e, size);
            dst = malloc(size + n * 6 + 1);
            if (dst == NULL) {
                abort();
            }

            (void) ngx_escape_html(dst, e, size);
            free(dst);
            free(e);
        }
        break;

    default:
        {
            u_char  *e = fuzz_dup(data, size, 0);
            u_char  *q = e;
            uint32_t  c;

            (void) ngx_utf8_length(e, size);

            while (q < e + size) {
                c = ngx_utf8_decode(&q, e + size - q);
                if (c > 0x10ffff) {
                    break;
                }
            }

            (void) ngx_atoi(e, size);
            (void) ngx_atofp(e, size, 3);
            (void) ngx_hextoi(e, size);
            free(e);
        }
        break;
    }

    free(p);
    ngx_destroy_pool(pool);

    return 0;
}
