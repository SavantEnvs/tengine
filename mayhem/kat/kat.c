/*
 * Known-answer probe: drives real tengine parsers with fixed inputs and prints computed values.
 * Built by build.sh with the project's normal flags against the unsanitized objects; test.sh
 * compares the output with kat/expected.txt line by line.
 */
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <ngx_mail.h>
#include <ngx_mail_pop3_module.h>
#include <ngx_dubbo.h>

static ngx_log_t  log_;

static ngx_http_request_t *
new_request(ngx_pool_t *pool)
{
    ngx_http_request_t  *r = ngx_pcalloc(pool, sizeof(ngx_http_request_t));
    r->pool = pool;
    return r;
}

static void
set_buf(ngx_buf_t *b, const char *s)
{
    ngx_memzero(b, sizeof(ngx_buf_t));
    b->start = b->pos = (u_char *) s;
    b->last = b->end = (u_char *) s + strlen(s);
    b->memory = 1;
}

static void
request_line(ngx_pool_t *pool)
{
    ngx_buf_t            b;
    ngx_int_t            rc;
    ngx_str_t            v;
    ngx_http_request_t  *r = new_request(pool);

    set_buf(&b, "GET /a%20b/c/../d?x=1&y=2 HTTP/1.1\r\nHost: example.com:8080\r\n"
                "X-Test:   padded value  \r\nCookie: sid=abc; theme=dark\r\n\r\n");

    rc = ngx_http_parse_request_line(r, &b);
    printf("req.rc=%d\n", (int) rc);
    printf("req.method=%u\n", (unsigned) r->method);
    printf("req.version=%u\n", (unsigned) r->http_version);
    printf("req.quoted=%u\n", (unsigned) r->quoted_uri);
    printf("req.unparsed=%.*s\n", (int) (r->uri_end - r->uri_start), r->uri_start);

    r->uri.len = r->uri_end - r->uri_start;
    r->uri.data = ngx_pnalloc(pool, r->uri.len + 1);
    rc = ngx_http_parse_complex_uri(r, 1);
    printf("req.uri_rc=%d\n", (int) rc);
    printf("req.uri=%.*s\n", (int) r->uri.len, r->uri.data);

    r->args.data = r->args_start;
    r->args.len = r->uri_end - r->args_start;
    printf("req.args=%.*s\n", (int) r->args.len, r->args.data);
    rc = ngx_http_arg(r, (u_char *) "y", 1, &v);
    printf("req.arg_y=%d:%.*s\n", (int) rc, (int) v.len, v.data);

    for ( ;; ) {
        rc = ngx_http_parse_header_line(r, &b, 0);
        if (rc != NGX_OK) {
            break;
        }

        printf("hdr=%.*s|%.*s\n",
               (int) (r->header_name_end - r->header_name_start), r->header_name_start,
               (int) (r->header_end - r->header_start), r->header_start);
    }

    printf("hdr.final=%d\n", (int) rc);
}

static void
status_line(ngx_pool_t *pool)
{
    ngx_buf_t            b;
    ngx_http_status_t    st;
    ngx_http_request_t  *r = new_request(pool);

    set_buf(&b, "HTTP/1.0 404 Not Found\r\nServer: probe\r\n\r\n");
    ngx_memzero(&st, sizeof(st));

    printf("resp.rc=%d\n", (int) ngx_http_parse_status_line(r, &b, &st));
    printf("resp.version=%u\n", (unsigned) st.http_version);
    printf("resp.code=%u\n", (unsigned) st.code);
}

static void
chunked(ngx_pool_t *pool)
{
    ngx_buf_t            b;
    ngx_int_t            rc;
    ngx_http_chunked_t   ctx;
    ngx_http_request_t  *r = new_request(pool);

    ngx_memzero(&ctx, sizeof(ctx));
    set_buf(&b, "1a;ext=1\r\n");
    rc = ngx_http_parse_chunked(r, &b, &ctx, 0);
    printf("chunk.rc=%d\n", (int) rc);
    printf("chunk.size=%d\n", (int) ctx.size);

    ngx_memzero(&ctx, sizeof(ctx));
    set_buf(&b, "5\r\nhello\r\n0\r\n\r\n");
    rc = ngx_http_parse_chunked(r, &b, &ctx, 0);
    printf("chunk.first_rc=%d\n", (int) rc);
    printf("chunk.first_size=%d\n", (int) ctx.size);
    b.pos += ctx.size;
    rc = ngx_http_parse_chunked(r, &b, &ctx, 0);
    printf("chunk.next_rc=%d\n", (int) rc);
    printf("chunk.done_consumed=%d\n", (int) (b.pos - b.start));
}

static void
core_util(void)
{
    ngx_str_t  s;
    u_char     out[64];
    u_char    *o;
    ngx_str_t  src, dst;
    ngx_cidr_t cidr;

    s.data = (u_char *) "10k"; s.len = 3;
    printf("size.10k=%d\n", (int) ngx_parse_size(&s));
    s.data = (u_char *) "2m"; s.len = 2;
    printf("offset.2m=%d\n", (int) ngx_parse_offset(&s));
    s.data = (u_char *) "1h30m"; s.len = 5;
    printf("time.1h30m=%d\n", (int) ngx_parse_time(&s, 1));
    s.data = (u_char *) "250ms"; s.len = 5;
    printf("time.250ms=%d\n", (int) ngx_parse_time(&s, 0));
    printf("httpdate=%ld\n",
           (long) ngx_parse_http_time((u_char *) "Sun, 06 Nov 1994 08:49:37 GMT", 29));
    printf("inet.addr=%u\n", (unsigned) ntohl(ngx_inet_addr((u_char *) "192.168.1.20", 12)));

    s.data = (u_char *) "10.0.0.0/8"; s.len = 10;
    ngx_ptocidr(&s, &cidr);
    printf("cidr.mask=%08x\n", (unsigned) ntohl(cidr.u.in.mask));

    src.data = (u_char *) "aGVsbG8gdGVuZ2luZQ=="; src.len = 20;
    dst.data = out;
    printf("b64.rc=%d\n", (int) ngx_decode_base64(&dst, &src));
    printf("b64.text=%.*s\n", (int) dst.len, dst.data);

    o = out;
    {
        u_char *in = (u_char *) "a%20b%2Fc";
        ngx_unescape_uri(&o, &in, 9, 0);
    }
    printf("unescape=%.*s\n", (int) (o - out), out);

    o = ngx_pnalloc(ngx_create_pool(1024, &log_), 64);
    ngx_escape_uri(o, (u_char *) "a b/c?d", 7, NGX_ESCAPE_URI_COMPONENT);
    printf("escape=%s\n", o);
}

static void
mail_cmd(ngx_pool_t *pool)
{
    ngx_buf_t           b;
    ngx_str_t          *arg;
    ngx_mail_session_t *s = ngx_pcalloc(pool, sizeof(ngx_mail_session_t));

    ngx_array_init(&s->args, pool, 2, sizeof(ngx_str_t));
    set_buf(&b, "USER alice\r\n");
    s->buffer = &b;

    printf("pop3.rc=%d\n", (int) ngx_mail_pop3_parse_command(s));
    printf("pop3.command_is_user=%d\n", s->command == NGX_POP3_USER);
    arg = s->args.elts;
    printf("pop3.nargs=%u\n", (unsigned) s->args.nelts);
    printf("pop3.arg0=%.*s\n", (int) arg[0].len, arg[0].data);
}

static void
dubbo(ngx_pool_t *pool)
{
    ngx_array_t   *kvs, *res;
    ngx_keyval_t  *kv;
    ngx_str_t      enc, key = ngx_string("method"), val = ngx_string("sayHello");

    kvs = ngx_array_create(pool, 2, sizeof(ngx_keyval_t));
    kv = ngx_array_push(kvs);
    kv->key = key;
    kv->value = val;

    printf("dubbo.enc_rc=%d\n", (int) ngx_dubbo_hessian2_encode_payload_map(pool, kvs, &enc));
    res = NULL;
    /* the decoder expects a leading attachment int32, then the map */
    {
        ngx_str_t in;
        in.len = enc.len + 1;
        in.data = ngx_pnalloc(pool, in.len);
        in.data[0] = 0x90;
        ngx_memcpy(in.data + 1, enc.data, enc.len);
        printf("dubbo.dec_rc=%d\n", (int) ngx_dubbo_hessian2_decode_payload_map(pool, &in, &res, &log_));
    }

    if (res && res->nelts) {
        kv = res->elts;
        printf("dubbo.n=%u\n", (unsigned) res->nelts);
        printf("dubbo.kv=%.*s=%.*s\n", (int) kv[0].key.len, kv[0].key.data,
               (int) kv[0].value.len, kv[0].value.data);
    } else {
        printf("dubbo.n=0\n");
    }
}

int
main(void)
{
    ngx_pool_t  *pool;

    setvbuf(stdout, NULL, _IONBF, 0);

    ngx_pagesize = 4096;
    ngx_pagesize_shift = 12;
    ngx_cacheline_size = 64;
    log_.log_level = 0;
    ngx_time_init();

    pool = ngx_create_pool(16384, &log_);

    request_line(pool);
    status_line(pool);
    chunked(pool);
    core_util();
    mail_cmd(pool);
    dubbo(pool);

    return 0;
}
