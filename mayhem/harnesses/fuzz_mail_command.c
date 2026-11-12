/*
 * Mail proxy command parsers (ngx_mail_pop3/imap/smtp_parse_command) as ngx_mail_*_auth_state()
 * run them: parse one command, reset the parser state, parse the next (pipelining) until the
 * buffer is used up. First input byte selects the protocol; the rest is the client's stream.
 */
#include "ngx_fuzz_common.h"
#include <ngx_mail.h>
#include <ngx_mail_pop3_module.h>
#include <ngx_mail_imap_module.h>
#include <ngx_mail_smtp_module.h>

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    int                   cmds;
    u_char               *buf;
    ngx_int_t             rc;
    ngx_buf_t             b;
    ngx_pool_t           *pool;
    ngx_mail_session_t   *s;
    ngx_uint_t            proto;

    if (size < 2) {
        return -1;
    }

    fuzz_ngx_init();

    proto = data[0] % 3;
    data++;
    size--;

    pool = ngx_create_pool(4096, &fuzz_log);
    if (pool == NULL) {
        abort();
    }

    s = ngx_pcalloc(pool, sizeof(ngx_mail_session_t));
    if (s == NULL
        || ngx_array_init(&s->args, pool, 2, sizeof(ngx_str_t)) != NGX_OK)
    {
        abort();
    }

    buf = fuzz_dup(data, size, 0);

    ngx_memzero(&b, sizeof(ngx_buf_t));
    b.start = b.pos = buf;
    b.last = b.end = buf + size;
    b.memory = 1;

    s->buffer = &b;

    rc = NGX_OK;

    for (cmds = 0; cmds < 64 && b.pos < b.last; cmds++) {

        s->args.nelts = 0;
        s->state = 0;
        s->cmd_start = s->arg_start = s->tag_start = NULL;

        switch (proto) {
        case 0:
            rc = ngx_mail_pop3_parse_command(s);
            break;
        case 1:
            rc = ngx_mail_imap_parse_command(s);
            break;
        default:
            rc = ngx_mail_smtp_parse_command(s);
            break;
        }

        if (rc != NGX_OK) {
            break;
        }
    }

    free(buf);
    ngx_destroy_pool(pool);

    return rc == NGX_ERROR || rc == NGX_MAIL_PARSE_INVALID_COMMAND ? -1 : 0;
}
