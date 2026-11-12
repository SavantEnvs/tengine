/* Shared setup for the in-process tengine parser harnesses: no cycle, no sockets, no files. */
#ifndef NGX_FUZZ_COMMON_H
#define NGX_FUZZ_COMMON_H

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

static ngx_log_t  fuzz_log;

/* log_level 0 keeps ngx_log_error() silent; no ngx_cycle is needed by the parsers */
static void
fuzz_ngx_init(void)
{
    static int  done;

    if (done) {
        return;
    }

    done = 1;

    ngx_pagesize = 4096;
    ngx_pagesize_shift = 12;
    ngx_cacheline_size = 64;

    fuzz_log.log_level = 0;
    ngx_time_init();
}

/* exact-size heap copy (optionally NUL-terminated) so ASan sees any read past the input */
static u_char *
fuzz_dup(const uint8_t *data, size_t size, int nul)
{
    u_char  *p = malloc(size + (nul ? 1 : 0) + 1);

    if (p == NULL) {
        abort();
    }

    ngx_memcpy(p, data, size);

    if (nul) {
        p[size] = '\0';
    }

    return p;
}

#endif
