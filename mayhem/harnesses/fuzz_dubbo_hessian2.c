/*
 * Dubbo (mod_dubbo) Hessian2 response-payload decoder: ngx_dubbo_hessian2_decode_payload_map()
 * is what ngx_http_dubbo_module runs over the bytes a Dubbo provider returns.
 */
#include "ngx_fuzz_common.h"
#include <ngx_dubbo.h>

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    u_char       *buf;
    ngx_int_t     rc;
    ngx_str_t     in;
    ngx_pool_t   *pool;
    ngx_array_t  *res;

    if (size < 2) {
        return -1;
    }

    fuzz_ngx_init();

    pool = ngx_create_pool(4096, &fuzz_log);
    if (pool == NULL) {
        abort();
    }

    buf = fuzz_dup(data, size, 0);
    in.data = buf;
    in.len = size;
    res = NULL;

    rc = ngx_dubbo_hessian2_decode_payload_map(pool, &in, &res, &fuzz_log);

    free(buf);
    ngx_destroy_pool(pool);

    return rc == NGX_OK ? 0 : -1;
}
