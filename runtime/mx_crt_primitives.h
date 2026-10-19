#ifndef MX_CRT_PRIMITIVES_H
#define MX_CRT_PRIMITIVES_H
#include "mx_crt_vm.h"
/* Guest GS:[offset] via an injected TEB virtual address. No TEB model. */
static inline int mx_crt_gs_read64(mx_crt_state *s, mx_cfg_memory *m,
                                    uint64_t gs_base, uint64_t offset,
                                    uint64_t *output) {
    if (!s || !m || !output || gs_base > UINT64_MAX-offset) {
        if(s) s->fault=1;
        return 0;
    }
    uint64_t value=0;
    if (!mx_cfg_transfer(m,gs_base+offset,&value,8,0)) {
        s->fault=1;
        return 0;
    }
    *output=value;
    return 1;
}
#endif
