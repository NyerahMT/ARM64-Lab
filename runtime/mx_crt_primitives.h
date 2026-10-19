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
/* Exclusive-guest-memory CMPXCHG64 only; not a LOCK atomic model. */
static inline int mx_crt_cmpxchg64_single_thread(mx_crt_state *s,
        mx_cfg_memory *m, uint64_t address, uint64_t replacement, int exclusive) {
    if(!s || !m || !exclusive || (address&7U)) {
        if(s)s->fault=1;
        return 0;
    }
    uint64_t value=0;
    if(!mx_cfg_transfer(m,address,&value,8,0)) {
        s->fault=1;
        return 0;
    }
    if(s->rax==value) {
        if(!mx_cfg_transfer(m,address,&replacement,8,1)) {
            s->fault=1;
            return 0;
        }
        s->zf=1;
    } else {
        s->rax=value;
        s->zf=0;
    }
    return 1;
}
/* Exclusive single-thread guest XCHG64; x64 XCHG mem operand is
 * implicitly atomic, so concurrent memory is deliberately unsupported.
 * This leaves guest condition flags unchanged. */
static inline int mx_crt_xchg64_single_thread(mx_crt_state *s,
        mx_cfg_memory *m,uint64_t address,int exclusive) {
    if(!s||!m||!exclusive||(address&7U)) {
        if(s)s->fault=1;
        return 0;
    }
    uint64_t before=0;
    if(!mx_cfg_transfer(m,address,&before,8,0)) {
        s->fault=1;
        return 0;
    }
    uint64_t replacement=s->rax;
    if(!mx_cfg_transfer(m,address,&replacement,8,1)) {
        s->fault=1;
        return 0;
    }
    s->rax=before;
    return 1;
}
#endif
