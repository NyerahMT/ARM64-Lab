#ifndef MX_CRT_SERVICES_H
#define MX_CRT_SERVICES_H
/*
 * Synthetic, deterministic MSVCR90-style host service contracts.
 *
 * Independent portable implementation, not Microsoft's EncodePointer or
 * actual MSVCR90. This is a bounded guest-runtime prototype for differential
 * fixtures: no OS mutexes, guest heap reallocation, or exit invocation.
 *
 * Real services must ultimately be tested against the original x64 program.
 */
#include <stdint.h>
#include "mx_cfg_vm.h"

#define MX_CRT_SVC_LOCKS 16U
#define MX_CRT_SVC_ONEXIT_MAX 32U
#define MX_CRT_SVC_OK 1
#define MX_CRT_SVC_BUSY 0
#define MX_CRT_SVC_INVALID (-1)
#define MX_CRT_SVC_FULL (-2)

typedef struct {
    uint64_t pointer_key;
    uint64_t lock_owner[MX_CRT_SVC_LOCKS];
    uint32_t lock_depth[MX_CRT_SVC_LOCKS];
    uint64_t onexit[MX_CRT_SVC_ONEXIT_MAX];
    uint32_t onexit_count;
} mx_crt_services;

static inline int mx_crt_services_init(mx_crt_services *s, uint64_t key) {
    if (!s || !key) return MX_CRT_SVC_INVALID;
    s->pointer_key=key;
    s->onexit_count=0;
    for (uint32_t i=0;i<MX_CRT_SVC_LOCKS;i++) {
        s->lock_owner[i]=0;
        s->lock_depth[i]=0;
    }
    for (uint32_t i=0;i<MX_CRT_SVC_ONEXIT_MAX;i++)s->onexit[i]=0;
    return MX_CRT_SVC_OK;
}

/* An explicit test-only process-local invertible mapping. It does not
 * claim wire/token compatibility with Windows EncodePointer/DecodePointer. */
static inline uint64_t mx_crt_encode_pointer(const mx_crt_services *s, uint64_t p) {
    if (!s || !s->pointer_key)return 0;
    uint64_t x=p^s->pointer_key;
    return (x<<17U)|(x>>47U);
}
static inline uint64_t mx_crt_decode_pointer(const mx_crt_services *s, uint64_t p) {
    if (!s || !s->pointer_key)return 0;
    uint64_t x=(p>>17U)|(p<<47U);
    return x^s->pointer_key;
}

/* Single-thread deterministic guest-owner model. Contention is returned to
 * the caller, never silently ignored or treated as a successful acquisition.
 * This is NOT a Windows critical section or concurrently correct lock. */
static inline int mx_crt_service_lock(mx_crt_services *s, uint32_t number,
                                       uint64_t guest_owner) {
    if (!s || !s->pointer_key || !guest_owner || number>=MX_CRT_SVC_LOCKS)
        return MX_CRT_SVC_INVALID;
    if (!s->lock_depth[number]) {
        s->lock_owner[number]=guest_owner;
        s->lock_depth[number]=1;
        return MX_CRT_SVC_OK;
    }
    if (s->lock_owner[number]!=guest_owner)return MX_CRT_SVC_BUSY;
    if (s->lock_depth[number]==UINT32_MAX)return MX_CRT_SVC_FULL;
    s->lock_depth[number]++;
    return MX_CRT_SVC_OK;
}
static inline int mx_crt_service_unlock(mx_crt_services *s, uint32_t number,
                                         uint64_t guest_owner) {
    if (!s || !s->pointer_key || !guest_owner || number>=MX_CRT_SVC_LOCKS ||
        !s->lock_depth[number] || s->lock_owner[number]!=guest_owner)
        return MX_CRT_SVC_INVALID;
    s->lock_depth[number]--;
    if (!s->lock_depth[number])s->lock_owner[number]=0;
    return MX_CRT_SVC_OK;
}

/* Model MSVCR90 _onexit(func): return func on successful registration and
 * 0 on failure. No callback is executed here; execution order is separately
 * tested by consumers when implementing the process-exit lifecycle. */
static inline uint64_t mx_crt_service_onexit(mx_crt_services *s, uint64_t func) {
    if (!s || !s->pointer_key || !func ||
        s->onexit_count>=MX_CRT_SVC_ONEXIT_MAX)return 0;
    s->onexit[s->onexit_count++]=func;
    return func;
}

/* Bounded __dllonexit model using an explicitly preallocated guest array.
 * start_ref/end_ref are guest addresses of pointers to the array. The test
 * fixture must supply heap_base and capacity; unlike Windows realloc(), this
 * function does not relocate or grow the array. Full/invalid tables fail,
 * rather than manufacturing a successful registration.
 *
 * The two guest refs must initially both point to heap_base. Guest pointers
 * and stored exit functions are all 64-bit. The caller owns guest memory.
 */
static inline uint64_t mx_crt_service_dllonexit(
        mx_cfg_memory *mem, uint64_t func,
        uint64_t start_ref, uint64_t end_ref,
        uint64_t heap_base, uint32_t capacity) {
    if (!mem || !func || !heap_base || !start_ref || !end_ref ||
        capacity==0 || capacity>MX_CRT_SVC_ONEXIT_MAX ||
        heap_base>UINT64_MAX-(uint64_t)capacity*8U)return 0;
    uint64_t begin=0,end=0,probe=0;
    if (!mx_cfg_transfer(mem,start_ref,&begin,8,0) ||
        !mx_cfg_transfer(mem,end_ref,&end,8,0) ||
        begin!=heap_base || end<begin || (end-begin)%8U ||
        (end-begin)/8U>=capacity || end>UINT64_MAX-8U ||
        !mx_cfg_transfer(mem,end,&probe,8,0))return 0;
    uint64_t next=end+8U;
    if (!mx_cfg_transfer(mem,end,&func,8,1) ||
        !mx_cfg_transfer(mem,end_ref,&next,8,1))return 0;
    return func;
}
#endif
