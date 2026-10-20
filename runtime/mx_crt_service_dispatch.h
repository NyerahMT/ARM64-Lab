#ifndef MX_CRT_SERVICE_DISPATCH_H
#define MX_CRT_SERVICE_DISPATCH_H
/*
 * Test-only typed Win64 argument adapter for independently modeled MSVCR90
 * callback services. The native importer must resolve the original DLL and
 * IAT symbol before selecting a typed service ID. This file does not register
 * these stubs as supported production Windows services.
 *
 * Win64 RCX/RDX/R8 arguments and guest RAX returns are modeled explicitly.
 * Guest memory is bounded; any unsupported call or busy/invalid lock is
 * returned as failure rather than unconditionally faked as success.
 */
#include <stdint.h>
#include "mx_crt_services.h"

typedef enum {
    MX_CRT_SERVICE_UNSUPPORTED=0,
    MX_CRT_SERVICE_ENCODE_POINTER=1,
    MX_CRT_SERVICE_DECODE_POINTER=2,
    MX_CRT_SERVICE_ONEXIT=3,
    MX_CRT_SERVICE_DLLONEXIT=4,
    MX_CRT_SERVICE_LOCK=5,
    MX_CRT_SERVICE_UNLOCK=6
} mx_crt_service_id;

typedef struct {
    mx_crt_services *services;
    mx_cfg_memory *guest_memory;
    uint64_t owner_id;
    uint64_t dll_heap_base;
    uint32_t dll_heap_capacity;
} mx_crt_service_adapter;

/* 1=handled, 0=unknown, -1=missing/unsafe context or lock contention.
 * Only RAX and guest-memory effects are modeled. This is not Win64
 * exception/unwind, ABI stack manipulation or real heap implementation.
 */
static inline int mx_crt_dispatch_service(mx_crt_service_adapter *a,
                                           mx_crt_service_id id,
                                           uint64_t rcx,uint64_t rdx,uint64_t r8,
                                           uint64_t *guest_rax) {
    if (id<MX_CRT_SERVICE_ENCODE_POINTER || id>MX_CRT_SERVICE_UNLOCK)
        return 0;
    if (!a || !a->services || !a->services->pointer_key || !guest_rax)
        return -1;
    switch (id) {
    case MX_CRT_SERVICE_ENCODE_POINTER:
        *guest_rax=mx_crt_encode_pointer(a->services,rcx);
        return 1;
    case MX_CRT_SERVICE_DECODE_POINTER:
        *guest_rax=mx_crt_decode_pointer(a->services,rcx);
        return 1;
    case MX_CRT_SERVICE_ONEXIT:
        *guest_rax=mx_crt_service_onexit(a->services,rcx);
        return 1;
    case MX_CRT_SERVICE_DLLONEXIT:
        if (!a->guest_memory || !a->dll_heap_base ||
            !a->dll_heap_capacity)return -1;
        *guest_rax=mx_crt_service_dllonexit(a->guest_memory,rcx,rdx,r8,
                                             a->dll_heap_base,
                                             a->dll_heap_capacity);
        return 1;
    case MX_CRT_SERVICE_LOCK:
    case MX_CRT_SERVICE_UNLOCK: {
        if (rcx>UINT32_MAX)return -1;
        int status=id==MX_CRT_SERVICE_LOCK
            ? mx_crt_service_lock(a->services,(uint32_t)rcx,a->owner_id)
            : mx_crt_service_unlock(a->services,(uint32_t)rcx,a->owner_id);
        /* Void _lock/_unlock do not promise RAX; preserve its input. */
        return status==MX_CRT_SVC_OK ? 1 : -1;
    }
    default:
        return 0;
    }
}
#endif
