#ifndef MX_CRT_CLUSTER_GUEST_H
#define MX_CRT_CLUSTER_GUEST_H
/*
 * Bounded Win64 guest-register/memory adapter for a small, verified import
 * cluster compiled as native C/AArch64. Its imported services are supplied
 * by the caller and MUST fail closed if unavailable. It does not load PE
 * files, run arbitrary x64, implement Steam, or execute real MSVCR90.
 */
#include <stdint.h>
#include "mx_crt_service_dispatch.h"

typedef struct {
    uint64_t rax, rbx, rcx, rdx, r8, r9, rdi, rsi, r11;
    uint64_t rsp, rip, visited;
    uint32_t instructions, imports, local_calls;
    uint8_t local_depth;
    uint8_t zf, sf, cf, fault;
} mx_crt_cluster_state;

typedef int (*mx_crt_cluster_import_fn)(
    void *context, mx_crt_service_id service,
    mx_crt_cluster_state *state, mx_cfg_memory *memory,
    uint64_t callee_stack_pointer);

/* Authentic direct intra-image CALL targets must be explicitly mapped
 * to separately verified native implementations. A registered callback is
 * never proof that the original target body has been translated. */
typedef int (*mx_crt_cluster_direct_fn)(
    void *context, uint64_t target_va,
    mx_crt_cluster_state *state, mx_cfg_memory *memory);

enum {
    MX_CRT_CLUSTER_RETURNED = 1,
    MX_CRT_CLUSTER_INVALID = -1,
    MX_CRT_CLUSTER_MEMORY_FAULT = -2,
    MX_CRT_CLUSTER_IMPORT_UNSUPPORTED = -3
};

/* No unbounded host pointer traversal. All loads/stores are checked. */
static inline uint64_t mx_crt_cluster_read(
    mx_crt_cluster_state *s, mx_cfg_memory *m,
    uint64_t guest_address, uint32_t size) {
    uint64_t out = 0;
    if (!mx_cfg_transfer(m, guest_address, &out, size, 0)) s->fault = 1;
    return out;
}
static inline int mx_crt_cluster_write(
    mx_crt_cluster_state *s, mx_cfg_memory *m,
    uint64_t guest_address, uint32_t size, uint64_t value) {
    if (!mx_cfg_transfer(m, guest_address, &value, size, 1)) {
        s->fault = 1;
        return 0;
    }
    return 1;
}
/* The generated function is linked into the same native executable as the
 * guest-memory runtime and host's explicit service callback. */
int lifted_crt_import_cluster(mx_crt_cluster_state *s, mx_cfg_memory *m,
                              mx_crt_cluster_import_fn callback, void *ctx);
#endif
