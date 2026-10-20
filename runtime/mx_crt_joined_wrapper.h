#ifndef MX_CRT_JOINED_WRAPPER_H
#define MX_CRT_JOINED_WRAPPER_H
/*
 * Generic, bounded Win64 nested wrapper->child guest-state bridge.
 *
 * The caller must independently verify the concrete wrapper's original
 * x64 instruction sequence and direct callee target. This helper preserves
 * volatile register and memory side effects of the translated child, unlike
 * a stand-in callback that supplies only a guessed child RAX result.
 *
 * The wrapper semantics modeled here are:
 * sub rsp,0x28; CALL rel32 child; neg rax; sbb eax,eax;
 * neg eax; dec eax; add rsp,0x28; ret.
 *
 * Imported service callback contracts remain explicit and fail-closed.
 * Not a Windows loader, CRT implementation, Steam integration or game boot.
 */
#include "mx_crt_cluster_guest.h"

typedef int (*mx_crt_joined_child_fn)(
    mx_crt_cluster_state *, mx_cfg_memory *, mx_crt_cluster_import_fn, void *);

static inline int mx_crt_joined_wrapper8(
        mx_crt_cluster_state *s, mx_cfg_memory *mem,
        uint64_t wrapper_pc, uint64_t child_pc,
        mx_crt_joined_child_fn child,
        mx_crt_cluster_import_fn import_callback,
        void *context) {
    if (!s || !mem || !child || !import_callback || s->fault ||
        s->rip != wrapper_pc || wrapper_pc > UINT64_MAX-9U ||
        !child_pc || child_pc == wrapper_pc ||
        s->rsp < 0x38U || (s->rsp & 15U) != 8U ||
        s->rsp > UINT64_MAX-8U)
        return MX_CRT_CLUSTER_INVALID;

    const uint64_t initial_rsp = s->rsp;
    uint64_t original_return = 0;
    if (!mx_cfg_transfer(mem, initial_rsp, &original_return, 8U, 0))
        return MX_CRT_CLUSTER_MEMORY_FAULT;
    /* Original SUB RSP,0x28 and CALL rel32 put continuation at -0x30. */
    const uint64_t child_entry_rsp = initial_rsp - 0x30U;
    const uint64_t child_continuation = wrapper_pc + 9U;
    if (!mx_cfg_transfer(mem, child_entry_rsp,
                         (void *)&child_continuation, 8U, 1))
        return MX_CRT_CLUSTER_MEMORY_FAULT;
    s->rsp = child_entry_rsp;
    s->rip = child_pc;

    const int outcome = child(s, mem, import_callback, context);
    if (outcome != MX_CRT_CLUSTER_RETURNED)
        return outcome;
    if (s->fault || s->rsp != initial_rsp - 0x28U ||
        s->rip != child_continuation)
        return MX_CRT_CLUSTER_INVALID;

    /* Convert child pointer/status RAX into original wrapper return EAX.
     * Zero -> UINT32_MAX, nonzero -> 0; the 32-bit write zero extends RAX.
     */
    s->rax = s->rax == 0 ? UINT64_C(0xffffffff) : 0U;
    /* ADD RSP,0x28 updates ZF based on the nonzero aligned guest stack. */
    s->zf = 0U;
    s->rsp = initial_rsp;
    s->rip = original_return;
    s->rsp += 8U;
    if (s->instructions > UINT32_MAX-8U)
        return MX_CRT_CLUSTER_INVALID;
    s->instructions += 8U;
    return MX_CRT_CLUSTER_RETURNED;
}
#endif
