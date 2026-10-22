#ifndef MX_CRT_TO_MAIN_PREFIX_H
#define MX_CRT_TO_MAIN_PREFIX_H
/*
 * Strict Win64 CRT -> game-main CALL handoff in ONE guest address space.
 *
 * The caller must privately verify original CALL instruction identity,
 * original main prefix opcode forms, and every layout virtual address.
 * This bridge only handles the first eight original main instructions and
 * stops at the callee CALL boundary. It is NOT a PE loader, Win32 runtime,
 * native game main, Steam or iOS boot.
 */
#include <stdint.h>
#include "mx_crt_main_handoff.h"
#include "mx_main_entry_prefix.h"

typedef struct {
    uint64_t crt_direct_call_pc;
    uint64_t crt_return_pc;
    mx_main_prefix_layout prefix;
} mx_crt_to_main_layout;

static inline int mx_crt_enter_main_prefix(
        const mx_crt_state *crt, const mx_crt_main_handoff *hand,
        mx_cfg_memory *memory, const mx_crt_to_main_layout *layout,
        mx_main_prefix_state *out) {
    if (!crt || !hand || !memory || !layout || !out ||
        crt->fault || crt->pending_import ||
        !hand->reached_main_call || hand->commands_consumed!=1U ||
        !hand->executable_base || !hand->r8 ||
        crt->rip!=layout->crt_direct_call_pc ||
        hand->main_call_pc!=layout->crt_direct_call_pc ||
        layout->prefix.entry<hand->executable_base ||
        !layout->crt_return_pc ||
        layout->crt_direct_call_pc>UINT64_MAX-5U ||
        layout->crt_return_pc!=layout->crt_direct_call_pc+5U ||
        (crt->rsp&15U)!=0U ||
        crt->rsp<layout->prefix.stack_alloc+8U)
        return MX_MAIN_PREFIX_INVALID;

    /* The original x64 CALL pushes the next instruction address.
     * At the callee entry, RSP is eight below the aligned CRT caller RSP.
     * Make sure that original CALL slot and every subsequent write are
     * mapped before changing guest memory.
     */
    const uint64_t call_rsp=crt->rsp-8U;
    const uint64_t frame_rsp=call_rsp-layout->prefix.stack_alloc;
    if (frame_rsp>UINT64_MAX-layout->prefix.cookie_stack_offset)
        return MX_MAIN_PREFIX_INVALID;
    const uint64_t cookie_dest=frame_rsp+layout->prefix.cookie_stack_offset;
    uint64_t checked=0U;
    uint32_t checked32=0U;
    if (!mx_cfg_transfer(memory,call_rsp,&checked,8U,0) ||
        !mx_cfg_transfer(memory,cookie_dest,&checked,8U,0) ||
        !mx_cfg_transfer(memory,layout->prefix.cookie_va,&checked,8U,0) ||
        !mx_cfg_transfer(memory,layout->prefix.arg0_global,&checked,8U,0) ||
        !mx_cfg_transfer(memory,layout->prefix.arg1_global,&checked,8U,0) ||
        !mx_cfg_transfer(memory,layout->prefix.show_global,&checked32,4U,0))
        return MX_MAIN_PREFIX_INVALID;

    mx_main_prefix_state candidate={0};
    candidate.rip=layout->prefix.entry;
    candidate.rsp=call_rsp;
    candidate.rax=crt->rax;
    candidate.rcx=crt->rcx;
    candidate.rdx=hand->rdx;
    candidate.r8=hand->r8;
    candidate.r9=hand->r9;
    candidate.zf=(uint32_t)crt->zf;
    if(!mx_cfg_transfer(memory,call_rsp,
                        (void*)&layout->crt_return_pc,8U,1))
        return MX_MAIN_PREFIX_INVALID;
    const int result=mx_main_execute_prefix(
        &candidate,memory,&layout->prefix);
    if(result!=MX_MAIN_PREFIX_CALL_BOUNDARY)
        return MX_MAIN_PREFIX_INVALID;
    *out=candidate;
    return MX_MAIN_PREFIX_CALL_BOUNDARY;
}
#endif
