#ifndef MX_CRT_MAIN_HANDOFF_H
#define MX_CRT_MAIN_HANDOFF_H
/*
 * Strict, bounded post-CRT continuation for the original Win64 empty-command
 * line path. Advances only to the game's direct main CALL, never executes
 * that CALL or claims an engine boot.
 *
 * The private importer validates all instruction identities and supplies
 * the precise source/target VAs, pointer imports and stack layout. This
 * intentionally rejects nonempty/quoted command lines and nonzero exit
 * registration state until their native branches are implemented.
 */
#include <stdint.h>
#include "mx_crt_vm.h"

typedef struct {
    uint64_t continuation_pc, main_call_pc, executable_base;
    uint64_t onexit_state_va, command_line_iat_va;
    uint64_t rdx, r8, r9;
    uint32_t commands_consumed;
    uint8_t reached_main_call;
} mx_crt_main_handoff;

static inline int mx_crt_advance_to_main_call(
        mx_crt_state *s, mx_cfg_memory *memory, mx_crt_main_handoff *out) {
    if (!s || !memory || !out || s->fault || s->pending_import ||
        !out->continuation_pc || !out->main_call_pc ||
        !out->executable_base || !out->onexit_state_va ||
        !out->command_line_iat_va ||
        s->rip!=out->continuation_pc || s->rsp>UINT64_MAX-0x72U)
        return MX_CRT_INVALID;
    /* The original CMP/J(E) after lock release. Nonzero requires the
     * authentic exit-register helper, which this bridge cannot yet run. */
    uint64_t onexit=0U;
    if (!mx_cfg_transfer(memory,out->onexit_state_va,&onexit,8U,0))
        return MX_CRT_MEMORY_FAULT;
    if(onexit!=0U)return MX_CRT_IMPORT_BOUNDARY;

    /* mov rax, [_acmdln IAT]; mov rdi, [rax].
     * _acmdln is a DLL DATA import (pointer-to-pointer), not a function. */
    uint64_t command_slot=0U,command_line=0U;
    if (!mx_cfg_transfer(memory,out->command_line_iat_va,&command_slot,8U,0) ||
        !command_slot ||
        !mx_cfg_transfer(memory,command_slot,&command_line,8U,0) ||
        !command_line)return MX_CRT_MEMORY_FAULT;

    /* This slice covers the original empty-command-line control path:
     * first character must be NUL. Nonempty paths are never skipped. */
    uint8_t first=0U;
    if (!mx_cfg_transfer(memory,command_line,&first,1U,0))
        return MX_CRT_MEMORY_FAULT;
    if(first!=0U)return MX_CRT_IMPORT_BOUNDARY;

    uint32_t initial_mode=0,show_flags=0;
    uint16_t show_command=0;
    if (!mx_cfg_transfer(memory,s->rsp+0x20U,&initial_mode,4U,0) ||
        !mx_cfg_transfer(memory,s->rsp+0x6cU,&show_flags,4U,0) ||
        !mx_cfg_transfer(memory,s->rsp+0x70U,&show_command,2U,0))
        return MX_CRT_MEMORY_FAULT;

    /* At 0x2ab166 the original TEST flag; MOVZX show; CMOVNE;
     * MOV R8, RDI; XOR EDX, EDX; LEA RCX,[image_base].
     * These outputs describe the ABI at the CALL boundary. */
    uint64_t show=(show_flags&1U)?show_command:10U;
    if (!mx_cfg_transfer(memory,s->rsp+0x28U,&command_line,8U,1))
        return MX_CRT_MEMORY_FAULT;
    s->rax=command_slot;
    s->rdi=command_line;
    s->rsi=initial_mode;
    s->rcx=out->executable_base;
    s->rip=out->main_call_pc;
    s->zf=1U;
    out->rdx=0U;
    out->r8=command_line;
    out->r9=show;
    out->commands_consumed=1U;
    out->reached_main_call=1U;
    return MX_CRT_BRANCH_BOUNDARY;
}
#endif
