#ifndef MX_GAME_MAIN_CALLEE_PREFIX_H
#define MX_GAME_MAIN_CALLEE_PREFIX_H
/*
 * Strict first-branch native translation of the original MX Bikes
 * game main's first direct callee, not its full function:
 *  LEA RAX,[RIP+disp] ; MOV R10D,1 ; MOV [RIP+disp],RAX ;
 *  MOVZX EAX,BYTE [RCX] ; MOV [RIP+disp],R10D ;
 *  TEST AL,AL ; JE target.
 *
 * Original PE instruction identity, memory addresses, branch destinations
 * and output guest state are validated by the PRIVATE original x64 differential.
 * The untranslated branch destination must NOT be treated as callable.
 */
#include <stdint.h>
#include "mx_crt_cluster_guest.h"

enum {
  MX_GAME_PREFIX_BRANCH_REACHED=1,
  MX_GAME_PREFIX_BAD_STATE=-61,
  MX_GAME_PREFIX_UNMAPPED=-62
};
typedef struct {
    uint64_t original_entry_va;
    uint64_t constant_address_va;
    uint64_t output_address_global_va;
    uint64_t output_flag_global_va;
    uint64_t branch_taken_va;
    uint64_t branch_fallthrough_va;
} mx_game_main_callee_layout;

typedef struct {
    uint64_t r10;
    uint8_t branch_taken;
    uint8_t input_first_byte;
    uint32_t executed_original_instructions;
} mx_game_main_callee_out;

static inline int mx_game_main_callee_branch(
   mx_crt_cluster_state *s,mx_cfg_memory *memory,
   const mx_game_main_callee_layout *layout,mx_game_main_callee_out *out){
    if(!s || !memory || !layout || !out || s->fault ||
       s->rip!=layout->original_entry_va || s->rsp<8U ||
       (s->rsp&15U)!=8U ||
       !layout->constant_address_va || !layout->output_address_global_va ||
       !layout->output_flag_global_va ||
       !layout->branch_taken_va || !layout->branch_fallthrough_va)
        return MX_GAME_PREFIX_BAD_STATE;
    uint8_t first=0U;
    uint64_t old_global=0U;
    uint32_t old_flag=0U;
    /* Full preflight of every guest access before mutating any state. */
    if(!mx_cfg_transfer(memory,s->rcx,&first,1U,0) ||
       !mx_cfg_transfer(memory,layout->output_address_global_va,&old_global,8U,0) ||
       !mx_cfg_transfer(memory,layout->output_flag_global_va,&old_flag,4U,0))
        return MX_GAME_PREFIX_UNMAPPED;
    uint64_t resolved=layout->constant_address_va;
    uint32_t r10d=1U;
    if(!mx_cfg_transfer(memory,layout->output_address_global_va,&resolved,8U,1) ||
       !mx_cfg_transfer(memory,layout->output_flag_global_va,&r10d,4U,1))
        return MX_GAME_PREFIX_UNMAPPED;

    /* TEST AL,AL changes SF,ZF,CF and OF; the guest cluster currently
     * tracks SF,ZF,CF, but not OF. The original test always sets OF=0. */
    s->rax=(uint64_t)first;
    s->zf=(uint8_t)(first==0U);
    s->sf=(uint8_t)((first>>7)&1U);
    s->cf=0U;
    s->rip=first==0U ? layout->branch_taken_va :
                       layout->branch_fallthrough_va;
    s->instructions+=7U; /* six straight-line instructions + JE */
    out->r10=1U;
    out->branch_taken=(uint8_t)(first==0U);
    out->input_first_byte=first;
    out->executed_original_instructions=7U;
    return MX_GAME_PREFIX_BRANCH_REACHED;
}
#endif
