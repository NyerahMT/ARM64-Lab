#ifndef MX_GAME_PATH_HELPER_PREFIX_H
#define MX_GAME_PATH_HELPER_PREFIX_H
/*
 * Original MX Bikes game-main filename helper, RVA 0x15b790, strictly
 * validated first basic block before CALL at RVA 0x15b7a5:
 * MOV [RSP+8],RCX; SUB RSP,0x38; MOV RDX,[RSP+0x40];
 * LEA RCX,[RIP+0x23b0fb].
 *
 * On entry the guest RSP includes the real return slot from a prior CALL.
 * This function preserves that return slot and stops before another original
 * internal CALL to RVA 0x2ab41a. No unverified successor is executed.
 */
#include <stdint.h>
#include "mx_crt_cluster_guest.h"

enum {
    MX_GAME_PATH_HELPER_FRONTIER=1,
    MX_GAME_PATH_HELPER_BAD_STATE=-91,
    MX_GAME_PATH_HELPER_GUEST_FAULT=-92
};
typedef struct {
    uint64_t original_entry_va,original_next_call_va;
    uint64_t original_constant_va;
    uint32_t stack_bytes;
} mx_game_path_helper_layout;

static inline int mx_game_main_prepare_path_helper(
        mx_crt_cluster_state*s,uint64_t after_filename_va,
        uint64_t helper_callsite_va){
    if(!s||s->fault||s->rip!=after_filename_va||
       !helper_callsite_va||s->rsp>UINT64_MAX-0x140U)
        return MX_GAME_PATH_HELPER_BAD_STATE;
    /* Original LEA RCX,[RSP+0x140], no flags modified. */
    s->rcx=s->rsp+0x140U;
    s->rip=helper_callsite_va;
    s->instructions+=1U;
    return MX_GAME_PATH_HELPER_FRONTIER;
}
static inline int mx_game_path_helper_first_block(
        mx_crt_cluster_state*s,mx_cfg_memory*m,
        const mx_game_path_helper_layout*l){
    if(!s||!m||!l||s->fault||s->rip!=l->original_entry_va||
       (s->rsp&15U)!=8U||s->rsp<l->stack_bytes||
       l->stack_bytes!=0x38U||
       !l->original_next_call_va||!l->original_constant_va)
        return MX_GAME_PATH_HELPER_BAD_STATE;
    const uint64_t original_rsp=s->rsp;
    const uint64_t allocated_rsp=original_rsp-l->stack_bytes;
    if(original_rsp>UINT64_MAX-8U||allocated_rsp>UINT64_MAX-0x40U)
        return MX_GAME_PATH_HELPER_BAD_STATE;
    uint64_t saved_arg=0U;
    uint64_t old=0U;
    uint64_t old_stack=0U;
    uint64_t return_address=0U;
    if(!mx_cfg_transfer(m,original_rsp,&return_address,8U,0)||
       !return_address ||
       !mx_cfg_transfer(m,original_rsp+8U,&old,8U,0)||
       !mx_cfg_transfer(m,allocated_rsp,&old_stack,8U,0))
        return MX_GAME_PATH_HELPER_GUEST_FAULT;
    saved_arg=s->rcx;
    if(!mx_cfg_transfer(m,original_rsp+8U,&saved_arg,8U,1))
        return MX_GAME_PATH_HELPER_GUEST_FAULT;
    /* MOV [RSP+8],RCX followed by SUB RSP,0x38.
     * Re-loading [RSP+0x40] reads the just-saved RCX argument. */
    s->rsp=allocated_rsp;
    s->rdx=saved_arg;
    s->rcx=l->original_constant_va;
    /* SUB RSP,0x38 sets flags. No borrow under preflight. */
    s->zf=(uint8_t)(allocated_rsp==0U);
    s->sf=(uint8_t)((allocated_rsp>>63U)&1U);
    s->cf=0U;
    s->rip=l->original_next_call_va;
    s->instructions+=4U;
    return MX_GAME_PATH_HELPER_FRONTIER;
}
#endif
