#ifndef MX_GAME_FILENAME_HELPER_RETURN_H
#define MX_GAME_FILENAME_HELPER_RETURN_H
/*
 * Original MX Bikes game filename helper shared epilogue:
 * RVA 0x15B862 ADD RSP,0x38; RVA 0x15B866 RET.
 *
 * The x64 Win64 direct CALL at original 0x136764 has already placed the
 * authentic continuation (0x136769) at the helper's return slot before
 * SUB RSP,0x38. This AArch64 native guest adapter performs the corresponding
 * 2 original instructions, consuming the original saved return address.
 *
 * No external runtime imports, synthetic stubs, or restoration of any
 * non-machine state. Invalid stack, return address or unmapped memory fails
 * without changing registers, RIP, RSP or instruction counts.
 */
#include <stdint.h>
#include "mx_crt_cluster_guest.h"

enum {
    MX_GAME_HELPER_EPILOGUE_RETURNED=1,
    MX_GAME_HELPER_EPILOGUE_INVALID=-211,
    MX_GAME_HELPER_EPILOGUE_UNMAPPED=-212,
    MX_GAME_HELPER_EPILOGUE_BAD_RETURN=-213
};
typedef struct {
    uint64_t epilogue_pc, continuation_pc;
    uint64_t caller_rsp;
    uint32_t original_local_bytes;
} mx_game_filename_helper_return_layout;
static inline int mx_game_filename_helper_return(
    mx_crt_cluster_state*s,mx_cfg_memory*m,
    const mx_game_filename_helper_return_layout*l) {
    if(!s||!m||!l||s->fault||!l->epilogue_pc||
       !l->continuation_pc||!l->caller_rsp||
       s->rip!=l->epilogue_pc||
       l->original_local_bytes!=0x38U||
       (s->rsp&15U)!=0U||
       s->rsp>UINT64_MAX-0x40U||
       s->rsp+0x40U!=l->caller_rsp ||
       (l->caller_rsp&15U)!=0U)
        return MX_GAME_HELPER_EPILOGUE_INVALID;
    const uint64_t ret_rsp=s->rsp+0x38U;
    uint64_t return_va=0U;
    if(!mx_cfg_transfer(m,ret_rsp,&return_va,8U,0))
        return MX_GAME_HELPER_EPILOGUE_UNMAPPED;
    if(return_va!=l->continuation_pc)
        return MX_GAME_HELPER_EPILOGUE_BAD_RETURN;
    const uint64_t sum=ret_rsp;
    /* Original ADD RSP,0x38 changes arithmetic flags. Model the
     * exposed CF/SF/ZF subset; OF/AF/PF are not yet in guest state.
     * RET itself leaves arithmetic flags unchanged. */
    s->cf=(uint8_t)(sum<s->rsp);
    s->sf=(uint8_t)((sum>>63U)&1U);
    s->zf=(uint8_t)(sum==0U);
    s->rsp=l->caller_rsp;
    s->rip=return_va;
    s->instructions+=2U;
    return MX_GAME_HELPER_EPILOGUE_RETURNED;
}
#endif
