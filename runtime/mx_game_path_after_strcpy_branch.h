#ifndef MX_GAME_PATH_AFTER_STRCPY_BRANCH_H
#define MX_GAME_PATH_AFTER_STRCPY_BRANCH_H
/*
 * Verified original filename-helper branch at RVA 0x15b7cf:
 * MOV RAX,QWORD PTR [RSP+0x28]
 * MOVSX EAX,BYTE PTR [RAX]    (32-bit sign extend, zero extend to RAX)
 * TEST EAX,EAX                (ZF/SF/CF; OF is cleared but not modeled)
 * JE 0x15b801                 (fallthrough 0x15b7db).
 *
 * Original guest-memory load is bounded; no branch successors executed.
 * Source byte (often in .rdata) must be explicitly mapped from the owned PE.
 */
#include <stdint.h>
#include "mx_crt_cluster_guest.h"
enum {
    MX_GAME_PATH_BRANCH_REACHED=1,
    MX_GAME_PATH_BRANCH_INVALID=-121,
    MX_GAME_PATH_BRANCH_UNMAPPED=-122
};
typedef struct {
    uint64_t start_va;
    uint64_t original_taken_va;
    uint64_t original_fallthrough_va;
} mx_game_path_after_strcpy_branch_layout;
typedef struct {
    uint64_t source_pointer;
    uint8_t source_byte;
    uint8_t branch_taken;
} mx_game_path_after_strcpy_branch_result;

static inline int mx_game_path_after_strcpy_branch(
    mx_crt_cluster_state*s,mx_cfg_memory*m,
    const mx_game_path_after_strcpy_branch_layout*l,
    mx_game_path_after_strcpy_branch_result*out){
    if(!s||!m||!l||!out||s->fault||s->rip!=l->start_va||
       !l->original_taken_va||!l->original_fallthrough_va||
       l->original_taken_va==l->original_fallthrough_va||
       (s->rsp&15U)!=0U||s->rsp>UINT64_MAX-0x30U)
        return MX_GAME_PATH_BRANCH_INVALID;
    uint64_t original_pointer=0U;
    if(!mx_cfg_transfer(m,s->rsp+0x28U,&original_pointer,8U,0)||
       !original_pointer)
        return MX_GAME_PATH_BRANCH_UNMAPPED;
    uint8_t value=0U;
    if(!mx_cfg_transfer(m,original_pointer,&value,1U,0))
        return MX_GAME_PATH_BRANCH_UNMAPPED;
    /* Original MOVSX writes EAX, therefore clears the high 32 bits of RAX.
     * A negative byte becomes 0x00000000FFFFFFxx, NOT a sign-extended RAX. */
    uint32_t eax=(uint32_t)(int32_t)(int8_t)value;
    s->rax=(uint64_t)eax;
    s->cf=0U;
    s->sf=(uint8_t)((eax>>31U)&1U);
    s->zf=(uint8_t)(eax==0U);
    s->rip=s->zf ? l->original_taken_va : l->original_fallthrough_va;
    s->instructions+=4U;
    out->source_pointer=original_pointer;
    out->source_byte=value;
    out->branch_taken=s->zf;
    return MX_GAME_PATH_BRANCH_REACHED;
}
#endif
