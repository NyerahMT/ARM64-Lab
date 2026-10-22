#ifndef MX_GAME_PATH_AFTER_STRCPY_H
#define MX_GAME_PATH_AFTER_STRCPY_H
/*
 * Original game filename helper AFTER a successful MSVCR90!strcpy thunk.
 * RVA 0x15b7aa: MOV QWORD [RSP+0x20],0; LEA RAX,[RIP+0x23b0e6];
 *               MOV QWORD [RSP+0x28],RAX; JMP 0x15b7cf.
 *
 * This is a verified bounded original x64 block, not a full function.
 * It prepares helper stack locals and jumps to the next unimplemented
 * control frontier. Inputs must use guest addresses, never host pointers.
 */
#include <stdint.h>
#include "mx_crt_cluster_guest.h"
enum {
    MX_GAME_PATH_AFTER_STRCPY_FRONTIER=1,
    MX_GAME_PATH_AFTER_STRCPY_INVALID=-111,
    MX_GAME_PATH_AFTER_STRCPY_UNMAPPED=-112
};
typedef struct {
    uint64_t original_block_va;
    uint64_t original_constant_va;
    uint64_t original_jump_target_va;
} mx_game_path_after_strcpy_layout;

static inline int mx_game_path_after_strcpy(
        mx_crt_cluster_state*s,mx_cfg_memory*m,
        const mx_game_path_after_strcpy_layout*l){
    if(!s||!m||!l||s->fault||s->rip!=l->original_block_va||
       !l->original_constant_va||!l->original_jump_target_va||
       (s->rsp&15U)!=0U||s->rsp>UINT64_MAX-0x30U)
        return MX_GAME_PATH_AFTER_STRCPY_INVALID;
    uint64_t old0=0U,old1=0U;
    if(!mx_cfg_transfer(m,s->rsp+0x20U,&old0,8U,0)||
       !mx_cfg_transfer(m,s->rsp+0x28U,&old1,8U,0))
        return MX_GAME_PATH_AFTER_STRCPY_UNMAPPED;
    uint64_t zero=0U;
    uint64_t addr=l->original_constant_va;
    if(!mx_cfg_transfer(m,s->rsp+0x20U,&zero,8U,1)||
       !mx_cfg_transfer(m,s->rsp+0x28U,&addr,8U,1))
        return MX_GAME_PATH_AFTER_STRCPY_UNMAPPED;
    s->rax=addr;
    s->rip=l->original_jump_target_va;
    s->instructions+=4U;
    /* MOV, LEA and JMP leave guest flags unchanged. */
    return MX_GAME_PATH_AFTER_STRCPY_FRONTIER;
}
#endif
