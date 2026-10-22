#ifndef MX_GAME_FILENAME_LOOP_ITERATION_H
#define MX_GAME_FILENAME_LOOP_ITERATION_H
/*
 * Original MX Bikes filename parser loop body at RVA 0x15b7c1:
 * MOV RAX,QWORD [RSP+0x28]; ADD RAX,1;
 * MOV QWORD [RSP+0x28],RAX;
 * MOV RAX,QWORD [RSP+0x28]; MOVSX EAX,BYTE [RAX];
 * TEST EAX,EAX; JE 0x15b801 (fallthrough 0x15b7db).
 *
 * This executes exactly ONE bounded iteration and stops at either
 * original branch successor. It must not silently re-enter the loop.
 */
#include <stdint.h>
#include "mx_crt_cluster_guest.h"
enum {
 MX_GAME_LOOP_ITERATION_REACHED=1,
 MX_GAME_LOOP_ITERATION_INVALID=-151,
 MX_GAME_LOOP_ITERATION_UNMAPPED=-152
};
typedef struct {
 uint64_t entry_va,zero_destination_va,nonzero_destination_va;
} mx_game_filename_iteration_layout;
typedef struct {
 uint64_t original_next_pointer;
 uint8_t next_character;
 uint8_t zero_branch;
} mx_game_filename_iteration_result;

static inline int mx_game_filename_loop_iteration(
 mx_crt_cluster_state*s,mx_cfg_memory*m,
 const mx_game_filename_iteration_layout*l,
 mx_game_filename_iteration_result*out){
 if(!s||!m||!l||!out||s->fault||s->rip!=l->entry_va||
    !l->zero_destination_va||!l->nonzero_destination_va||
    l->zero_destination_va==l->nonzero_destination_va||
    (s->rsp&15U)!=0U||s->rsp>UINT64_MAX-0x30U)
    return MX_GAME_LOOP_ITERATION_INVALID;
 uint64_t current=0U;
 if(!mx_cfg_transfer(m,s->rsp+0x28U,&current,8U,0)||
    !current||current==UINT64_MAX)
    return MX_GAME_LOOP_ITERATION_UNMAPPED;
 const uint64_t next=current+1U;
 uint8_t value=0U;
 if(!mx_cfg_transfer(m,next,&value,1U,0))
    return MX_GAME_LOOP_ITERATION_UNMAPPED;
 if(!mx_cfg_transfer(m,s->rsp+0x28U,&next,8U,1))
    return MX_GAME_LOOP_ITERATION_UNMAPPED;
 const uint32_t eax=(uint32_t)(int32_t)(int8_t)value;
 s->rax=(uint64_t)eax;
 s->zf=(uint8_t)(eax==0U);
 s->sf=(uint8_t)((eax>>31U)&1U);
 s->cf=0U;
 s->rip=s->zf?l->zero_destination_va:l->nonzero_destination_va;
 s->instructions+=7U;
 out->original_next_pointer=next;
 out->next_character=value;
 out->zero_branch=s->zf;
 return MX_GAME_LOOP_ITERATION_REACHED;
}
#endif
