#ifndef MX_GAME_PATH_SLASH_LOOP_H
#define MX_GAME_PATH_SLASH_LOOP_H
/*
 * Bounded original MX Bikes filename normal-character successor:
 * RVA 0x15B7E8 MOV RAX,QWORD [RSP+0x28]
 * 0x15B7ED MOVSX EAX,BYTE [RAX]
 * 0x15B7F0 CMP EAX,0x2f
 * 0x15B7F3 JNE 0x15B7FF (fallthrough 0x15B7F5)
 * 0x15B7FF JMP 0x15B7C1, only when JNE was taken.
 *
 * Handles original x64 32-bit sign extension; checks all guest accesses
 * before any mutations and fails closed on invalid PC/stack.
 * Stops at original loop entry or separator-found path.
 */
#include <stdint.h>
#include "mx_crt_cluster_guest.h"
enum {
 MX_GAME_SLASH_LOOP_REACHED=1,
 MX_GAME_SLASH_LOOP_INVALID=-141,
 MX_GAME_SLASH_LOOP_UNMAPPED=-142
};
typedef struct {
 uint64_t start_va;
 uint64_t found_separator_va;
 uint64_t next_loop_va;
} mx_game_slash_loop_layout;

static inline int mx_game_slash_loop(
 mx_crt_cluster_state*s,mx_cfg_memory*m,
 const mx_game_slash_loop_layout*l){
 if(!s||!m||!l||s->fault||s->rip!=l->start_va||
    !l->found_separator_va||!l->next_loop_va||
    (s->rsp&15U)!=0U||s->rsp>UINT64_MAX-0x30U)
    return MX_GAME_SLASH_LOOP_INVALID;
 uint64_t pointer=0U;
 if(!mx_cfg_transfer(m,s->rsp+0x28U,&pointer,8U,0)||!pointer)
    return MX_GAME_SLASH_LOOP_UNMAPPED;
 uint8_t byte=0U;
 if(!mx_cfg_transfer(m,pointer,&byte,1U,0))
    return MX_GAME_SLASH_LOOP_UNMAPPED;
 const uint32_t eax=(uint32_t)(int32_t)(int8_t)byte;
 const uint32_t difference=eax-0x2fU;
 s->rax=(uint64_t)eax;
 s->cf=(uint8_t)(eax<0x2fU);
 s->sf=(uint8_t)((difference>>31U)&1U);
 s->zf=(uint8_t)(difference==0U);
 if(s->zf){
    s->rip=l->found_separator_va;
    s->instructions+=4U;
 }else{
    s->rip=l->next_loop_va;
    s->instructions+=5U; /* includes exact original JMP 0x15B7FF */
 }
 return MX_GAME_SLASH_LOOP_REACHED;
}
#endif
