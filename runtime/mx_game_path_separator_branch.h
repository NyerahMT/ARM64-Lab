#ifndef MX_GAME_PATH_SEPARATOR_BRANCH_H
#define MX_GAME_PATH_SEPARATOR_BRANCH_H
/*
 * Two ORIGINAL MX Bikes filename helper JE successors reached from
 * verified MOVSX/TEST JE at RVA 0x15b7d9.
 *
 * Nonzero:
 *  0x15b7db MOV RAX,[RSP+0x28]
 *  0x15b7e0 MOVSX EAX,BYTE [RAX]
 *  0x15b7e3 CMP EAX,0x5c
 *  0x15b7e6 JE 0x15b7f5  (fallthrough 0x15b7e8)
 *
 * Zero:
 *  0x15b801 CMP QWORD [RSP+0x20],0
 *  0x15b807 JE 0x15b81b (fallthrough 0x15b809)
 *
 * Native guest SF/ZF/CF supported; original OF is not tracked.
 * Both successors stop safely at their next original control destinations.
 */
#include <stdint.h>
#include "mx_crt_cluster_guest.h"
enum {
    MX_GAME_SEPARATOR_FRONTIER=1,
    MX_GAME_SEPARATOR_INVALID=-131,
    MX_GAME_SEPARATOR_UNMAPPED=-132
};
typedef struct {
    uint64_t normal_start_va, zero_start_va;
    uint64_t normal_taken_va, normal_fallthrough_va;
    uint64_t zero_taken_va, zero_fallthrough_va;
} mx_game_path_separator_layout;
typedef struct {
    uint8_t normalized_byte;
    uint8_t branch_taken;
    uint8_t zero_path;
} mx_game_path_separator_result;

static inline int mx_game_path_separator_branch(
    mx_crt_cluster_state*s,mx_cfg_memory*m,
    const mx_game_path_separator_layout*l,
    mx_game_path_separator_result*out){
    if(!s||!m||!l||!out||s->fault||
       (s->rip!=l->normal_start_va&&s->rip!=l->zero_start_va)||
       (s->rsp&15U)!=0U || s->rsp>UINT64_MAX-0x30U ||
       !l->normal_taken_va||!l->normal_fallthrough_va||
       !l->zero_taken_va||!l->zero_fallthrough_va)
        return MX_GAME_SEPARATOR_INVALID;
    const uint8_t is_zero_path=(uint8_t)(s->rip==l->zero_start_va);
    if(is_zero_path){
        uint64_t value=0U;
        if(!mx_cfg_transfer(m,s->rsp+0x20U,&value,8U,0))
            return MX_GAME_SEPARATOR_UNMAPPED;
        s->cf=0U;
        s->sf=(uint8_t)((value>>63U)&1U);
        s->zf=(uint8_t)(value==0U);
        s->rip=s->zf ? l->zero_taken_va:l->zero_fallthrough_va;
        s->instructions+=2U;
        out->normalized_byte=0U;
    }else{
        uint64_t address=0U;
        if(!mx_cfg_transfer(m,s->rsp+0x28U,&address,8U,0)||!address)
            return MX_GAME_SEPARATOR_UNMAPPED;
        uint8_t value=0U;
        if(!mx_cfg_transfer(m,address,&value,1U,0))
            return MX_GAME_SEPARATOR_UNMAPPED;
        const uint32_t eax=(uint32_t)(int32_t)(int8_t)value;
        const uint32_t difference=eax-0x5cU;
        s->rax=(uint64_t)eax;
        s->cf=(uint8_t)(eax<0x5cU);
        s->sf=(uint8_t)((difference>>31U)&1U);
        s->zf=(uint8_t)(difference==0U);
        s->rip=s->zf?l->normal_taken_va:l->normal_fallthrough_va;
        s->instructions+=4U;
        out->normalized_byte=value;
    }
    out->branch_taken=s->zf;
    out->zero_path=is_zero_path;
    return MX_GAME_SEPARATOR_FRONTIER;
}
#endif
