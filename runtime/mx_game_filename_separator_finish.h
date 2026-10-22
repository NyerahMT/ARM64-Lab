#ifndef MX_GAME_FILENAME_SEPARATOR_FINISH_H
#define MX_GAME_FILENAME_SEPARATOR_FINISH_H
/*
 * ORIGINAL MX Bikes separator-present filename exit, 0x15B809:
 *   mov rax, qword ptr [rsp+0x20]  ; last slash/backslash
 *   mov byte ptr [rax+1], 0        ; terminate after directory separator
 *   lea rax, [rip+0x23b087]        ; filename buffer at RVA 0x3968A0
 *   jmp 0x15B862                  ; next original shared epilogue
 *
 * This is an independently identity-checked, four-instruction native guest
 * block. It does NOT execute the post-jump block or claim the entire helper
 * has returned. All pointers refer to mapped guest memory, never host RAM.
 */
#include <stdint.h>
#include "mx_crt_cluster_guest.h"

enum {
    MX_GAME_FILENAME_FINISH_REACHED=1,
    MX_GAME_FILENAME_FINISH_INVALID=-201,
    MX_GAME_FILENAME_FINISH_UNMAPPED=-202
};
typedef struct {
    uint64_t entry_va, filename_global_va, continuation_va;
    uint32_t filename_capacity;
} mx_game_filename_finish_layout;

static inline int mx_game_filename_finish_separator(
    mx_crt_cluster_state*s,mx_cfg_memory*m,
    const mx_game_filename_finish_layout*l) {
    if(!s||!m||!l||s->fault||
       s->rip!=l->entry_va||!l->filename_global_va||
       !l->continuation_va||(s->rsp&15U)!=0U||
       s->rsp>UINT64_MAX-0x30U||
       l->filename_capacity<2U||l->filename_capacity>4096U||
       l->filename_global_va>UINT64_MAX-l->filename_capacity)
        return MX_GAME_FILENAME_FINISH_INVALID;
    uint64_t slash=0U;
    if(!mx_cfg_transfer(m,s->rsp+0x20U,&slash,8U,0))
        return MX_GAME_FILENAME_FINISH_UNMAPPED;
    if(slash<l->filename_global_va||
       slash>=l->filename_global_va+l->filename_capacity-1U)
        return MX_GAME_FILENAME_FINISH_INVALID;
    uint8_t old=0U;
    if(!mx_cfg_transfer(m,slash+1U,&old,1U,0))
        return MX_GAME_FILENAME_FINISH_UNMAPPED;
    const uint8_t zero=0U;
    if(!mx_cfg_transfer(m,slash+1U,(void*)&zero,1U,1))
        return MX_GAME_FILENAME_FINISH_UNMAPPED;
    s->rax=l->filename_global_va;
    s->rip=l->continuation_va;
    s->instructions+=4U;
    /* The original MOV, MOV, LEA and JMP leave arithmetic flags intact. */
    (void)old;
    return MX_GAME_FILENAME_FINISH_REACHED;
}
#endif
