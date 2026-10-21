#ifndef MX_MAIN_ENTRY_PREFIX_H
#define MX_MAIN_ENTRY_PREFIX_H
/*
 * Bounded first basic block of a Win64 main-entry function:
 *   sub rsp,imm; mov rax,[rip+disp]; xor rax,rsp;
 *   mov [rsp+disp],rax; mov [rip+disp],rcx; mov rcx,r8;
 *   mov [rip+disp],rdx; mov dword [rip+disp],r9d.
 *
 * The private runner validates these exact eight source instruction forms,
 * addresses and widths before this helper can be used for an actual game.
 * It halts BEFORE the original direct CALL. This does not implement the
 * callee, Windows services, graphics, game engine or a PE loader.
 */
#include <stdint.h>
#include "mx_cfg_vm.h"

enum {
    MX_MAIN_PREFIX_CALL_BOUNDARY=1,
    MX_MAIN_PREFIX_INVALID=-1
};
typedef struct {
    uint64_t rip,rsp,rax,rcx,rdx,r8,r9;
    uint32_t zf;
    uint32_t instructions;
} mx_main_prefix_state;
typedef struct {
    uint64_t entry, call_site, cookie_va;
    uint64_t arg0_global, arg1_global, show_global;
    uint32_t stack_alloc, cookie_stack_offset;
} mx_main_prefix_layout;

static inline int mx_main_prefix_nonoverlap(uint64_t a,uint32_t an,
                                             uint64_t b,uint32_t bn){
    if(a>UINT64_MAX-an||b>UINT64_MAX-bn)return 0;
    return a+an<=b || b+bn<=a;
}

static inline int mx_main_execute_prefix(mx_main_prefix_state *s,
        mx_cfg_memory *memory,const mx_main_prefix_layout *layout){
    if(!s || !memory || !layout || !layout->entry || !layout->call_site ||
       s->rip!=layout->entry || s->instructions!=0U ||
       !layout->cookie_va || !layout->arg0_global ||
       !layout->arg1_global || !layout->show_global ||
       !layout->stack_alloc || s->rsp<layout->stack_alloc ||
       layout->cookie_stack_offset>layout->stack_alloc ||
       layout->call_site<=layout->entry ||
       layout->call_site-layout->entry>256U)
        return MX_MAIN_PREFIX_INVALID;
    const uint64_t new_rsp=s->rsp-layout->stack_alloc;
    if(new_rsp>UINT64_MAX-layout->cookie_stack_offset)
        return MX_MAIN_PREFIX_INVALID;
    const uint64_t saved_cookie=new_rsp+layout->cookie_stack_offset;
    uint64_t cookie=0U,old64=0U;
    uint32_t old32=0U;
    if(!mx_main_prefix_nonoverlap(saved_cookie,8U,layout->arg0_global,8U) ||
       !mx_main_prefix_nonoverlap(saved_cookie,8U,layout->arg1_global,8U) ||
       !mx_main_prefix_nonoverlap(saved_cookie,8U,layout->show_global,4U) ||
       !mx_main_prefix_nonoverlap(layout->arg0_global,8U,layout->arg1_global,8U) ||
       !mx_main_prefix_nonoverlap(layout->arg0_global,8U,layout->show_global,4U) ||
       !mx_main_prefix_nonoverlap(layout->arg1_global,8U,layout->show_global,4U))
        return MX_MAIN_PREFIX_INVALID;

    /* Preflight all guest destinations before any store. */
    if(!mx_cfg_transfer(memory,layout->cookie_va,&cookie,8U,0) ||
       !mx_cfg_transfer(memory,saved_cookie,&old64,8U,0) ||
       !mx_cfg_transfer(memory,layout->arg0_global,&old64,8U,0) ||
       !mx_cfg_transfer(memory,layout->arg1_global,&old64,8U,0) ||
       !mx_cfg_transfer(memory,layout->show_global,&old32,4U,0))
        return MX_MAIN_PREFIX_INVALID;
    uint64_t mixed=cookie^new_rsp;
    uint32_t show=(uint32_t)s->r9;
    uint64_t orig_rcx=s->rcx,orig_rdx=s->rdx;
    if(!mx_cfg_transfer(memory,saved_cookie,&mixed,8U,1) ||
       !mx_cfg_transfer(memory,layout->arg0_global,&orig_rcx,8U,1) ||
       !mx_cfg_transfer(memory,layout->arg1_global,&orig_rdx,8U,1) ||
       !mx_cfg_transfer(memory,layout->show_global,&show,4U,1))
        return MX_MAIN_PREFIX_INVALID;
    s->rsp=new_rsp;
    s->rax=mixed;
    s->rcx=s->r8;
    s->zf=(mixed==0U);
    s->rip=layout->call_site;
    s->instructions=8U;
    return MX_MAIN_PREFIX_CALL_BOUNDARY;
}
#endif
