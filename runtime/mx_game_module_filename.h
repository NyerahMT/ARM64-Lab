#ifndef MX_GAME_MODULE_FILENAME_H
#define MX_GAME_MODULE_FILENAME_H
/*
 * Bounded Win64 KERNEL32!GetModuleFileNameA compatibility boundary.
 *
 * The host MUST supply an explicit (possibly virtual) ANSI executable path.
 * Never invent an executable location or claim a real Windows module query.
 * Supported only for hModule==NULL, valid success-size buffer, and an
 * existing mapped guest output. Windows truncation/GetLastError and non-NULL
 * handles are deliberately NOT simulated.
 */
#include <stdint.h>
#include "mx_crt_cluster_guest.h"

enum {
    MX_GAME_FILENAME_OK=1,
    MX_GAME_FILENAME_UNSUPPORTED=0,
    MX_GAME_FILENAME_INVALID=-81,
    MX_GAME_FILENAME_UNMAPPED=-82
};
typedef struct {
    const uint8_t *exe_path;
    uint32_t path_length; /* no terminating NUL, must be exact */
} mx_game_module_context;

/* Carry genuine original post-callee three instructions to the indirect
 * KERNEL32 import CALL at RVAs 0x136746 .. 0x136756. */
static inline int mx_game_main_filename_prepare(
    mx_crt_cluster_state*s, uint64_t expected_va,
    uint64_t import_call_va){
    if(!s || s->fault || s->rip!=expected_va ||
       !import_call_va || s->rsp>UINT64_MAX-0x140U)
        return MX_GAME_FILENAME_INVALID;
    s->rdx=s->rsp+0x140U; /* LEA RDX,[RSP+0x140] */
    s->r8=0x104U;        /* MOV R8D,0x104 */
    s->rcx=0U;          /* XOR ECX,ECX */
    s->zf=1U;s->sf=0U;s->cf=0U;
    s->rip=import_call_va;
    s->instructions+=3U;
    return MX_GAME_FILENAME_OK;
}

static inline int mx_game_get_module_filename_a(
    mx_crt_cluster_state*s,mx_cfg_memory*m,
    const mx_game_module_context*ctx){
    if(!s || !m || !ctx || s->fault ||
       !ctx->exe_path || !ctx->path_length ||
       ctx->path_length>=0x104U ||
       s->rcx!=0U || !s->rdx || s->rdx>UINT64_MAX-0x104U ||
       s->r8!=0x104U)
        return MX_GAME_FILENAME_UNSUPPORTED;
    /* ANSI path is exact and NUL-free. No escape to native filesystem. */
    for(uint32_t i=0;i<ctx->path_length;i++){
        uint8_t byte=ctx->exe_path[i];
        if(byte==0U || byte>=0x80U)return MX_GAME_FILENAME_UNSUPPORTED;
    }
    uint8_t previous=0U;
    for(uint32_t i=0;i<=ctx->path_length;i++){
        if(!mx_cfg_transfer(m,s->rdx+i,&previous,1U,0))
            return MX_GAME_FILENAME_UNMAPPED;
    }
    for(uint32_t i=0;i<ctx->path_length;i++){
        uint8_t value=ctx->exe_path[i];
        if(!mx_cfg_transfer(m,s->rdx+i,&value,1U,1))
            return MX_GAME_FILENAME_UNMAPPED;
    }
    uint8_t terminator=0U;
    if(!mx_cfg_transfer(m,s->rdx+ctx->path_length,
                        &terminator,1U,1))
        return MX_GAME_FILENAME_UNMAPPED;
    s->rax=ctx->path_length;
    s->imports+=1U;
    return MX_GAME_FILENAME_OK;
}

/* Strict known original CALL [IAT] at RVA 0x136756. Builds the genuine
 * Win64 guest return slot, calls the modeled API, pops the slot like RET,
 * and resumes the original 0x13675C continuation. */
static inline int mx_game_main_filename_import_call(
    mx_crt_cluster_state*s,mx_cfg_memory*m,
    const mx_game_module_context*ctx,
    uint64_t import_call_va,uint64_t continuation_va){
    if(!s||!m||!ctx||s->fault||s->rip!=import_call_va||
       !continuation_va || s->rsp<8U || (s->rsp&15U)!=0U)
        return MX_GAME_FILENAME_INVALID;
    const uint64_t caller_rsp=s->rsp,callee_rsp=caller_rsp-8U;
    uint64_t previous=0U;
    if(!mx_cfg_transfer(m,callee_rsp,&previous,8U,0))
        return MX_GAME_FILENAME_UNMAPPED;
    /* Validate the API's guest output BEFORE the CALL modifies memory. */
    if(s->rcx!=0U||!s->rdx||s->rdx>UINT64_MAX-0x104U||
       s->r8!=0x104U||!ctx->exe_path||!ctx->path_length||
       ctx->path_length>=0x104U)
        return MX_GAME_FILENAME_UNSUPPORTED;
    uint8_t probe=0U;
    for(uint32_t i=0;i<=ctx->path_length;i++){
        if(!mx_cfg_transfer(m,s->rdx+i,&probe,1U,0))
            return MX_GAME_FILENAME_UNMAPPED;
    }
    if(!mx_cfg_transfer(m,callee_rsp,&continuation_va,8U,1))
        return MX_GAME_FILENAME_UNMAPPED;
    s->rsp=callee_rsp;
    int result=mx_game_get_module_filename_a(s,m,ctx);
    if(result!=MX_GAME_FILENAME_OK)return result;
    uint64_t ret=0U;
    if(!mx_cfg_transfer(m,s->rsp,&ret,8U,0)||
       ret!=continuation_va)return MX_GAME_FILENAME_INVALID;
    s->rsp=caller_rsp;s->rip=ret;s->instructions+=2U; /* CALL + RET */
    return MX_GAME_FILENAME_OK;
}
#endif
