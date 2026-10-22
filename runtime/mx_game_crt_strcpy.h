#ifndef MX_GAME_CRT_STRCPY_H
#define MX_GAME_CRT_STRCPY_H
/*
 * Bounded, explicitly identified MSVCR90.dll!strcpy native guest service.
 * Used after original game-internal helper CALL -> PE import JMP thunk.
 *
 * Only copies a fully mapped, non-overlapping, NUL-terminated source and
 * preserves the x64 strcpy return contract RAX = destination pointer.
 * Imported thunk identity MUST be checked by original private PE validator.
 * This is not a full MSVCR90 runtime or a native filesystem lookup.
 */
#include <stdint.h>
#include "mx_crt_cluster_guest.h"

enum {
   MX_GAME_STRCPY_OK=1,
   MX_GAME_STRCPY_UNSUPPORTED=0,
   MX_GAME_STRCPY_MEMORY=-101,
   MX_GAME_STRCPY_BAD_STATE=-102
};
static inline int mx_game_crt_bounded_strcpy(
        mx_crt_cluster_state*s,mx_cfg_memory*m,uint32_t limit){
    if(!s||!m||s->fault||!s->rcx||!s->rdx||
       limit==0U||limit>4096U ||
       s->rcx>UINT64_MAX-limit||s->rdx>UINT64_MAX-limit)
        return MX_GAME_STRCPY_UNSUPPORTED;
    uint32_t copied=0U;
    uint8_t byte=0U;
    int terminator_found=0;
    /* Locate NUL without reading past the agreed guest buffer size. */
    for(copied=0U;copied<limit;copied++){
       if(!mx_cfg_transfer(m,s->rdx+copied,&byte,1U,0))
          return MX_GAME_STRCPY_MEMORY;
       if(byte==0U){terminator_found=1;break;}
    }
    if(!terminator_found)return MX_GAME_STRCPY_UNSUPPORTED;
    const uint32_t bytes=copied+1U;
    if(s->rcx<s->rdx+bytes && s->rdx<s->rcx+bytes)
        return MX_GAME_STRCPY_UNSUPPORTED; /* strcpy undefined for overlap */
    /* Verify all writes possible before touching guest destination. */
    for(uint32_t i=0;i<bytes;i++){
        if(!mx_cfg_transfer(m,s->rcx+i,&byte,1U,0))
           return MX_GAME_STRCPY_MEMORY;
    }
    for(uint32_t i=0;i<bytes;i++){
        if(!mx_cfg_transfer(m,s->rdx+i,&byte,1U,0)||
           !mx_cfg_transfer(m,s->rcx+i,&byte,1U,1))
           return MX_GAME_STRCPY_MEMORY;
    }
    s->rax=s->rcx;
    s->imports++;
    return MX_GAME_STRCPY_OK;
}

/* Model the original direct CALL to the PE JMP thunk and the external
 * imported CRT function's RET. The caller's shadow space must be available.
 * This does not claim to execute the actual MSVCR90 dynamic library. */
static inline int mx_game_crt_strcpy_import_call(
        mx_crt_cluster_state*s,mx_cfg_memory*m,
        uint64_t callsite_va,uint64_t thunk_va,
        uint64_t continuation_va,uint32_t limit){
    if(!s||!m||s->fault||!thunk_va||!continuation_va||
       s->rip!=callsite_va||s->rsp<8U||
       (s->rsp&15U)!=0U)return MX_GAME_STRCPY_BAD_STATE;
    uint64_t prior=0U;
    const uint64_t guest_rsp=s->rsp-8U;
    if(!mx_cfg_transfer(m,guest_rsp,&prior,8U,0))
       return MX_GAME_STRCPY_MEMORY;
    if(!mx_cfg_transfer(m,guest_rsp,&continuation_va,8U,1))
       return MX_GAME_STRCPY_MEMORY;
    s->rsp=guest_rsp;s->rip=thunk_va;
    int status=mx_game_crt_bounded_strcpy(s,m,limit);
    if(status!=MX_GAME_STRCPY_OK)return status;
    uint64_t ret=0U;
    if(!mx_cfg_transfer(m,s->rsp,&ret,8U,0)||
       ret!=continuation_va)return MX_GAME_STRCPY_BAD_STATE;
    s->rsp+=8U;s->rip=continuation_va;
    s->instructions+=3U; /* original CALL, PE JMP thunk, CRT RET */
    return MX_GAME_STRCPY_OK;
}
#endif
