#ifndef MX_GAME_CRT_STRRCHR_H
#define MX_GAME_CRT_STRRCHR_H
/*
 * Bounded Win64 MSVCR90!strrchr guest-pointer compatibility service.
 *
 * This is NOT Microsoft's DLL or a production CRT. It implements only the
 * 8-bit char search and Win64 RCX source / EDX search argument contract,
 * using mapped guest memory. The entire string must contain a NUL within
 * the explicit byte limit. No host pointers are exposed; an absent match
 * returns guest RAX=0. Searching for NUL returns the terminator address.
 *
 * Original PE IAT identity/call target MUST be verified privately before
 * dispatch. A mapping/search failure preserves guest register state.
 */
#include <stdint.h>
#include "mx_crt_cluster_guest.h"

enum {
    MX_GAME_STRRCHR_OK=1,
    MX_GAME_STRRCHR_UNSUPPORTED=0,
    MX_GAME_STRRCHR_MEMORY=-161,
    MX_GAME_STRRCHR_BAD_STATE=-162
};

static inline int mx_game_crt_bounded_strrchr(
        mx_crt_cluster_state *s, mx_cfg_memory *m, uint32_t limit) {
    if (!s || !m || s->fault || !s->rcx ||
        !limit || limit>4096U || s->rcx>UINT64_MAX-limit)
        return MX_GAME_STRRCHR_UNSUPPORTED;
    /* Win64 int character search: cast low 32 bits of RDX to unsigned char. */
    const uint8_t needle=(uint8_t)(uint32_t)s->rdx;
    uint64_t match=0U;
    int seen_end=0;
    for(uint32_t index=0U;index<limit;index++) {
        uint8_t byte=0;
        if(!mx_cfg_transfer(m,s->rcx+index,&byte,1U,0))
            return MX_GAME_STRRCHR_MEMORY;
        if(byte==needle)match=s->rcx+index;
        if(!byte){seen_end=1;break;}
    }
    if(!seen_end)return MX_GAME_STRRCHR_UNSUPPORTED;
    s->rax=match;
    return MX_GAME_STRRCHR_OK;
}

/* Validate the original x64 CALL -> PE IAT-thunk JMP -> CRT RET shape before
 * use. This only models that known three-instruction imported call boundary.
 * The service body is a bounded approximation. The Win64 return slot remains
 * observable at caller RSP minus eight after the modeled RET.
 */
static inline int mx_game_crt_strrchr_import_call(
        mx_crt_cluster_state *s, mx_cfg_memory *m,
        uint64_t callsite, uint64_t thunk, uint64_t continuation,
        uint32_t maximum_bytes) {
    if (!s || !m || s->fault || !callsite || !thunk || !continuation ||
        s->rip!=callsite || s->rsp<8U || (s->rsp&15U)!=0U)
        return MX_GAME_STRRCHR_BAD_STATE;
    uint64_t old_return=0U;
    const uint64_t guest_rsp=s->rsp-8U;
    if(!mx_cfg_transfer(m,guest_rsp,&old_return,8U,0))
        return MX_GAME_STRRCHR_MEMORY;
    /* Preflight the service before overwriting the guest return slot. */
    mx_crt_cluster_state probe=*s;
    const int status=mx_game_crt_bounded_strrchr(&probe,m,maximum_bytes);
    if(status!=MX_GAME_STRRCHR_OK)return status;
    if(!mx_cfg_transfer(m,guest_rsp,&continuation,8U,1))
        return MX_GAME_STRRCHR_MEMORY;
    s->rax=probe.rax;
    s->rip=continuation;
    s->instructions+=3U;
    s->imports++;
    return MX_GAME_STRRCHR_OK;
}
#endif
