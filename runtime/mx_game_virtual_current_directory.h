#ifndef MX_GAME_VIRTUAL_CURRENT_DIRECTORY_H
#define MX_GAME_VIRTUAL_CURRENT_DIRECTORY_H
/*
 * Bounded original game-main Win64 KERNEL32!SetCurrentDirectoryA call-site
 * adapter: 0x136769 MOV RCX,RAX; 0x13676C CALL [RIP+0x1EA95E] -> 0x136772.
 *
 * This does NOT call a native host chdir(), change the process working
 * directory, simulate a Windows filesystem, or assume guest paths exist.
 * An explicitly supplied validator must approve a guest ANSI directory.
 * The deterministic test uses a synthetic validator only. A missing validator
 * is a hard unsupported boundary, never silently returns success.
 * The known original-game IAT identity is verified on the private runner.
 */
#include <stdint.h>
#include "mx_crt_cluster_guest.h"

enum {
    MX_GAME_CWD_OK=1,
    MX_GAME_CWD_UNSUPPORTED=0,
    MX_GAME_CWD_INVALID=-221,
    MX_GAME_CWD_UNMAPPED=-222
};
typedef int (*mx_game_cwd_validate)(void *opaque, const uint8_t *path,
                                    uint32_t nbytes);
typedef struct {
    uint8_t virtual_path[260];
    uint32_t length, calls;
    mx_game_cwd_validate validate;
    void *opaque;
} mx_game_cwd_context;

static inline int mx_game_setcwd_prepare(
    mx_crt_cluster_state *s, uint64_t entry, uint64_t callsite) {
    if(!s || s->fault || s->rip!=entry || !callsite)
        return MX_GAME_CWD_INVALID;
    s->rcx=s->rax; /* original MOV RCX,RAX preserves arithmetic flags */
    s->rip=callsite;
    s->instructions++;
    return MX_GAME_CWD_OK;
}

static inline int mx_game_setcwd_import_call(
    mx_crt_cluster_state *s,mx_cfg_memory *m,mx_game_cwd_context *ctx,
    uint64_t callsite,uint64_t continuation,uint32_t capacity) {
    if(!s||!m||!ctx||s->fault||s->rip!=callsite||
       !continuation||s->rsp<8U||(s->rsp&15U)!=0U||
       capacity<4U||capacity>260U||!s->rcx||
       s->rcx>UINT64_MAX-capacity)
        return MX_GAME_CWD_INVALID;
    if(!ctx->validate)return MX_GAME_CWD_UNSUPPORTED;
    uint8_t name[260];
    uint32_t len=0;
    uint8_t ended=0;
    for(uint32_t i=0;i<capacity;i++){
        if(!mx_cfg_transfer(m,s->rcx+i,&name[i],1U,0))
            return MX_GAME_CWD_UNMAPPED;
        if(!name[i]){len=i;ended=1U;break;}
        if(name[i]<0x20U||name[i]>=0x7fU)
            return MX_GAME_CWD_UNSUPPORTED;
    }
    if(!ended||len<3U||len>=capacity)
        return MX_GAME_CWD_UNSUPPORTED;
    /* Tested subset: absolute DOS drive root or directory with a final slash.
     * No virtual share paths, Win32 drive-relative paths or filesystem
     * enumeration are implemented.
     */
    if(!((name[0]>='A'&&name[0]<='Z')||
         (name[0]>='a'&&name[0]<='z'))||
       name[1]!=':'||name[2]!='\\'||
       name[len-1U]!='\\')
        return MX_GAME_CWD_UNSUPPORTED;
    const uint64_t ret_slot=s->rsp-8U;
    uint64_t previous=0U;
    if(!mx_cfg_transfer(m,ret_slot,&previous,8U,0))
        return MX_GAME_CWD_UNMAPPED;
    /* Complete preflight before any changes to guest stack or native ctx. */
    int allowed=ctx->validate(ctx->opaque,name,len);
    if(allowed<0)return MX_GAME_CWD_UNSUPPORTED;
    if(!mx_cfg_transfer(m,ret_slot,&continuation,8U,1))
        return MX_GAME_CWD_UNMAPPED;
    if(allowed){
        for(uint32_t i=0;i<=len;i++)
            ctx->virtual_path[i]=name[i];
        ctx->length=len;
    }
    ctx->calls++;
    s->rax=allowed?1U:0U;
    s->rip=continuation;
    /* Modeled CALL IAT and Win64 external RET. Original native DLL code
     * is not executed. Guest RSP is unchanged after returning to caller. */
    s->instructions+=2U;
    s->imports++;
    return MX_GAME_CWD_OK;
}

/* Original post-SetCurrentDirectoryA main-block:
 * 0x136772 MOV ECX,DWORD PTR [RIP+0xD14678]
 * 0x136778 LEA RDX,[RIP+0xD146A1]
 * stop before 0x13677F CALL 0x133E80 (untranslated direct game callee).
 */
static inline int mx_game_main_after_cwd_prepare(
    mx_crt_cluster_state *s,mx_cfg_memory *m,
    uint64_t entry,uint64_t guest_dword,uint64_t guest_constant,
    uint64_t callsite) {
    if(!s||!m||s->fault||s->rip!=entry||
       !guest_dword||!guest_constant||!callsite)
        return MX_GAME_CWD_INVALID;
    uint32_t value=0;
    if(!mx_cfg_transfer(m,guest_dword,&value,4U,0))
        return MX_GAME_CWD_UNMAPPED;
    s->rcx=(uint64_t)value;
    s->rdx=guest_constant;
    s->rip=callsite;
    s->instructions+=2U;
    /* MOV/LEA preserve flags from the earlier original operation. */
    return MX_GAME_CWD_OK;
}
#endif
