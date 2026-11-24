#ifndef MXB_STEAM_ORIGINAL_BRANCH_NATIVE_H
#define MXB_STEAM_ORIGINAL_BRANCH_NATIVE_H
/* SHA-pinned MX Bikes original x64 branch/indirect-call semantics translated
 * into freestanding C suitable for AArch64 execution.
 *
 * Verified original x64 instructions:
 *  1306F3 TEST AL,AL; 1306F5 JNE 130606
 *  130701 TEST AL,AL; 130703 JE 130606
 *  130716 MOV EDX,000A008C; 13071B MOV RCX,[RAX+30];
 *  13071F MOV RAX,[RCX]; 130722 CALL QWORD PTR [RAX+30]
 *  130725 XOR ECX,ECX; 130727 TEST AL,AL; 130729 SETE CL;
 *  13072C MOV EAX,ECX; continuation 13072E
 *
 * This translates caller code only. External Steam API call, supplied
 * ownership result and interface method remain unimplemented. No
 * authentication, entitlement, game patching, or engine execution is implied.
 */
#include <stdint.h>
#include "mx_crt_cluster_guest.h"

#define MXB_STEAM_POST_RESTART UINT64_C(0x1401306f3)
#define MXB_STEAM_INIT_CALL UINT64_C(0x1401306fb)
#define MXB_STEAM_POST_INIT UINT64_C(0x140130701)
#define MXB_STEAM_CONTEXT_PREP UINT64_C(0x140130709)
#define MXB_STEAM_CONTEXT_RETURN UINT64_C(0x140130716)
#define MXB_STEAM_VIRTUAL_CALL UINT64_C(0x140130722)
#define MXB_STEAM_VIRTUAL_RETURN UINT64_C(0x140130725)
#define MXB_STEAM_RESULT_CONTINUATION UINT64_C(0x14013072e)
#define MXB_STEAM_FAILURE_BRANCH UINT64_C(0x140130606)
#define MXB_STEAM_APP_ID UINT64_C(0xa008c)

typedef struct {
 uint64_t interface_object;
 uint64_t interface_vtable;
 uint64_t method_address;
 uint64_t return_pc;
 uint64_t app_id;
} mxb_original_apps_call;

/* Pure x64 TEST AL/branch translation after an externally completed CALL.
 * The return is an input; this function does not invent one.
 */
static inline int mxb_original_steam_branch_after_return(mx_crt_cluster_state *s)
{
 if(!s||s->fault||
    (s->rip!=MXB_STEAM_POST_RESTART&&s->rip!=MXB_STEAM_POST_INIT))
    return 0;
 const uint64_t from=s->rip;
 const uint8_t al=(uint8_t)s->rax;
 s->zf=(uint8_t)(al==0U);
 s->sf=(uint8_t)((al&0x80U)!=0U);
 s->cf=0U;
 if(from==MXB_STEAM_POST_RESTART)
    s->rip=s->zf?MXB_STEAM_INIT_CALL:MXB_STEAM_FAILURE_BRANCH;
 else
    s->rip=s->zf?MXB_STEAM_FAILURE_BRANCH:MXB_STEAM_CONTEXT_PREP;
 return 1;
}

/* Translate real caller instructions up to *but not through* the virtual
 * call. No guest executable method code is invoked. Resolve only mapped
 * guest-memory pointers, not host memory. The method is a candidate target.
 */
static inline int mxb_original_steam_apps_method_preflight(
 mx_crt_cluster_state *s,mx_cfg_memory *memory,mxb_original_apps_call *result)
{
 if(!s||!memory||!result||s->fault||
    s->rip!=MXB_STEAM_CONTEXT_RETURN||
    (s->rsp&UINT64_C(15))!=0U||
    s->rax>UINT64_MAX-UINT64_C(0x30))
    return 0;
 *result=(mxb_original_apps_call){0};
 const uint64_t obj=mx_crt_cluster_read(s,memory,s->rax+0x30U,8U);
 if(s->fault||!obj)return 0;
 const uint64_t table=mx_crt_cluster_read(s,memory,obj,8U);
 if(s->fault||!table||table>UINT64_MAX-UINT64_C(0x30))
    return 0;
 const uint64_t method=mx_crt_cluster_read(s,memory,table+0x30U,8U);
 if(s->fault||!method)return 0;
 s->rdx=MXB_STEAM_APP_ID;
 s->rcx=obj;
 s->rax=table;
 s->rip=MXB_STEAM_VIRTUAL_CALL;
 *result=(mxb_original_apps_call){
     obj,table,method,MXB_STEAM_VIRTUAL_RETURN,MXB_STEAM_APP_ID
 };
 return 1;
}

/* Translate exact original Boolean-to-error conversion after a *separately
 * supplied* virtual-method return. 1 from the method => game status 0,
 * 0 from the method => game status 1. DOES NOT invoke/validate Steam.
 */
static inline int mxb_original_steam_apps_result(mx_crt_cluster_state *s)
{
 if(!s||s->fault||s->rip!=MXB_STEAM_VIRTUAL_RETURN)return 0;
 const uint8_t al=(uint8_t)s->rax;
 s->rcx=0U;                     /* XOR ECX,ECX */
 s->zf=(uint8_t)(al==0U);      /* TEST AL,AL */
 s->sf=(uint8_t)((al&0x80U)!=0U);
 s->cf=0U;
 s->rcx=(uint64_t)s->zf;        /* SETE CL */
 s->rax=(uint32_t)s->rcx;       /* MOV EAX,ECX */
 s->rip=MXB_STEAM_RESULT_CONTINUATION;
 return 1;
}
#endif
