#ifndef MXB_STEAM_PLATFORM_BOUNDARY_H
#define MXB_STEAM_PLATFORM_BOUNDARY_H
#include <stdint.h>
#include "mx_crt_cluster_guest.h"
/* A fail-closed Steamworks platform boundary, NOT an implementation of
 * SteamAPI_RestartAppIfNecessary. Original Win64 PC / app-ID only.
 *
 * Valve supports desktop Windows/macOS/Linux Steam contexts; the original
 * SteamAPI Windows DLL cannot be invoked or authenticated on iOS.
 * Only a real publisher-approved/native service may ever implement the
 * separate Steamworks application lifecycle in a future build.
 */
#define MXB_ORIGINAL_STEAM_PC UINT64_C(0x1401306ed)
#define MXB_ORIGINAL_STEAM_APP_ID UINT64_C(0xa008c)

enum mxb_host_platform {MXB_HOST_IOS=1,MXB_HOST_DESKTOP=2};
enum mxb_steam_status {
 MXB_STEAM_INVALID_GUEST_STATE=0,
 MXB_STEAM_UNSUPPORTED_IOS=1,
 MXB_STEAM_DESKTOP_CLIENT_NOT_CONNECTED=2
};

/* Strict nonmutating capability query. Nothing grants a success result,
 * clears the original check, patches RAX, or advances RIP. */
static inline enum mxb_steam_status mxb_steam_platform_boundary(
 const mx_crt_cluster_state *guest,enum mxb_host_platform platform)
{
 if(!guest||guest->fault||
    guest->rip!=MXB_ORIGINAL_STEAM_PC||
    guest->rcx!=MXB_ORIGINAL_STEAM_APP_ID)
    return MXB_STEAM_INVALID_GUEST_STATE;
 if(platform==MXB_HOST_IOS)return MXB_STEAM_UNSUPPORTED_IOS;
 if(platform==MXB_HOST_DESKTOP)
    return MXB_STEAM_DESKTOP_CLIENT_NOT_CONNECTED;
 return MXB_STEAM_INVALID_GUEST_STATE;
}

/* Verified import *callsite*, not a Steam invocation or a licensing result.
 * The original six-byte CALL [RIP+0x1f1325] at 0x1401306ED targets
 * IAT slot 0x140321A18; on invocation Win64 would push 0x1401306F3.
 * A future authorized desktop host must separately resolve and implement
 * the imported API. iOS intentionally remains unsupported.
 */
#define MXB_ORIGINAL_STEAM_RETURN_PC UINT64_C(0x1401306f3)
#define MXB_ORIGINAL_STEAM_IAT_SLOT UINT64_C(0x140321a18)
typedef struct {
 uint64_t guest_call_pc;
 uint64_t import_iat_slot;
 uint64_t original_return_pc;
 uint64_t guest_app_id;
 uint64_t caller_rsp;
 uint64_t callee_rsp_if_invoked;
 uint64_t prior_callee_stack_bytes;
} mxb_steam_call_contract;

/* Inspect the *live* guest without pushing a fake return, altering RAX,
 * modifying Win64 memory or making any Steam/client authentication claim.
 * The callee stack address must be mapped and the caller must satisfy
 * the Win64 pre-CALL 16-byte stack alignment requirement.
 *
 * Status is BLOCKED for both currently supported inspection platforms.
 * A future adapter may only dispatch after it independently establishes
 * access to the actual authorized platform runtime; this code cannot
 * turn a status into a successful imported call.
 */
static inline enum mxb_steam_status mxb_steam_capture_call_contract(
 const mx_crt_cluster_state *guest,mx_cfg_memory *memory,
 enum mxb_host_platform platform,mxb_steam_call_contract *output)
{
 if(!output)return MXB_STEAM_INVALID_GUEST_STATE;
 *output=(mxb_steam_call_contract){0};
 const enum mxb_steam_status status=
     mxb_steam_platform_boundary(guest,platform);
 if(status==MXB_STEAM_INVALID_GUEST_STATE||!memory||
    guest->rsp<8U||(guest->rsp&UINT64_C(15))!=0U)
     return MXB_STEAM_INVALID_GUEST_STATE;
 const uint64_t callee_rsp=guest->rsp-8U;
 uint64_t old_bytes=0U;
 if(!mx_cfg_transfer(memory,callee_rsp,&old_bytes,8U,0))
     return MXB_STEAM_INVALID_GUEST_STATE;
 *output=(mxb_steam_call_contract){
    MXB_ORIGINAL_STEAM_PC,MXB_ORIGINAL_STEAM_IAT_SLOT,
    MXB_ORIGINAL_STEAM_RETURN_PC,guest->rcx,guest->rsp,
    callee_rsp,old_bytes
 };
 return status;
}
#endif
