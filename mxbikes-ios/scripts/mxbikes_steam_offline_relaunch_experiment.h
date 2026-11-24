#ifndef MXB_STEAM_OFFLINE_RELAUNCH_EXPERIMENT_H
#define MXB_STEAM_OFFLINE_RELAUNCH_EXPERIMENT_H
/*
 * Opt-in, synthetic guest-ABI experiment for ONE Steamworks launcher call.
 *
 * SteamAPI_RestartAppIfNecessary asks whether to relaunch via desktop Steam.
 * A false return means only "do not relaunch"; it is NOT an ownership check,
 * SteamAPI_Init, user identity, interface pointer, or platform entitlement.
 *
 * This is intentionally NOT connected to normal game execution. It neither
 * changes any executable bytes nor supplies authorization. All other Steam
 * imports remain unsupported and must be handled separately.
 */
#include <stdint.h>
#include "mxbikes_steam_platform_boundary.h"

#ifndef MXB_EXPERIMENTAL_OFFLINE_RELAUNCH
#define MXB_EXPERIMENTAL_OFFLINE_RELAUNCH 0
#endif

enum mxb_offline_relaunch_result {
    MXB_OFFLINE_RELAUNCH_INVALID = -1,
    MXB_OFFLINE_RELAUNCH_DISABLED = 0,
    MXB_OFFLINE_RELAUNCH_TEST_RETURN = 1
};

/*
 * Model the Win64 CALL/RET net effect on the first Steamworks import:
 * a C bool false in RAX and the original return PC, with RSP unchanged.
 * The pre-CALL stack slot must be mapped and aligned (call contract).
 *
 * No original post-call instruction is executed here. SteamAPI_Init still
 * cannot succeed without an actual client/interface/entitlement strategy.
 */
static inline enum mxb_offline_relaunch_result
mxb_steam_offline_relaunch_experiment(mx_crt_cluster_state *guest,
                                      mx_cfg_memory *memory)
{
#if MXB_EXPERIMENTAL_OFFLINE_RELAUNCH
    mxb_steam_call_contract contract = {0};
    if (mxb_steam_capture_call_contract(guest, memory, MXB_HOST_IOS,
                                        &contract) != MXB_STEAM_UNSUPPORTED_IOS)
        return MXB_OFFLINE_RELAUNCH_INVALID;
    if (guest->imports == UINT32_MAX)
        return MXB_OFFLINE_RELAUNCH_INVALID;

    guest->rax = UINT64_C(0);
    guest->rip = contract.original_return_pc;
    guest->imports += 1U;
    return MXB_OFFLINE_RELAUNCH_TEST_RETURN;
#else
    (void)guest;
    (void)memory;
    return MXB_OFFLINE_RELAUNCH_DISABLED;
#endif
}
#endif
