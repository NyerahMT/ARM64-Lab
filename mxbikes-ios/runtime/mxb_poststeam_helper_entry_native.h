#ifndef MXB_POSTSTEAM_HELPER_ENTRY_NATIVE_H
#define MXB_POSTSTEAM_HELPER_ENTRY_NATIVE_H
/*
 * Contiguous original-game x64 caller + callee-entry translation, for ARM64.
 * The entrypoint joins original RVAs 133F66..133F7A (E8 CALL) and
 * 2A9AE0..2A9B07 (helper prologue). It stops BEFORE the original nested
 * CALL at 2A9B08. No host pointer represents the original guest stack.
 *
 * The guest security cookie is supplied as synthetic input in tests; this
 * routine does not read original private executable data on iOS.
 */
#include <stdint.h>
#include "mxb_poststeam_timer_native.h"

#ifdef __cplusplus
extern "C" {
#endif

#define MXB_POSTSTEAM_HELPER_BEGIN_RVA UINT32_C(0x2A9AE0)
#define MXB_POSTSTEAM_HELPER_NEXT_RVA UINT32_C(0x2A9B08)
#define MXB_POSTSTEAM_HELPER_SECURITY_COOKIE_RVA UINT32_C(0x3928A0)
#define MXB_POSTSTEAM_HELPER_BEGIN_PC \
 (MXB_POSTSTEAM_TIMER_IMAGE_BASE+MXB_POSTSTEAM_HELPER_BEGIN_RVA)
#define MXB_POSTSTEAM_HELPER_NEXT_PC \
 (MXB_POSTSTEAM_TIMER_IMAGE_BASE+MXB_POSTSTEAM_HELPER_NEXT_RVA)
#define MXB_POSTSTEAM_AFTER_CALL_PC \
 (MXB_POSTSTEAM_TIMER_IMAGE_BASE+UINT64_C(0x133F7B))
#define MXB_POSTSTEAM_JOINED_STACK_BYTES 1024U

typedef struct {
    mxb_poststeam_timer_guest timer;
    uint64_t rsp;
    uint64_t rbx;
    uint64_t rsi;
    uint64_t rdi;
    uint64_t security_cookie;
    uint64_t stack_base;
    uint8_t stack[MXB_POSTSTEAM_JOINED_STACK_BYTES];
} mxb_poststeam_joined_guest;

/* 13 original x64 instructions: 3 timer + 1 direct call + 9 helper entry.
 * Does not model guest CALL shadow-space reads beyond the bounded stack.
 * On invalid input, returns zero and leaves every guest byte unchanged.
 */
int mxb_poststeam_join_to_helper_entry(mxb_poststeam_joined_guest *guest);

/* C-owned synthetic guest-state iOS UI smoke, NOT actual MX Bikes startup. */
int mxb_poststeam_joined_synthetic_smoke(void);

#ifdef __cplusplus
}
#endif
#endif
