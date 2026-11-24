#ifndef MXB_POSTSTEAM_TIMER_NATIVE_H
#define MXB_POSTSTEAM_TIMER_NATIVE_H
/*
 * Three original MX Bikes post-Steam x64 caller instructions, expressed as
 * portable C operations on guest CPU / game-global state for native ARM64.
 *
 * Original pinned-game addresses (RVA, not host pointers):
 *   0x133F66 MOV EDX, 1
 *   0x133F6B MOV ECX, 0xD3B8
 *   0x133F70 MOV DWORD PTR [RIP+0xD172CA], EAX
 *   0x133F76 next original instruction: CALL 0x2A9AE0
 * The 32-bit MOVs zero-extend EDX and ECX; no flags are changed.
 * The write destination is original guest image RVA 0xE4B240.
 *
 * This routine does not execute the next call, implement Steamworks,
 * translate the whole engine, or perform any iOS graphics operations.
 * Original executable bytes remain private and are NOT embedded here.
 */
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define MXB_POSTSTEAM_TIMER_IMAGE_BASE UINT64_C(0x140000000)
#define MXB_POSTSTEAM_TIMER_BEGIN_RVA UINT32_C(0x133F66)
#define MXB_POSTSTEAM_TIMER_NEXT_RVA UINT32_C(0x133F76)
#define MXB_POSTSTEAM_TIMER_GLOBAL_RVA UINT32_C(0xE4B240)
#define MXB_POSTSTEAM_TIMER_BEGIN_PC   (MXB_POSTSTEAM_TIMER_IMAGE_BASE + MXB_POSTSTEAM_TIMER_BEGIN_RVA)
#define MXB_POSTSTEAM_TIMER_NEXT_PC   (MXB_POSTSTEAM_TIMER_IMAGE_BASE + MXB_POSTSTEAM_TIMER_NEXT_RVA)

typedef struct {
    uint64_t rip;
    uint64_t rax;
    uint64_t rcx;
    uint64_t rdx;
    uint64_t rflags;
    uint32_t global_time_ms;
    uint32_t reserved;
} mxb_poststeam_timer_guest;

/* A deterministic, original-game code translation with bounded side effects.
 * One global DWORD is represented by this explicit guest-state field rather
 * than dereferencing an unsafe Windows image address in iOS memory.
 * Returns 0 and leaves *guest untouched on invalid input / unexpected PC.
 */
int mxb_poststeam_timer_apply(mxb_poststeam_timer_guest *guest);

#ifdef __cplusplus
}
#endif
#endif
