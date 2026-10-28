#ifndef MXB_GL_WIN64_ABI_H
#define MXB_GL_WIN64_ABI_H
#include <stdint.h>
#include <stddef.h>
#include "mxb_gl_surface.h"
#ifdef __cplusplus
extern "C" {
#endif

/* Input is the GUEST state at a Win64 imported function's ENTRY (after CALL).
 * Float/double arguments 1-4 are passed in XMM0..XMM3, not integer RCX..R9.
 * Floating args 5+ occupy stack [RSP+0x28], [RSP+0x30], etc.
 * XMM low 64 bits preserve the float32 low lane or full float64 value.
 * This adapter does not emulate RET, license checks, or import resolution.
 */
typedef struct MXBGLWin64Call {
 uint64_t rcx;                 /* int/enum or guest pointer argument 1 */
 uint64_t rsp;                 /* guest stack at the import entry */
 uint64_t xmm_low64[4];       /* bits, NEVER interpreted as host pointers */
 uint64_t rdx,r8,r9;          /* Win64 integer/pointer arguments 2–4 */
} MXBGLWin64Call;

/* Guest-mapped address reading callback. Must return nonzero on exact read.
 * Never dereference Win64 pointers directly as host pointers. */
typedef int (*MXBGLGuestRead)(void *context,uint64_t guest_address,
                               void *output,size_t length);

enum MXBGLGuestStatus {
 MXB_GL_GUEST_OK=0,
 MXB_GL_GUEST_UNSUPPORTED=1,
 MXB_GL_GUEST_INVALID_STATE=2,
 MXB_GL_GUEST_UNMAPPED_POINTER=3,
 MXB_GL_GUEST_RENDER_REJECTED=4
};

enum MXBGLGuestStatus mxb_gl_dispatch_win64(
 MXBGLSurface *surface,
 const char *original_library,const char *original_import_symbol,
 const MXBGLWin64Call *guest_at_import_entry,
 MXBGLGuestRead read_guest,void *guest_context);

#ifdef __cplusplus
}
#endif
#endif
