#ifndef MXB_OBSERVED_GRAPHICS_H
#define MXB_OBSERVED_GRAPHICS_H
#include "mxb_observed_session.h"
#include "mxb_gl_win64_abi.h"
#ifdef __cplusplus
extern "C" {
#endif
/* Caller owns the surface, checked memory, and adapter state. Attach only
 * after a real platform context is established. This adapter implements
 * the existing fixed-function subset, not WGL or a complete renderer. */
typedef struct {
    MXBGLSurface *surface;
    mxb_observed_memory *memory;
    uint64_t completed_calls;
    enum MXBGLGuestStatus last_status;
} mxb_observed_graphics;
int mxb_observed_graphics_attach(mxb_observed_session *,mxb_observed_graphics *,MXBGLSurface *);
#ifdef __cplusplus
}
#endif
#endif
