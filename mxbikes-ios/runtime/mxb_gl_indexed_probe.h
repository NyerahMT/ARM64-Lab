#ifndef MXB_GL_INDEXED_PROBE_H
#define MXB_GL_INDEXED_PROBE_H
#include "mxb_gl_surface.h"
#ifdef __cplusplus
extern "C" {
#endif
/* TEST-ONLY: renders geometry from constructed Win64 guest memory.
 * Never use as a substitute for verified ORIGINAL MX Bikes graphics. */
int mxb_gl_indexed_fixture(MXBGLSurface *surface);
#ifdef __cplusplus
}
#endif
#endif
