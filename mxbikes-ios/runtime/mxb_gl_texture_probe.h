#ifndef MXB_GL_TEXTURE_PROBE_H
#define MXB_GL_TEXTURE_PROBE_H
#include "mxb_gl_texture.h"
#ifdef __cplusplus
extern "C"{
#endif
/* ONLY for deterministic simulator texture pixel verification. */
int mxb_gl_texture_fixture(MXBGLTextures *bank);
#ifdef __cplusplus
}
#endif
#endif
