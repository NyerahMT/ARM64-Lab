#ifndef MXB_GL_TEXTURE_H
#define MXB_GL_TEXTURE_H
#include <stdint.h>
#include <stddef.h>
#include "mxb_gl_win64_abi.h"
#ifdef __cplusplus
extern "C" {
#endif
#define MXB_GL_TEXTURE_2D 0x0de1u
#define MXB_GL_RGB 0x1907u
#define MXB_GL_RGBA 0x1908u
#define MXB_GL_UNPACK_ALIGNMENT 0x0cf5u
#define MXB_GL_TEXTURE_MIN_FILTER 0x2801u
#define MXB_GL_TEXTURE_MAG_FILTER 0x2800u
#define MXB_GL_NEAREST 0x2600u
#define MXB_GL_LINEAR 0x2601u
#define MXB_GL_MAX_TEXTURES 8u
#define MXB_GL_MAX_TEX_DIM 256u
typedef int (*MXBGLGuestWrite)(void *context,uint64_t guest_address,
                                const void *input,size_t length);
typedef struct MXBGLTextures MXBGLTextures;
MXBGLTextures *mxb_tex_create(void);
void mxb_tex_destroy(MXBGLTextures *textures);
void mxb_tex_reset(MXBGLTextures *textures);
int mxb_tex_enabled(const MXBGLTextures *textures);
/* Returns a fully copied RGBA8 owned upload only after successful guest read.
 * Pixel storage persists until next bind/upload/delete/reset. */
const uint8_t *mxb_tex_current_rgba(const MXBGLTextures *textures,
                                    unsigned *width,unsigned *height);
enum MXBGLGuestStatus mxb_tex_dispatch_win64(
 MXBGLTextures *textures,const char *library,const char *symbol,
 const MXBGLWin64Call *registers,
 MXBGLGuestRead read_guest,MXBGLGuestWrite write_guest,void *guest_context);
#ifdef __cplusplus
}
#endif
#endif
