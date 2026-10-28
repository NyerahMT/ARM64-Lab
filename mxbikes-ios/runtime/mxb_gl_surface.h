#ifndef MXB_GL_SURFACE_H
#define MXB_GL_SURFACE_H
#include <stddef.h>
#include <stdint.h>
#ifdef __cplusplus
extern "C" {
#endif
/* New bounded CPU OpenGL-1 command bridge for an eventual iOS Metal backend.
 * NEVER count its test geometry as original MX Bikes graphics execution.
 * Steamworks authentication and any game engine are outside this adapter. */
#define MXB_GL_MAX_INPUT 2048u
#define MXB_GL_MAX_OUTPUT 6144u
#define MXB_GL_TRIANGLES 0x0004u
#define MXB_GL_TRIANGLE_STRIP 0x0005u
#define MXB_GL_TRIANGLE_FAN 0x0006u
#define MXB_GL_QUADS 0x0007u
#define MXB_GL_MODELVIEW 0x1700u
#define MXB_GL_PROJECTION 0x1701u
#define MXB_GL_VERTEX_ARRAY 0x8074u
#define MXB_GL_COLOR_ARRAY 0x8076u
#define MXB_GL_TEXTURE_COORD_ARRAY 0x8078u
#define MXB_GL_FLOAT 0x1406u
#define MXB_GL_UNSIGNED_BYTE 0x1401u
#define MXB_GL_UNSIGNED_SHORT 0x1403u
#define MXB_GL_UNSIGNED_INT 0x1405u
#define MXB_GL_MAX_INDEXED 512u
typedef struct {float position[4];float color[4];float uv[2];} MXBGLVertex;
typedef struct MXBGLSurface MXBGLSurface;
MXBGLSurface *mxb_gl_create(void);
void mxb_gl_destroy(MXBGLSurface *s);
void mxb_gl_reset(MXBGLSurface *s);
void mxb_gl_clear_frame(MXBGLSurface *s);
int mxb_gl_matrix_mode(MXBGLSurface *s,unsigned mode);
int mxb_gl_load_identity(MXBGLSurface *s);
int mxb_gl_translatef(MXBGLSurface *s,float x,float y,float z);
int mxb_gl_scalef(MXBGLSurface *s,float x,float y,float z);
int mxb_gl_ortho(MXBGLSurface *s,float l,float r,float b,float t,float n,float f);
int mxb_gl_color4f(MXBGLSurface *s,float r,float g,float b,float a);
int mxb_gl_begin(MXBGLSurface *s,unsigned primitive);
int mxb_gl_vertex3f(MXBGLSurface *s,float x,float y,float z);
int mxb_gl_tex_coord2f(MXBGLSurface *s,float u,float v);
int mxb_gl_end(MXBGLSurface *s);
int mxb_gl_load_matrixf(MXBGLSurface *s,const float *matrix16);
int mxb_gl_mult_matrixf(MXBGLSurface *s,const float *matrix16);
int mxb_gl_frustum(MXBGLSurface *s,float l,float r,float b,float t,float n,float f);
int mxb_gl_vertex3fv(MXBGLSurface *s,const float *xyz3);
int mxb_gl_color3f(MXBGLSurface *s,float r,float g,float b);
int mxb_gl_color3fv(MXBGLSurface *s,const float *rgb3);
int mxb_gl_color4ubv(MXBGLSurface *s,const uint8_t *rgba4);
/* Dispatches specific ORIGINAL imported OpenGL32.dll names.
 * Arguments must ALREADY be decoded from the Win64 guest calling ABI.
 * Never pass unverified guest pointers. Unsupported calls fail closed. */
int mxb_gl_dispatch_import(MXBGLSurface *s,const char *library,
                           const char *symbol,unsigned word,
                           const float *args,size_t nargs);
/* Saved guest-address descriptors; never host-dereference these pointers. */
typedef struct {
 uint64_t guest_pointer;
 unsigned type, components, stride, enabled;
} MXBGLClientArray;
int mxb_gl_client_pointer(MXBGLSurface *s,unsigned client_array,
                          unsigned components,unsigned type,
                          unsigned stride,uint64_t guest_pointer);
int mxb_gl_client_enable(MXBGLSurface *s,unsigned client_array,int enabled);
int mxb_gl_client_lookup(const MXBGLSurface *s,unsigned client_array,
                         MXBGLClientArray *output);
int mxb_gl_current_color(const MXBGLSurface *s,float output[4]);
int mxb_gl_current_uv(const MXBGLSurface *s,float output[2]);
/* Cancel an incomplete immediate-mode primitive with no frame commit. */
void mxb_gl_abort(MXBGLSurface *s);
size_t mxb_gl_vertex_count(const MXBGLSurface *s);
const MXBGLVertex *mxb_gl_vertices(const MXBGLSurface *s);
unsigned mxb_gl_faults(const MXBGLSurface *s);
#ifdef __cplusplus
}
#endif
#endif
