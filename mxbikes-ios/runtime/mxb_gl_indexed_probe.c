#include "mxb_gl_indexed_probe.h"
#include "mxb_gl_win64_abi.h"
#include <stddef.h>
#include <stdint.h>

/* Deliberately synthetic guest-memory segment for CI / iPhone Simulator. */
#define GUEST_BASE UINT64_C(0x600000000)
#define GUEST_STACK UINT64_C(0x710000008)
typedef struct {
 float position[9];
 uint8_t color[12];
 float uv[6];
 uint16_t indices[3];
} ProbeGuest;

static int guest_read(void*ctx,uint64_t address,void*output,size_t bytes){
 if(!ctx||!output||address<GUEST_BASE)return 0;
 uint64_t offset=address-GUEST_BASE;
 if(offset>sizeof(ProbeGuest)||bytes>sizeof(ProbeGuest)-(size_t)offset)return 0;
 __builtin_memcpy(output,(const uint8_t*)ctx+(size_t)offset,bytes);
 return 1;
}
static int call(MXBGLSurface*s,ProbeGuest*guest,const char*name,
                uint64_t rcx,uint64_t rdx,uint64_t r8,uint64_t r9){
 MXBGLWin64Call regs={0};
 regs.rsp=GUEST_STACK;
 regs.rcx=rcx;regs.rdx=rdx;regs.r8=r8;regs.r9=r9;
 return mxb_gl_dispatch_win64(s,"OPENGL32.dll",name,
                              &regs,guest_read,guest)==MXB_GL_GUEST_OK;
}
int mxb_gl_indexed_fixture(MXBGLSurface*s){
 if(!s)return 0;
 ProbeGuest guest={
   .position={-.70f,-.60f,0.0f,.70f,-.60f,0.0f,0.0f,.75f,0.0f},
   .color={255,255,255,255,255,255,255,255,255,255,255,255},
   .uv={0.1f,0.1f,0.9f,0.1f,0.5f,0.9f},
   .indices={0,1,2}
 };
 if(!call(s,&guest,"glMatrixMode",MXB_GL_PROJECTION,0,0,0)||
    !call(s,&guest,"glLoadIdentity",0,0,0,0)||
    !call(s,&guest,"glMatrixMode",MXB_GL_MODELVIEW,0,0,0)||
    !call(s,&guest,"glLoadIdentity",0,0,0,0)||
    !call(s,&guest,"glVertexPointer",3,MXB_GL_FLOAT,12,GUEST_BASE)||
    !call(s,&guest,"glColorPointer",4,MXB_GL_UNSIGNED_BYTE,4,
          GUEST_BASE+offsetof(ProbeGuest,color))||
    !call(s,&guest,"glTexCoordPointer",2,MXB_GL_FLOAT,8,
          GUEST_BASE+offsetof(ProbeGuest,uv))||
    !call(s,&guest,"glEnableClientState",MXB_GL_TEXTURE_COORD_ARRAY,0,0,0)||
    !call(s,&guest,"glEnableClientState",MXB_GL_VERTEX_ARRAY,0,0,0)||
    !call(s,&guest,"glEnableClientState",MXB_GL_COLOR_ARRAY,0,0,0)||
    !call(s,&guest,"glDrawElements",MXB_GL_TRIANGLES,3,MXB_GL_UNSIGNED_SHORT,
          GUEST_BASE+offsetof(ProbeGuest,indices)))
   return 0;
 return mxb_gl_vertex_count(s)==3u;
}
