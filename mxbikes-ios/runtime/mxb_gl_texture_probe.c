#include "mxb_gl_texture_probe.h"
#include <stdint.h>
#include <stddef.h>
#define GUEST_BASE UINT64_C(0x620000000)
#define STACK_BASE UINT64_C(0x740000008)
typedef struct {
 uint8_t color[16];
 uint32_t generated_id;
 uint64_t stack[10];
} Guest;
static int read_fixture(void*ctx,uint64_t ptr,void*out,size_t n){
 Guest*g=(Guest*)ctx;
 if(!ctx||!ptr)return 0;
 if(ptr>=GUEST_BASE&&ptr-GUEST_BASE<=sizeof(*g)&&n<=sizeof(*g)-(size_t)(ptr-GUEST_BASE)){
  __builtin_memcpy(out,(const uint8_t*)g+(size_t)(ptr-GUEST_BASE),n);
  return 1;
 }
 if(ptr>=STACK_BASE&&ptr-STACK_BASE<=sizeof(g->stack)&&
    n<=sizeof(g->stack)-(size_t)(ptr-STACK_BASE)){
  __builtin_memcpy(out,(const uint8_t*)g->stack+(size_t)(ptr-STACK_BASE),n);
  return 1;
 }
 return 0;
}
static int write_fixture(void*ctx,uint64_t ptr,const void*data,size_t n){
 Guest*g=(Guest*)ctx;
 if(!ctx||ptr<GUEST_BASE||ptr-GUEST_BASE>sizeof(*g)||
    n>sizeof(*g)-(size_t)(ptr-GUEST_BASE))return 0;
 __builtin_memcpy((uint8_t*)g+(size_t)(ptr-GUEST_BASE),data,n);
 return 1;
}
static int call(MXBGLTextures*t,Guest*guest,const char*name,
                uint64_t rcx,uint64_t rdx,uint64_t r8,uint64_t r9){
 MXBGLWin64Call regs={0};
 regs.rsp=STACK_BASE;regs.rcx=rcx;regs.rdx=rdx;regs.r8=r8;regs.r9=r9;
 return mxb_tex_dispatch_win64(t,"OPENGL32.dll",name,&regs,
                 read_fixture,write_fixture,guest)==MXB_GL_GUEST_OK;
}
int mxb_gl_texture_fixture(MXBGLTextures*t){
 if(!t)return 0;
 Guest guest={
  .color={
   255,102,32,255, 64,235,64,255,
   64,235,64,255, 255,102,32,255
  },
  /* memory starting at import RSP+0x28 maps to stack[5]. */
  .stack={0}
 };
 if(!call(t,&guest,"glGenTextures",1,GUEST_BASE+offsetof(Guest,generated_id),0,0)||
    !guest.generated_id||
    !call(t,&guest,"glBindTexture",MXB_GL_TEXTURE_2D,guest.generated_id,0,0)||
    !call(t,&guest,"glPixelStorei",MXB_GL_UNPACK_ALIGNMENT,1,0,0))
  return 0;
 guest.stack[5]=2;guest.stack[6]=0;guest.stack[7]=MXB_GL_RGBA;
 guest.stack[8]=MXB_GL_UNSIGNED_BYTE;
 guest.stack[9]=GUEST_BASE+offsetof(Guest,color);
 if(!call(t,&guest,"glTexImage2D",MXB_GL_TEXTURE_2D,0,MXB_GL_RGBA,2)||
    !call(t,&guest,"glTexParameteri",MXB_GL_TEXTURE_2D,
          MXB_GL_TEXTURE_MIN_FILTER,MXB_GL_NEAREST,0)||
    !call(t,&guest,"glEnable",MXB_GL_TEXTURE_2D,0,0,0))return 0;
 unsigned w=0,h=0;
 const uint8_t *bytes=mxb_tex_current_rgba(t,&w,&h);
 return bytes&&w==2&&h==2&&bytes[0]==255&&bytes[8]==64;

}
