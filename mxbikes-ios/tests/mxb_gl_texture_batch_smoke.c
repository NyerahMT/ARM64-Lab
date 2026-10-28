#include "mxb_gl_texture_probe.h"
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#define MEM UINT64_C(0x630000000)
#define SP UINT64_C(0x750000008)
typedef struct {
 uint8_t pixels[64];
 uint32_t name;
 uint64_t stack[10];
 int blocked;
} Memory;
static int rd(void*ctx,uint64_t address,void*out,size_t n){
 Memory*m=(Memory*)ctx;
 if(m->blocked)return 0;
 if(address>=MEM&&address-MEM<=sizeof(*m)&&n<=sizeof(*m)-(size_t)(address-MEM)){
  memcpy(out,(const uint8_t*)m+(size_t)(address-MEM),n);return 1;
 }
 if(address>=SP&&address-SP<=sizeof(m->stack)&&
    n<=sizeof(m->stack)-(size_t)(address-SP)){
  memcpy(out,(const uint8_t*)m->stack+(size_t)(address-SP),n);return 1;
 }
 return 0;
}
static int wr(void*ctx,uint64_t a,const void*in,size_t n){
 Memory*m=(Memory*)ctx;
 if(m->blocked||a<MEM||a-MEM>sizeof(*m)||n>sizeof(*m)-(size_t)(a-MEM))
  return 0;
 memcpy((uint8_t*)m+(size_t)(a-MEM),in,n);return 1;
}
static enum MXBGLGuestStatus invoke(MXBGLTextures*t,Memory*m,const char*sym,
  uint64_t rcx,uint64_t rdx,uint64_t r8,uint64_t r9){
 MXBGLWin64Call g={0};
 g.rsp=SP;g.rcx=rcx;g.rdx=rdx;g.r8=r8;g.r9=r9;
 return mxb_tex_dispatch_win64(t,"OPENGL32.dll",sym,&g,rd,wr,m);
}
int main(void){
 MXBGLTextures*t=mxb_tex_create();
 if(!t)return 1;
 if(!mxb_gl_texture_fixture(t))return 2;
 unsigned w=0,h=0;
 const uint8_t*px=mxb_tex_current_rgba(t,&w,&h);
 if(!px||w!=2||h!=2||px[0]!=255||px[8]!=64)return 3;
 Memory m={0};
 enum MXBGLGuestStatus gen_status=invoke(t,&m,"glGenTextures",1,MEM+offsetof(Memory,name),0,0);
 if(gen_status!=MXB_GL_GUEST_OK)return 40+(int)gen_status;
 if(!m.name)return 49;
 if(invoke(t,&m,"glBindTexture",MXB_GL_TEXTURE_2D,m.name,0,0)!=MXB_GL_GUEST_OK)return 5;
 if(invoke(t,&m,"glEnable",MXB_GL_TEXTURE_2D,0,0,0)!=MXB_GL_GUEST_OK)return 6;
 if(invoke(t,&m,"glPixelStorei",MXB_GL_UNPACK_ALIGNMENT,4,0,0)!=MXB_GL_GUEST_OK)return 61;
 /* RGB width 3 has 9 pixel bytes but 12 byte row pitch at alignment=4. */
 uint8_t input[24]={
  255,0,0, 0,255,0, 0,0,255, 99,99,99,
  32,64,96, 10,20,30, 3,2,1, 99,99,99
 };
 memcpy(m.pixels,input,sizeof(input));
 m.stack[5]=2;m.stack[6]=0;m.stack[7]=MXB_GL_RGB;
 m.stack[8]=MXB_GL_UNSIGNED_BYTE;m.stack[9]=MEM+offsetof(Memory,pixels);
 if(invoke(t,&m,"glTexImage2D",MXB_GL_TEXTURE_2D,0,MXB_GL_RGB,3)!=MXB_GL_GUEST_OK)return 7;
 px=mxb_tex_current_rgba(t,&w,&h);
 if(!px||w!=3||h!=2||px[0]!=255||px[3]!=255||px[4]!=0||
    px[5]!=255||px[8]!=0||px[10]!=255||px[12]!=32||
    px[13]!=64||px[14]!=96||px[15]!=255)return 8;
 /* Broken source mapping never overwrites previous texture. */
 m.blocked=1;
 if(invoke(t,&m,"glTexImage2D",MXB_GL_TEXTURE_2D,0,MXB_GL_RGB,3)!=MXB_GL_GUEST_UNMAPPED_POINTER)return 9;
 px=mxb_tex_current_rgba(t,&w,&h);
 if(!px||w!=3||px[12]!=32)return 10;
 m.blocked=0;
 if(invoke(t,&m,"glTexImage2D",MXB_GL_TEXTURE_2D,0,MXB_GL_RGBA,257)!=MXB_GL_GUEST_UNSUPPORTED)return 11;
 if(invoke(t,&m,"glTexParameteri",MXB_GL_TEXTURE_2D,MXB_GL_TEXTURE_MIN_FILTER,MXB_GL_LINEAR,0)!=MXB_GL_GUEST_UNSUPPORTED)return 12;
 if(invoke(t,&m,"glDisable",MXB_GL_TEXTURE_2D,0,0,0)!=MXB_GL_GUEST_OK||
    mxb_tex_current_rgba(t,&w,&h)!=0)return 13;
 if(invoke(t,&m,"glEnable",MXB_GL_TEXTURE_2D,0,0,0)!=MXB_GL_GUEST_OK)return 14;
 if(invoke(t,&m,"glDeleteTextures",1,MEM+offsetof(Memory,name),0,0)!=MXB_GL_GUEST_OK)return 15;
 if(mxb_tex_current_rgba(t,&w,&h)!=0)return 16;
 mxb_tex_destroy(t);
 return 0;
}
