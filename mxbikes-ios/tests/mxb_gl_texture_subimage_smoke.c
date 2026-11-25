#include "mxb_gl_texture.h"
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#define SP UINT64_C(0x700000008)
#define PIX UINT64_C(0x900000000)
#define W 67u
#define H 9u
#define CHECK(x) do { if(!(x)){fprintf(stderr,"line %d: %s\n",__LINE__,#x);return 1;} }while(0)
typedef struct {uint64_t stack[10];uint8_t data[4096];size_t limit,reads;} Guest;
static int rd(void*ctx,uint64_t a,void*out,size_t n){
 Guest*g=ctx;
 if(a>=SP&&a-SP<=sizeof(g->stack)&&n<=sizeof(g->stack)-(a-SP)){
  memcpy(out,(uint8_t*)g->stack+(a-SP),n);return 1;
 }
 if(a>=PIX&&a-PIX<=g->limit&&n<=g->limit-(a-PIX)){
  memcpy(out,g->data+(a-PIX),n);g->reads++;return 1;
 }
 return 0;
}
static enum MXBGLGuestStatus call(MXBGLTextures*t,Guest*g,const char*s,uint64_t a,uint64_t b,uint64_t c,uint64_t d){
 MXBGLWin64Call r={0};r.rsp=SP;r.rcx=a;r.rdx=b;r.r8=c;r.r9=d;
 return mxb_tex_dispatch_win64(t,"OPENGL32.dll",s,&r,rd,0,g);
}
static void args(Guest*g,unsigned w,unsigned h,unsigned fmt,uint64_t ptr){
 g->stack[5]=UINT64_C(0xdeadbeef00000000)|w;
 g->stack[6]=UINT64_C(0xfadebeef00000000)|h;
 g->stack[7]=UINT64_C(0xfeedface00000000)|fmt;
 g->stack[8]=UINT64_C(0xbadcafe000000000)|MXB_GL_UNSIGNED_BYTE;
 g->stack[9]=ptr;
}
static int allocate(MXBGLTextures*t,Guest*g,unsigned internal){
 args(g,H,0,MXB_GL_RGBA,0);
 return call(t,g,"glTexImage2D",MXB_GL_TEXTURE_2D,0,internal,W)==MXB_GL_GUEST_OK;
}
static unsigned rand32(unsigned*state){*state=*state*1664525u+1013904223u;return *state;}
int main(void){
 MXBGLTextures*t=mxb_tex_create(); Guest g={0};g.limit=sizeof(g.data);
 unsigned w=0,h=0;uint8_t expected[W*H*4],before[sizeof(expected)];
 CHECK(t);CHECK(call(t,&g,"glEnable",MXB_GL_TEXTURE_2D,0,0,0)==0);
 CHECK(call(t,&g,"glBindTexture",MXB_GL_TEXTURE_2D,42,0,0)==0);
 args(&g,1,1,MXB_GL_RGBA,PIX);
 CHECK(call(t,&g,"glTexSubImage2D",MXB_GL_TEXTURE_2D,0,0,0)==MXB_GL_GUEST_RENDER_REJECTED);
 CHECK(allocate(t,&g,MXB_GL_RGBA));
 const uint8_t*px=mxb_tex_current_rgba(t,&w,&h);
 memset(expected,0,sizeof(expected));
 CHECK(px&&w==W&&h==H&&!memcmp(px,expected,sizeof(expected))&&g.reads==0);
 CHECK(mxb_tex_storage_bytes(t)==sizeof(expected));
 unsigned state=12453;
 for(unsigned i=0;i<128;i++){
  unsigned x=rand32(&state)%W,y=rand32(&state)%H;
  unsigned rw=1+rand32(&state)%(W-x),rh=1+rand32(&state)%(H-y);
  unsigned bpp=3+(i%2),alignment=1u<<(i%4),fmt=bpp==3?MXB_GL_RGB:MXB_GL_RGBA;
  if(i==0){x=2;y=1;rw=63;rh=4;bpp=3;fmt=MXB_GL_RGB;alignment=8;}
  unsigned pitch=(rw*bpp+alignment-1)&~(alignment-1);
  CHECK(pitch*rh<=sizeof(g.data));
  for(unsigned j=0;j<pitch*rh;j++)g.data[j]=(uint8_t)(rand32(&state)>>24);
  CHECK(call(t,&g,"glPixelStorei",MXB_GL_UNPACK_ALIGNMENT,alignment,0,0)==0);
  args(&g,rw,rh,fmt,PIX);
  CHECK(call(t,&g,"glTexSubImage2D",UINT64_C(0x1234567800000de1),UINT64_C(0x1234567800000000),UINT64_C(0xabcdef0000000000)|x,UINT64_C(0xfedcba0000000000)|y)==0);
  for(unsigned j=0;j<rh;j++)for(unsigned k=0;k<rw;k++){
   uint8_t*dst=expected+((y+j)*W+x+k)*4;memcpy(dst,g.data+j*pitch+k*bpp,bpp);if(bpp==3)dst[3]=255;
  }
  CHECK(!memcmp(px,expected,sizeof(expected))&&mxb_tex_storage_bytes(t)==sizeof(expected));
 }
 memcpy(before,px,sizeof(before));
 CHECK(call(t,&g,"glPixelStorei",MXB_GL_UNPACK_ALIGNMENT,4,0,0)==0);
 args(&g,60,2,MXB_GL_RGBA,PIX);g.limit=300;size_t prev=g.reads;
 CHECK(call(t,&g,"glTexSubImage2D",MXB_GL_TEXTURE_2D,0,0,0)==MXB_GL_GUEST_UNMAPPED_POINTER);
 CHECK(g.reads>prev&&!memcmp(px,before,sizeof(before)));
 g.limit=sizeof(g.data);args(&g,1,1,MXB_GL_RGBA,PIX);
 CHECK(call(t,&g,"glTexSubImage2D",MXB_GL_TEXTURE_2D,0,UINT32_MAX,0)==MXB_GL_GUEST_UNSUPPORTED);
 CHECK(call(t,&g,"glTexSubImage2D",MXB_GL_TEXTURE_2D,0,W,0)==MXB_GL_GUEST_UNSUPPORTED);
 CHECK(call(t,&g,"glTexSubImage2D",MXB_GL_TEXTURE_2D,1,0,0)==MXB_GL_GUEST_UNSUPPORTED);
 args(&g,UINT32_MAX,1,MXB_GL_RGBA,PIX);
 CHECK(call(t,&g,"glTexSubImage2D",MXB_GL_TEXTURE_2D,0,0,0)==MXB_GL_GUEST_UNSUPPORTED);
 args(&g,0,1,MXB_GL_RGBA,0);prev=g.reads;
 CHECK(call(t,&g,"glTexSubImage2D",MXB_GL_TEXTURE_2D,0,W,0)==0&&g.reads==prev);
 args(&g,1,1,MXB_GL_RGBA,0);
 CHECK(call(t,&g,"glTexSubImage2D",MXB_GL_TEXTURE_2D,0,0,0)==MXB_GL_GUEST_UNMAPPED_POINTER);
 CHECK(!memcmp(px,before,sizeof(before)));
 CHECK(call(t,&g,"glBindTexture",MXB_GL_TEXTURE_2D,43,0,0)==0);
 CHECK(allocate(t,&g,MXB_GL_RGB));px=mxb_tex_current_rgba(t,&w,&h);
 CHECK(px&&px[3]==255&&px[sizeof(expected)-1]==255);
 args(&g,1,1,MXB_GL_RGBA,PIX);memcpy(g.data,"\x11\x22\x33\x44",4);
 CHECK(call(t,&g,"glTexSubImage2D",MXB_GL_TEXTURE_2D,0,1,0)==0);
 CHECK(px[4]==17&&px[5]==34&&px[6]==51&&px[7]==255);
 CHECK(call(t,&g,"glBindTexture",MXB_GL_TEXTURE_2D,42,0,0)==0);
 CHECK(!memcmp(mxb_tex_current_rgba(t,0,0),before,sizeof(before)));
 CHECK(mxb_tex_storage_bytes(t)==2*sizeof(expected));
 mxb_tex_destroy(t);puts("128 randomized subimage comparisons + edge/rollback checks passed");return 0;
}
