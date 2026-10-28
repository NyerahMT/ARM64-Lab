#include "mxb_gl_win64_abi.h"
#include <math.h>
#include <stdint.h>
#include <string.h>

#define HEAP UINT64_C(0x650000000)
#define STACK UINT64_C(0x720000000)
typedef struct {
 uint8_t heap[128];
 uint8_t stack[128];
 unsigned reads;
 int deny;
} TestMemory;
static int read_guest(void *ctx,uint64_t ptr,void*out,size_t len){
 TestMemory*m=(TestMemory*)ctx;
 if(m->deny)return 0;
 if(ptr>=HEAP&&ptr-HEAP<=sizeof(m->heap)&&len<=sizeof(m->heap)-(size_t)(ptr-HEAP)){
  memcpy(out,m->heap+(size_t)(ptr-HEAP),len);m->reads++;return 1;
 }
 if(ptr>=STACK&&ptr-STACK<=sizeof(m->stack)&&len<=sizeof(m->stack)-(size_t)(ptr-STACK)){
  memcpy(out,m->stack+(size_t)(ptr-STACK),len);m->reads++;return 1;
 }
 return 0;
}
static uint64_t bits_f(float f){
 uint32_t val=0;
 memcpy(&val,&f,4);return val;
}
static uint64_t bits_d(double f){
 uint64_t val=0;
 memcpy(&val,&f,8);return val;
}
static int nearly(float a,float b){return fabsf(a-b)<.00005f;}
static enum MXBGLGuestStatus invoke(MXBGLSurface *surface,TestMemory *mem,
  MXBGLWin64Call *regs,const char *name){
 return mxb_gl_dispatch_win64(surface,"OPENGL32.dll",name,regs,read_guest,mem);
}
int main(void){
 MXBGLSurface*s=mxb_gl_create();
 if(!s)return 1;
 TestMemory mem={0};
 MXBGLWin64Call regs={0};
 regs.rsp=STACK+8u;
 regs.rcx=MXB_GL_PROJECTION;
 if(invoke(s,&mem,&regs,"glMatrixMode")!=MXB_GL_GUEST_OK)return 2;
 /* Six doubles: first four XMM lanes, final two at Win64 stack +28,+30 */
 double ortho[]={-2,2,-2,2,-5,5};
 for(int i=0;i<4;i++)regs.xmm_low64[i]=bits_d(ortho[i]);
 memcpy(mem.stack+0x30,&ortho[4],8);
 memcpy(mem.stack+0x38,&ortho[5],8);
 if(invoke(s,&mem,&regs,"glOrtho")!=MXB_GL_GUEST_OK||mem.reads!=2)return 3;
 regs.rcx=MXB_GL_MODELVIEW;
 if(invoke(s,&mem,&regs,"glMatrixMode")!=MXB_GL_GUEST_OK||
    invoke(s,&mem,&regs,"glLoadIdentity")!=MXB_GL_GUEST_OK)return 4;
 float mat[16]={1,0,0,0,0,1,0,0,0,0,1,0,.25f,0,0,1};
 memcpy(mem.heap,mat,sizeof(mat));
 regs.rcx=HEAP;
 if(invoke(s,&mem,&regs,"glLoadMatrixf")!=MXB_GL_GUEST_OK)return 5;
 regs.rcx=MXB_GL_TRIANGLES;
 if(invoke(s,&mem,&regs,"glBegin")!=MXB_GL_GUEST_OK)return 6;
 regs.xmm_low64[0]=bits_f(.7f);
 regs.xmm_low64[1]=bits_f(.3f);
 regs.xmm_low64[2]=bits_f(.1f);
 regs.xmm_low64[3]=bits_f(1.0f);
 if(invoke(s,&mem,&regs,"glColor4f")!=MXB_GL_GUEST_OK)return 7;
 float points[3][3]={{-1,-1,0},{1,-1,0},{0,1,0}};
 for(int i=0;i<3;i++){
  for(int j=0;j<3;j++)regs.xmm_low64[j]=bits_f(points[i][j]);
  if(invoke(s,&mem,&regs,"glVertex3f")!=MXB_GL_GUEST_OK)return 8;
 }
 if(invoke(s,&mem,&regs,"glEnd")!=MXB_GL_GUEST_OK)return 9;
 if(mxb_gl_vertex_count(s)!=3u)return 10;
 const MXBGLVertex*vertices=mxb_gl_vertices(s);
 if(!nearly(vertices[0].position[0],-.375f)||
    !nearly(vertices[1].position[0],.625f)||
    !nearly(vertices[2].position[1],.5f)||
    !nearly(vertices[2].color[0],.7f))return 11;
 /* 3fv is pointer through RCX, not an immediate integer / host pointer. */
 mxb_gl_clear_frame(s);
 regs.rcx=MXB_GL_TRIANGLES;
 if(invoke(s,&mem,&regs,"glBegin")!=MXB_GL_GUEST_OK)return 12;
 for(int i=0;i<3;i++){
  regs.rcx=HEAP+64u;
  memcpy(mem.heap+64,points[i],sizeof(points[i]));
  if(invoke(s,&mem,&regs,"glVertex3fv")!=MXB_GL_GUEST_OK)return 13;
 }
 if(invoke(s,&mem,&regs,"glEnd")!=MXB_GL_GUEST_OK||
    mxb_gl_vertex_count(s)!=3u)return 14;
 mxb_gl_clear_frame(s);
 regs.rcx=HEAP+4096u;
 if(invoke(s,&mem,&regs,"glColor4ubv")!=MXB_GL_GUEST_UNMAPPED_POINTER)return 15;
 mem.deny=1;
 regs.rcx=HEAP;
 if(invoke(s,&mem,&regs,"glMultMatrixf")!=MXB_GL_GUEST_UNMAPPED_POINTER)return 16;
 mem.deny=0;
 if(invoke(s,&mem,&regs,"glTexImage2D")!=MXB_GL_GUEST_UNSUPPORTED)return 17;
 if(mxb_gl_dispatch_win64(s,"steam_api64.dll","SteamAPI_Init",&regs,read_guest,&mem)
   !=MXB_GL_GUEST_UNSUPPORTED)return 18;
 regs.rsp=STACK;
 if(invoke(s,&mem,&regs,"glBegin")!=MXB_GL_GUEST_INVALID_STATE)return 19;
 if(mxb_gl_vertex_count(s)!=0u)return 20;
 /* Original imported functions: indexed geometry with guest pointers.
  * No proprietary game bytes, synthetic fixture memory only. */
 mxb_gl_reset(s);
 regs.rsp=STACK+8u;
 memcpy(mem.heap,points,sizeof(points));
 const uint8_t rgba[12]={255,0,0,255,0,255,0,255,0,0,255,255};
 memcpy(mem.heap+64,rgba,sizeof(rgba));
 const uint16_t ix[6]={0,1,2,2,1,0};
 memcpy(mem.heap+96,ix,sizeof(ix));
 regs.rcx=3;regs.rdx=MXB_GL_FLOAT;regs.r8=12;regs.r9=HEAP;
 if(invoke(s,&mem,&regs,"glVertexPointer")!=MXB_GL_GUEST_OK)return 21;
 regs.rcx=4;regs.rdx=MXB_GL_UNSIGNED_BYTE;regs.r8=4;regs.r9=HEAP+64;
 if(invoke(s,&mem,&regs,"glColorPointer")!=MXB_GL_GUEST_OK)return 22;
 regs.rcx=MXB_GL_VERTEX_ARRAY;
 if(invoke(s,&mem,&regs,"glEnableClientState")!=MXB_GL_GUEST_OK)return 23;
 regs.rcx=MXB_GL_COLOR_ARRAY;
 if(invoke(s,&mem,&regs,"glEnableClientState")!=MXB_GL_GUEST_OK)return 24;
 regs.rcx=MXB_GL_TRIANGLES;regs.rdx=6;regs.r8=MXB_GL_UNSIGNED_SHORT;regs.r9=HEAP+96;
 if(invoke(s,&mem,&regs,"glDrawElements")!=MXB_GL_GUEST_OK)return 25;
 if(mxb_gl_vertex_count(s)!=6u)return 26;
 vertices=mxb_gl_vertices(s);
 if(!nearly(vertices[0].position[0],-1)||
    !nearly(vertices[1].position[0],1)||
    !nearly(vertices[2].position[1],1)||
    !nearly(vertices[0].color[0],1)||
    !nearly(vertices[1].color[1],1)||
    !nearly(vertices[2].color[2],1)||
    !nearly(vertices[3].color[2],1))return 27;
 mxb_gl_clear_frame(s);
 /* Failed reads must not leave half a triangle in the output frame. */
 mem.deny=1;
 if(invoke(s,&mem,&regs,"glDrawElements")!=MXB_GL_GUEST_UNMAPPED_POINTER||
    mxb_gl_vertex_count(s)!=0u)return 28;
 mem.deny=0;
 regs.r9=HEAP+127;
 if(invoke(s,&mem,&regs,"glDrawElements")!=MXB_GL_GUEST_UNMAPPED_POINTER||
    mxb_gl_vertex_count(s)!=0u)return 29;
 regs.r9=HEAP+96;regs.rdx=513;
 if(invoke(s,&mem,&regs,"glDrawElements")!=MXB_GL_GUEST_RENDER_REJECTED)return 30;
 regs.rdx=6;regs.r8=MXB_GL_UNSIGNED_BYTE;
 if(invoke(s,&mem,&regs,"glDrawElements")!=MXB_GL_GUEST_RENDER_REJECTED)return 31;
 uint32_t wide[3]={2,1,0};
 memcpy(mem.heap+96,wide,sizeof(wide));
 regs.rdx=3;regs.r8=MXB_GL_UNSIGNED_INT;regs.r9=HEAP+96;
 if(invoke(s,&mem,&regs,"glDrawElements")!=MXB_GL_GUEST_OK||
    mxb_gl_vertex_count(s)!=3u)return 32;
 mxb_gl_clear_frame(s);
 regs.rcx=MXB_GL_VERTEX_ARRAY;
 if(invoke(s,&mem,&regs,"glDisableClientState")!=MXB_GL_GUEST_OK)return 33;
 regs.rcx=MXB_GL_TRIANGLES;
 if(invoke(s,&mem,&regs,"glDrawElements")!=MXB_GL_GUEST_RENDER_REJECTED)return 34;
 if(mxb_gl_vertex_count(s)!=0u)return 35;
 /* Another original OpenGL path: nonindexed contiguous glDrawArrays
  * with guest UV float arrays and verified index-independent safety. */
 mxb_gl_reset(s);
 memcpy(mem.heap,points,sizeof(points));
 const float uv[6]={0,0,1,0,.5f,1};
 memcpy(mem.heap+36,uv,sizeof(uv));
 regs.rcx=3;regs.rdx=MXB_GL_FLOAT;regs.r8=12;regs.r9=HEAP;
 if(invoke(s,&mem,&regs,"glVertexPointer")!=MXB_GL_GUEST_OK)return 40;
 regs.rcx=2;regs.rdx=MXB_GL_FLOAT;regs.r8=8;regs.r9=HEAP+36;
 if(invoke(s,&mem,&regs,"glTexCoordPointer")!=MXB_GL_GUEST_OK)return 41;
 regs.rcx=MXB_GL_VERTEX_ARRAY;
 if(invoke(s,&mem,&regs,"glEnableClientState")!=MXB_GL_GUEST_OK)return 42;
 regs.rcx=MXB_GL_TEXTURE_COORD_ARRAY;
 if(invoke(s,&mem,&regs,"glEnableClientState")!=MXB_GL_GUEST_OK)return 43;
 regs.rcx=MXB_GL_TRIANGLES;regs.rdx=0;regs.r8=3;regs.r9=0;
 if(invoke(s,&mem,&regs,"glDrawArrays")!=MXB_GL_GUEST_OK)return 44;
 if(mxb_gl_vertex_count(s)!=3u)return 45;
 vertices=mxb_gl_vertices(s);
 if(!nearly(vertices[0].uv[0],0)||!nearly(vertices[1].uv[0],1)||
    !nearly(vertices[2].uv[1],1)||
    !nearly(vertices[2].position[1],1))return 46;
 mxb_gl_clear_frame(s);
 regs.rdx=65535;regs.r8=3;
 if(invoke(s,&mem,&regs,"glDrawArrays")!=MXB_GL_GUEST_RENDER_REJECTED)return 47;
 mxb_gl_destroy(s);
 return 0;
}
