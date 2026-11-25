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
 regs.rdx=6;regs.r8=MXB_GL_FLOAT;
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
 /* Nested modelview and projection stacks, and 2D UI vertices via Win64 ABI. */
 mxb_gl_reset(s);
 regs.rcx=MXB_GL_MODELVIEW;
 if(invoke(s,&mem,&regs,"glMatrixMode")!=MXB_GL_GUEST_OK||
    invoke(s,&mem,&regs,"glPushMatrix")!=MXB_GL_GUEST_OK)return 48;
 regs.xmm_low64[0]=bits_f(2);regs.xmm_low64[1]=bits_f(3);regs.xmm_low64[2]=bits_f(0);
 if(invoke(s,&mem,&regs,"glTranslatef")!=MXB_GL_GUEST_OK||
    invoke(s,&mem,&regs,"glPushMatrix")!=MXB_GL_GUEST_OK)return 49;
 regs.xmm_low64[0]=bits_f(2);regs.xmm_low64[1]=bits_f(2);regs.xmm_low64[2]=bits_f(1);
 if(invoke(s,&mem,&regs,"glScalef")!=MXB_GL_GUEST_OK)return 50;
 regs.rcx=MXB_GL_PROJECTION;
 if(invoke(s,&mem,&regs,"glMatrixMode")!=MXB_GL_GUEST_OK||
    invoke(s,&mem,&regs,"glPushMatrix")!=MXB_GL_GUEST_OK||
    invoke(s,&mem,&regs,"glPushMatrix")!=MXB_GL_GUEST_RENDER_REJECTED||
    invoke(s,&mem,&regs,"glPopMatrix")!=MXB_GL_GUEST_OK||
    invoke(s,&mem,&regs,"glPopMatrix")!=MXB_GL_GUEST_RENDER_REJECTED)return 51;
 regs.rcx=MXB_GL_MODELVIEW;
 if(invoke(s,&mem,&regs,"glMatrixMode")!=MXB_GL_GUEST_OK)return 52;
 for(unsigned pass=0;pass<3u;pass++){
  regs.rcx=MXB_GL_TRIANGLES;
  if(invoke(s,&mem,&regs,"glBegin")!=MXB_GL_GUEST_OK||
     invoke(s,&mem,&regs,"glPopMatrix")!=MXB_GL_GUEST_RENDER_REJECTED)return 53;
  regs.xmm_low64[0]=bits_f(.25f);regs.xmm_low64[1]=bits_f(.75f);
  if(invoke(s,&mem,&regs,"glTexCoord2f")!=MXB_GL_GUEST_OK)return 54;
  float rgba4[4]={.1f,.2f,.3f,.4f};
  memcpy(mem.heap+64,rgba4,sizeof(rgba4));regs.rcx=HEAP+64;
  if(invoke(s,&mem,&regs,"glColor4fv")!=MXB_GL_GUEST_OK)return 55;
  regs.xmm_low64[0]=bits_f(1);regs.xmm_low64[1]=bits_f(1);
  if(invoke(s,&mem,&regs,"glVertex2f")!=MXB_GL_GUEST_OK)return 56;
  float xy[2]={0,1};memcpy(mem.heap,xy,sizeof(xy));regs.rcx=HEAP;
  if(invoke(s,&mem,&regs,"glVertex2fv")!=MXB_GL_GUEST_OK)return 57;
  regs.xmm_low64[0]=bits_f(0);regs.xmm_low64[1]=bits_f(0);
  if(invoke(s,&mem,&regs,"glVertex2f")!=MXB_GL_GUEST_OK||
     invoke(s,&mem,&regs,"glEnd")!=MXB_GL_GUEST_OK)return 58;
  if(pass<2u&&invoke(s,&mem,&regs,"glPopMatrix")!=MXB_GL_GUEST_OK)return 59;
 }
 vertices=mxb_gl_vertices(s);
 if(mxb_gl_vertex_count(s)!=9u||
    !nearly(vertices[0].position[0],4)||!nearly(vertices[0].position[1],5)||
    !nearly(vertices[3].position[0],3)||!nearly(vertices[3].position[1],4)||
    !nearly(vertices[6].position[0],1)||!nearly(vertices[6].position[1],1)||
    !nearly(vertices[1].position[2],0)||!nearly(vertices[1].uv[1],.75f)||
    !nearly(vertices[1].color[3],.4f))return 60;
 if(invoke(s,&mem,&regs,"glPopMatrix")!=MXB_GL_GUEST_RENDER_REJECTED)return 61;
 for(unsigned i=0;i<31u;i++)
  if(invoke(s,&mem,&regs,"glPushMatrix")!=MXB_GL_GUEST_OK)return 62;
 if(invoke(s,&mem,&regs,"glPushMatrix")!=MXB_GL_GUEST_RENDER_REJECTED)return 63;
 mxb_gl_reset(s);
 if(invoke(s,&mem,&regs,"glPopMatrix")!=MXB_GL_GUEST_RENDER_REJECTED)return 64;
 regs.rcx=HEAP+127;
 if(invoke(s,&mem,&regs,"glVertex2fv")!=MXB_GL_GUEST_UNMAPPED_POINTER||
    invoke(s,&mem,&regs,"glColor4fv")!=MXB_GL_GUEST_UNMAPPED_POINTER)return 65;
 /* Menu-style XY arrays and byte indices: the last XY pair ends exactly
  * at the mapped guest heap boundary. Reading a third float would fail. */
 mxb_gl_reset(s);
 const float xy_menu[6]={-1,-.5f,1,-.5f,0,1};
 const uint8_t rgb_menu[9]={255,0,0,0,255,0,0,0,255};
 const uint8_t byte_ix[3]={2,0,1};
 memcpy(mem.heap+104,xy_menu,sizeof(xy_menu));
 memcpy(mem.heap+64,rgb_menu,sizeof(rgb_menu));
 memcpy(mem.heap+80,byte_ix,sizeof(byte_ix));
 regs.xmm_low64[0]=bits_f(.1f);regs.xmm_low64[1]=bits_f(.2f);
 regs.xmm_low64[2]=bits_f(.3f);regs.xmm_low64[3]=bits_f(.25f);
 if(invoke(s,&mem,&regs,"glColor4f")!=MXB_GL_GUEST_OK)return 66;
 regs.rcx=2;regs.rdx=MXB_GL_FLOAT;regs.r8=0;regs.r9=HEAP+104;
 if(invoke(s,&mem,&regs,"glVertexPointer")!=MXB_GL_GUEST_OK)return 67;
 regs.rcx=3;regs.rdx=MXB_GL_UNSIGNED_BYTE;regs.r8=0;regs.r9=HEAP+64;
 if(invoke(s,&mem,&regs,"glColorPointer")!=MXB_GL_GUEST_OK)return 68;
 regs.rcx=MXB_GL_VERTEX_ARRAY;
 if(invoke(s,&mem,&regs,"glEnableClientState")!=MXB_GL_GUEST_OK)return 69;
 regs.rcx=MXB_GL_COLOR_ARRAY;
 if(invoke(s,&mem,&regs,"glEnableClientState")!=MXB_GL_GUEST_OK)return 70;
 regs.rcx=MXB_GL_TRIANGLES;regs.rdx=3;regs.r8=MXB_GL_UNSIGNED_BYTE;regs.r9=HEAP+80;
 if(invoke(s,&mem,&regs,"glDrawElements")!=MXB_GL_GUEST_OK||
    mxb_gl_vertex_count(s)!=3u)return 71;
 vertices=mxb_gl_vertices(s);
 if(!nearly(vertices[0].position[1],1)||
    !nearly(vertices[1].position[0],-1)||
    !nearly(vertices[2].position[0],1))return 72;
 for(unsigned i=0;i<3u;i++){
  if(!nearly(vertices[i].position[2],0)||
     !nearly(vertices[i].position[3],1)||
     !nearly(vertices[i].color[3],1))return 73;
 }
 if(!nearly(vertices[0].color[2],1)||
    !nearly(vertices[1].color[0],1)||
    !nearly(vertices[2].color[1],1))return 74;
 float restored[4];
 if(!mxb_gl_current_color(s,restored)||!nearly(restored[3],.25f))return 75;
 /* No partial output when a byte index or XY pair is outside guest memory. */
 regs.r9=HEAP+127;
 if(invoke(s,&mem,&regs,"glDrawElements")!=MXB_GL_GUEST_UNMAPPED_POINTER||
    mxb_gl_vertex_count(s)!=3u)return 76;
 regs.rcx=2;regs.rdx=MXB_GL_FLOAT;regs.r8=0;regs.r9=HEAP+105;
 if(invoke(s,&mem,&regs,"glVertexPointer")!=MXB_GL_GUEST_OK)return 77;
 regs.rcx=MXB_GL_TRIANGLES;regs.rdx=3;regs.r8=MXB_GL_UNSIGNED_BYTE;regs.r9=HEAP+80;
 if(invoke(s,&mem,&regs,"glDrawElements")!=MXB_GL_GUEST_UNMAPPED_POINTER||
    mxb_gl_vertex_count(s)!=3u)return 78;
 /* Nonindexed 2D path must use the same two-component layout. */
 regs.rcx=2;regs.rdx=MXB_GL_FLOAT;regs.r8=0;regs.r9=HEAP+104;
 if(invoke(s,&mem,&regs,"glVertexPointer")!=MXB_GL_GUEST_OK)return 79;
 regs.rcx=MXB_GL_TRIANGLES;regs.rdx=0;regs.r8=3;regs.r9=0;
 if(invoke(s,&mem,&regs,"glDrawArrays")!=MXB_GL_GUEST_OK||
    mxb_gl_vertex_count(s)!=6u)return 80;
 /* Original text renderer depends on state changes between independent draws.
  * The GL Win64 float argument is XMM1, not XMM0. */
 mxb_gl_reset(s);
 regs.rcx=MXB_GL_LIGHTING;
 if(invoke(s,&mem,&regs,"glEnable")!=MXB_GL_GUEST_UNSUPPORTED||
    invoke(s,&mem,&regs,"glDisable")!=MXB_GL_GUEST_OK)return 81;
 regs.rcx=MXB_GL_DEPTH_TEST;
 if(invoke(s,&mem,&regs,"glEnable")!=MXB_GL_GUEST_OK)return 82;
 regs.rcx=0xfeedface00000000ULL;
 if(invoke(s,&mem,&regs,"glDepthMask")!=MXB_GL_GUEST_OK)return 83;
 regs.rcx=0x0203;
 if(invoke(s,&mem,&regs,"glDepthFunc")!=MXB_GL_GUEST_OK)return 84;
 regs.rcx=MXB_GL_BLEND;
 if(invoke(s,&mem,&regs,"glEnable")!=MXB_GL_GUEST_OK)return 85;
 regs.rcx=MXB_GL_SRC_ALPHA;regs.rdx=MXB_GL_ONE_MINUS_SRC_ALPHA;
 if(invoke(s,&mem,&regs,"glBlendFunc")!=MXB_GL_GUEST_OK)return 86;
 regs.rcx=MXB_GL_ALPHA_TEST;
 if(invoke(s,&mem,&regs,"glEnable")!=MXB_GL_GUEST_OK)return 87;
 regs.rcx=0x0206;regs.xmm_low64[0]=bits_f(.875f);regs.xmm_low64[1]=bits_f(.125f);
 if(invoke(s,&mem,&regs,"glAlphaFunc")!=MXB_GL_GUEST_OK)return 88;
 for(unsigned pass=0;pass<2u;pass++){
  if(pass){
   regs.rcx=MXB_GL_BLEND;
   if(invoke(s,&mem,&regs,"glDisable")!=MXB_GL_GUEST_OK)return 89;
   regs.rcx=MXB_GL_ALPHA_TEST;
   if(invoke(s,&mem,&regs,"glDisable")!=MXB_GL_GUEST_OK)return 90;
   regs.rcx=MXB_GL_DEPTH_TEST;
   if(invoke(s,&mem,&regs,"glDisable")!=MXB_GL_GUEST_OK)return 91;
   regs.rcx=1;
   if(invoke(s,&mem,&regs,"glDepthMask")!=MXB_GL_GUEST_OK)return 92;
  }
  regs.rcx=MXB_GL_TRIANGLES;
  if(invoke(s,&mem,&regs,"glBegin")!=MXB_GL_GUEST_OK)return 93;
  regs.rcx=MXB_GL_BLEND;
  if(invoke(s,&mem,&regs,"glEnable")!=MXB_GL_GUEST_RENDER_REJECTED)return 94;
  for(unsigned i=0;i<3u;i++){
   regs.xmm_low64[0]=bits_f((float)i*.25f);regs.xmm_low64[1]=bits_f(0);
   if(invoke(s,&mem,&regs,"glVertex2f")!=MXB_GL_GUEST_OK)return 95;
  }
  if(invoke(s,&mem,&regs,"glEnd")!=MXB_GL_GUEST_OK)return 96;
 }
 const MXBGLDrawBatch *b=mxb_gl_batches(s);
 if(mxb_gl_batch_count(s)!=2u||mxb_gl_vertex_count(s)!=6u||
    b[0].first_vertex!=0u||b[0].vertex_count!=3u||
    b[0].depth_test!=1u||b[0].depth_write!=0u||b[0].depth_func!=0x0203u||
    b[0].blend_enabled!=1u||b[0].blend_src!=MXB_GL_SRC_ALPHA||
    b[0].blend_dst!=MXB_GL_ONE_MINUS_SRC_ALPHA||b[0].alpha_test!=1u||
    b[0].alpha_func!=0x0206u||!nearly(b[0].alpha_ref,.125f)||
    b[1].first_vertex!=3u||b[1].vertex_count!=3u||
    b[1].depth_test!=0u||b[1].depth_write!=1u||
    b[1].blend_enabled!=0u||b[1].alpha_test!=0u)return 97;
 mxb_gl_clear_frame(s);
 if(mxb_gl_batch_count(s)!=0u||mxb_gl_vertex_count(s)!=0u)return 98;
 /* Nonzero high words are legal for Win64 32-bit GL arguments.
  * Test both draw families, signed negative low words and full pointers. */
 mxb_gl_reset(s);
 memcpy(mem.heap,points,sizeof(points));
 memcpy(mem.heap+96,ix,sizeof(ix));
 regs.rcx=3;regs.rdx=MXB_GL_FLOAT;regs.r8=12;regs.r9=HEAP;
 if(invoke(s,&mem,&regs,"glVertexPointer")!=MXB_GL_GUEST_OK)return 99;
 regs.rcx=MXB_GL_VERTEX_ARRAY;
 if(invoke(s,&mem,&regs,"glEnableClientState")!=MXB_GL_GUEST_OK)return 100;
 regs.rcx=UINT64_C(0xdeadbeef00000004);
 regs.rdx=UINT64_C(0xaabbccdd00000006);
 regs.r8=UINT64_C(0x1234567800001403);regs.r9=HEAP+96;
 if(invoke(s,&mem,&regs,"glDrawElements")!=MXB_GL_GUEST_OK||
    mxb_gl_vertex_count(s)!=6u)return 101;
 vertices=mxb_gl_vertices(s);
 if(!nearly(vertices[0].position[0],-1)||
    !nearly(vertices[3].position[1],1))return 102;
 mxb_gl_clear_frame(s);
 regs.rdx=UINT64_C(0xaabbccdd00000000);
 regs.r8=UINT64_C(0x1234567800000003);
 if(invoke(s,&mem,&regs,"glDrawArrays")!=MXB_GL_GUEST_OK||
    mxb_gl_vertex_count(s)!=3u)return 103;
 vertices=mxb_gl_vertices(s);
 if(!nearly(vertices[0].position[0],-1)||
    !nearly(vertices[2].position[1],1))return 104;
 mxb_gl_clear_frame(s);
 unsigned reads_before=mem.reads;
 regs.rdx=UINT64_C(0xabcdef01ffffffff);
 if(invoke(s,&mem,&regs,"glDrawArrays")!=MXB_GL_GUEST_RENDER_REJECTED)return 105;
 regs.rdx=0;regs.r8=UINT64_C(0xabcdef01ffffffff);
 if(invoke(s,&mem,&regs,"glDrawArrays")!=MXB_GL_GUEST_RENDER_REJECTED)return 106;
 regs.rdx=UINT64_C(0xabcdef0180000000);regs.r8=MXB_GL_UNSIGNED_SHORT;
 if(invoke(s,&mem,&regs,"glDrawElements")!=MXB_GL_GUEST_RENDER_REJECTED||
    mem.reads!=reads_before||mxb_gl_vertex_count(s)!=0u)return 107;
 regs.rdx=3;regs.r9=(uint32_t)(HEAP+96);
 if(invoke(s,&mem,&regs,"glDrawElements")!=MXB_GL_GUEST_UNMAPPED_POINTER||
    mxb_gl_vertex_count(s)!=0u)return 108;
 mxb_gl_destroy(s);
 return 0;
}
