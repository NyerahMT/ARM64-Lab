#include "mxb_gl_surface.h"
#include <stddef.h>
/* AArch64 freestanding compilation; the app resolves libc allocation. */
extern void *calloc(size_t,size_t);
extern void free(void *);

struct MXBGLSurface {
 MXBGLVertex frame[MXB_GL_MAX_OUTPUT],working[MXB_GL_MAX_INPUT];
 size_t frame_len,working_len;
 float modelview[16],projection[16],current_color[4],current_uv[2];
 unsigned current_matrix,begin_mode,faults;
 MXBGLClientArray vertex_array,color_array,texcoord_array;
 int building;
};
static void identity(float*m){
 __builtin_memset(m,0,16*sizeof(float));m[0]=m[5]=m[10]=m[15]=1.0f;
}
static void multiply(float*lhs,const float*rhs){
 float x[16];for(int col=0;col<4;col++)for(int row=0;row<4;row++){
 float v=0.0f;for(int k=0;k<4;k++)v+=lhs[k*4+row]*rhs[col*4+k];
 x[col*4+row]=v;
 }
 __builtin_memcpy(lhs,x,sizeof(x));
}
static void transform(const float*m,const float*v,float*out){
 for(int row=0;row<4;row++)out[row]=m[row]*v[0]+m[4+row]*v[1]+m[8+row]*v[2]+m[12+row]*v[3];
}
static int fail(MXBGLSurface*s){if(s)s->faults++;return 0;}
static int valid(float v){return __builtin_isfinite(v);}
static float*selected(MXBGLSurface*s){return s->current_matrix==MXB_GL_PROJECTION?s->projection:s->modelview;}
MXBGLSurface*mxb_gl_create(void){MXBGLSurface*s=(MXBGLSurface*)calloc(1,sizeof(*s));if(s)mxb_gl_reset(s);return s;}
void mxb_gl_destroy(MXBGLSurface*s){free(s);}
void mxb_gl_reset(MXBGLSurface*s){
 if(!s)return;
 __builtin_memset(s,0,sizeof(*s));
 identity(s->modelview);identity(s->projection);
 for(unsigned i=0;i<4u;i++)s->current_color[i]=1.0f;
 s->current_matrix=MXB_GL_MODELVIEW;
}
void mxb_gl_clear_frame(MXBGLSurface*s){if(s)s->frame_len=0u;}
int mxb_gl_matrix_mode(MXBGLSurface*s,unsigned mode){
 if(!s)return 0;
 if(s->building||(mode!=MXB_GL_MODELVIEW&&mode!=MXB_GL_PROJECTION))return fail(s);
 s->current_matrix=mode;return 1;
}
int mxb_gl_load_identity(MXBGLSurface*s){
 if(!s)return 0;
 if(s->building)return fail(s);
 identity(selected(s));return 1;
}
int mxb_gl_translatef(MXBGLSurface*s,float x,float y,float z){
 if(!s)return 0;
 if(s->building||!valid(x)||!valid(y)||!valid(z))return fail(s);
 float m[16];identity(m);m[12]=x;m[13]=y;m[14]=z;
 multiply(selected(s),m);return 1;
}
int mxb_gl_scalef(MXBGLSurface*s,float x,float y,float z){
 if(!s)return 0;
 if(s->building||!valid(x)||!valid(y)||!valid(z))return fail(s);
 float m[16];identity(m);m[0]=x;m[5]=y;m[10]=z;
 multiply(selected(s),m);return 1;
}
int mxb_gl_ortho(MXBGLSurface*s,float l,float r,float b,float t,float n,float f){
 if(!s)return 0;
 if(s->building||!valid(l)||!valid(r)||!valid(b)||!valid(t)||!valid(n)||!valid(f)||r==l||t==b||f==n)return fail(s);
 float m[16];identity(m);
 m[0]=2.0f/(r-l);m[5]=2.0f/(t-b);m[10]=-2.0f/(f-n);
 m[12]=-(r+l)/(r-l);m[13]=-(t+b)/(t-b);m[14]=-(f+n)/(f-n);
 multiply(selected(s),m);return 1;
}
int mxb_gl_color4f(MXBGLSurface*s,float r,float g,float b,float a){
 if(!s)return 0;
 if(!valid(r)||!valid(g)||!valid(b)||!valid(a))return fail(s);
 s->current_color[0]=r;s->current_color[1]=g;
 s->current_color[2]=b;s->current_color[3]=a;return 1;
}
int mxb_gl_begin(MXBGLSurface*s,unsigned primitive){
 if(!s)return 0;
 if(s->building||(primitive!=MXB_GL_TRIANGLES&&primitive!=MXB_GL_TRIANGLE_STRIP&&
    primitive!=MXB_GL_TRIANGLE_FAN&&primitive!=MXB_GL_QUADS))return fail(s);
 s->working_len=0;s->begin_mode=primitive;s->building=1;return 1;
}
int mxb_gl_vertex3f(MXBGLSurface*s,float x,float y,float z){
 if(!s)return 0;
 if(!s->building||s->working_len>=MXB_GL_MAX_INPUT||
    !valid(x)||!valid(y)||!valid(z))return fail(s);
 const float pos[4]={x,y,z,1.0f};float view[4];
 MXBGLVertex*v=&s->working[s->working_len];
 transform(s->modelview,pos,view);transform(s->projection,view,v->position);
 __builtin_memcpy(v->color,s->current_color,sizeof(v->color));
 __builtin_memcpy(v->uv,s->current_uv,sizeof(v->uv));
 for(int i=0;i<4;i++)if(!valid(v->position[i]))return fail(s);
 s->working_len++;return 1;
}
int mxb_gl_tex_coord2f(MXBGLSurface*s,float u,float v){
 if(!s)return 0;
 if(!valid(u)||!valid(v))return fail(s);
 s->current_uv[0]=u;s->current_uv[1]=v;return 1;
}
static void tri(MXBGLSurface*s,size_t a,size_t b,size_t c){
 s->frame[s->frame_len++]=s->working[a];
 s->frame[s->frame_len++]=s->working[b];
 s->frame[s->frame_len++]=s->working[c];
}
int mxb_gl_end(MXBGLSurface*s){
 if(!s)return 0;
 if(!s->building)return fail(s);
 s->building=0;
 size_t n=s->working_len,triangles=0;
 if(s->begin_mode==MXB_GL_TRIANGLES){
  if(n%3u)return fail(s);
  triangles=n/3u;
 }else if(s->begin_mode==MXB_GL_QUADS){
  if(n%4u)return fail(s);
  triangles=(n/4u)*2u;
 }else triangles=n>=3u?n-2u:0u;
 if(triangles>(MXB_GL_MAX_OUTPUT-s->frame_len)/3u)return fail(s);
 if(s->begin_mode==MXB_GL_TRIANGLES){
  for(size_t i=0;i<n;i+=3u)tri(s,i,i+1u,i+2u);
 }else if(s->begin_mode==MXB_GL_QUADS){
  for(size_t i=0;i<n;i+=4u){tri(s,i,i+1u,i+2u);tri(s,i,i+2u,i+3u);}
 }else if(s->begin_mode==MXB_GL_TRIANGLE_FAN){
  for(size_t i=2;i<n;i++)tri(s,0,i-1u,i);
 }else{
  for(size_t i=2;i<n;i++){
   if(i&1u)tri(s,i-1u,i-2u,i);
   else tri(s,i-2u,i-1u,i);
  }
 }
 s->working_len=0;return 1;
}
int mxb_gl_load_matrixf(MXBGLSurface*s,const float*m){
 if(!s)return 0;
 if(s->building||!m)return fail(s);
 for(int i=0;i<16;i++)if(!valid(m[i]))return fail(s);
 __builtin_memcpy(selected(s),m,16u*sizeof(float));return 1;
}
int mxb_gl_mult_matrixf(MXBGLSurface*s,const float*m){
 if(!s)return 0;
 if(s->building||!m)return fail(s);
 for(int i=0;i<16;i++)if(!valid(m[i]))return fail(s);
 multiply(selected(s),m);return 1;
}
int mxb_gl_frustum(MXBGLSurface*s,float l,float r,float b,float t,float n,float f){
 if(!s)return 0;
 if(s->building||!valid(l)||!valid(r)||!valid(b)||!valid(t)||!valid(n)||!valid(f)||
    n<=0.0f||f<=0.0f||r==l||t==b||f==n)return fail(s);
 float m[16];__builtin_memset(m,0,sizeof(m));
 m[0]=(2.0f*n)/(r-l);m[5]=(2.0f*n)/(t-b);
 m[8]=(r+l)/(r-l);m[9]=(t+b)/(t-b);
 m[10]=-(f+n)/(f-n);m[11]=-1.0f;
 m[14]=-(2.0f*f*n)/(f-n);
 multiply(selected(s),m);return 1;
}
int mxb_gl_vertex3fv(MXBGLSurface*s,const float*xyz3){
 if(!s)return 0;
 if(!xyz3)return fail(s);
 return mxb_gl_vertex3f(s,xyz3[0],xyz3[1],xyz3[2]);
}
int mxb_gl_color3f(MXBGLSurface*s,float r,float g,float b){
 return mxb_gl_color4f(s,r,g,b,1.0f);
}
int mxb_gl_color3fv(MXBGLSurface*s,const float*rgb3){
 if(!s)return 0;
 if(!rgb3)return fail(s);
 return mxb_gl_color3f(s,rgb3[0],rgb3[1],rgb3[2]);
}
int mxb_gl_color4ubv(MXBGLSurface*s,const uint8_t*rgba4){
 if(!s)return 0;
 if(!rgba4)return fail(s);
 return mxb_gl_color4f(s,rgba4[0]/255.0f,rgba4[1]/255.0f,
                       rgba4[2]/255.0f,rgba4[3]/255.0f);
}
static int sym_eq(const char*a,const char*b){
 if(!a||!b)return 0;
 for(int i=0;i<64;i++){
  if(a[i]!=b[i])return 0;
  if(a[i]==0)return 1;
 }
 return 0;
}
int mxb_gl_dispatch_import(MXBGLSurface*s,const char*lib,const char*name,
                           unsigned word,const float*a,size_t n){
 if(!s)return 0;
 if(!sym_eq(lib,"OPENGL32.dll")||!name)return fail(s);
 if(sym_eq(name,"glBegin"))return mxb_gl_begin(s,word);
 if(sym_eq(name,"glEnd"))return mxb_gl_end(s);
 if(sym_eq(name,"glMatrixMode"))return mxb_gl_matrix_mode(s,word);
 if(sym_eq(name,"glLoadIdentity"))return mxb_gl_load_identity(s);
 if(sym_eq(name,"glVertex3f")||sym_eq(name,"glVertex3fv"))
  return (n==3u&&a)?mxb_gl_vertex3fv(s,a):fail(s);
 if(sym_eq(name,"glColor3f")||sym_eq(name,"glColor3fv"))
  return (n==3u&&a)?mxb_gl_color3fv(s,a):fail(s);
 if(sym_eq(name,"glColor4f"))
  return (n==4u&&a)?mxb_gl_color4f(s,a[0],a[1],a[2],a[3]):fail(s);
 if(sym_eq(name,"glOrtho"))
  return (n==6u&&a)?mxb_gl_ortho(s,a[0],a[1],a[2],a[3],a[4],a[5]):fail(s);
 if(sym_eq(name,"glFrustum"))
  return (n==6u&&a)?mxb_gl_frustum(s,a[0],a[1],a[2],a[3],a[4],a[5]):fail(s);
 if(sym_eq(name,"glLoadMatrixf"))
  return (n==16u&&a)?mxb_gl_load_matrixf(s,a):fail(s);
 if(sym_eq(name,"glMultMatrixf"))
  return (n==16u&&a)?mxb_gl_mult_matrixf(s,a):fail(s);
 /* Textures, lighting, vertex arrays, depth, and WGL are not yet supported.
  * Fail closed: never silently display a semantically invalid game frame. */
 return fail(s);
}
static MXBGLClientArray*client(MXBGLSurface*s,unsigned array){
 if(!s)return NULL;
 if(array==MXB_GL_VERTEX_ARRAY)return &s->vertex_array;
 if(array==MXB_GL_COLOR_ARRAY)return &s->color_array;
 if(array==MXB_GL_TEXTURE_COORD_ARRAY)return &s->texcoord_array;
 return NULL;
}
int mxb_gl_client_pointer(MXBGLSurface*s,unsigned array,
 unsigned components,unsigned type,unsigned stride,uint64_t pointer){
 MXBGLClientArray*c=client(s,array);
 if(!s)return 0;
 unsigned width=(type==MXB_GL_FLOAT?4u:type==MXB_GL_UNSIGNED_BYTE?1u:0u);
 if(!c||s->building||!pointer||!width||stride>4096u||
    (array==MXB_GL_VERTEX_ARRAY&&(components!=3u||type!=MXB_GL_FLOAT))||
    (array==MXB_GL_COLOR_ARRAY&&(components!=3u&&components!=4u))||
    (array==MXB_GL_TEXTURE_COORD_ARRAY&&(components!=2u||type!=MXB_GL_FLOAT))||
    (stride!=0u&&stride<components*width))return fail(s);
 c->guest_pointer=pointer;c->components=components;
 c->type=type;c->stride=stride;return 1;
}
int mxb_gl_client_enable(MXBGLSurface*s,unsigned array,int enabled){
 MXBGLClientArray*c=client(s,array);
 if(!s)return 0;
 if(!c||s->building)return fail(s);
 c->enabled=enabled!=0;return 1;
}
int mxb_gl_client_lookup(const MXBGLSurface*s,unsigned array,
 MXBGLClientArray*out){
 if(!s||!out)return 0;
 if(array==MXB_GL_VERTEX_ARRAY)*out=s->vertex_array;
 else if(array==MXB_GL_COLOR_ARRAY)*out=s->color_array;
 else if(array==MXB_GL_TEXTURE_COORD_ARRAY)*out=s->texcoord_array;
 else return 0;
 return 1;
}
int mxb_gl_current_color(const MXBGLSurface*s,float out[4]){
 if(!s||!out)return 0;
 __builtin_memcpy(out,s->current_color,4u*sizeof(float));return 1;
}
int mxb_gl_current_uv(const MXBGLSurface*s,float out[2]){
 if(!s||!out)return 0;
 __builtin_memcpy(out,s->current_uv,2u*sizeof(float));return 1;
}
void mxb_gl_abort(MXBGLSurface*s){
 if(s){s->building=0;s->working_len=0;}
}
size_t mxb_gl_vertex_count(const MXBGLSurface*s){return s?s->frame_len:0u;}
const MXBGLVertex*mxb_gl_vertices(const MXBGLSurface*s){return s?s->frame:NULL;}
unsigned mxb_gl_faults(const MXBGLSurface*s){return s?s->faults:0u;}
