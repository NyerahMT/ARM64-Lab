#include "mxb_gl_win64_abi.h"

static int same(const char *a,const char *b){
 if(!a||!b)return 0;
 for(unsigned i=0;i<80u;i++){
  if(a[i]!=b[i])return 0;
  if(a[i]==0)return 1;
 }
 return 0;
}
static float xmm_float(uint64_t bits){
 uint32_t low=(uint32_t)bits;
 float f=0.0f;
 __builtin_memcpy(&f,&low,sizeof(f));
 return f;
}
static double xmm_double(uint64_t bits){
 double f=0.0;
 __builtin_memcpy(&f,&bits,sizeof(f));
 return f;
}
static int readable(MXBGLGuestRead cb,void*ctx,
                    uint64_t addr,void*dst,size_t bytes){
 if(!cb||!addr||bytes>128u||addr>UINT64_MAX-bytes)return 0;
 return cb(ctx,addr,dst,bytes)!=0;
}
static enum MXBGLGuestStatus rendered(int valid){
 return valid?MXB_GL_GUEST_OK:MXB_GL_GUEST_RENDER_REJECTED;
}

typedef struct {float vertex[3],color[4],uv[2];} MXBIndexedVertex;
static int read_at(MXBGLGuestRead cb,void*ctx,uint64_t base,uint64_t offset,
                   void*out,size_t bytes){
 if(!base||base>UINT64_MAX-offset)return 0;
 return readable(cb,ctx,base+offset,out,bytes);
}
static int good_mode(unsigned mode,unsigned count){
 if(count<3u||count>MXB_GL_MAX_INDEXED)return 0;
 switch(mode){
 case MXB_GL_TRIANGLES:return count%3u==0;
 case MXB_GL_QUADS:return count%4u==0;
 case MXB_GL_TRIANGLE_STRIP:
 case MXB_GL_TRIANGLE_FAN:return 1;
 default:return 0;
 }
}
static enum MXBGLGuestStatus draw_elements(MXBGLSurface*s,
 const MXBGLWin64Call*g,MXBGLGuestRead cb,void*ctx,int indexed){
 unsigned mode=(unsigned)g->rcx;
 unsigned count=(unsigned)(indexed?g->rdx:g->r8);
 unsigned type=(unsigned)g->r8;
 if(!good_mode(mode,count)||(indexed?g->rdx:g->r8)!=(uint64_t)count||
    (indexed&&(type!=MXB_GL_UNSIGNED_SHORT&&type!=MXB_GL_UNSIGNED_INT))||
    (!indexed&&(g->rdx>65535u||g->rdx+count>65536u)))
  return MXB_GL_GUEST_RENDER_REJECTED;
 MXBGLClientArray vertex,color,texcoord;
 if(!mxb_gl_client_lookup(s,MXB_GL_VERTEX_ARRAY,&vertex)||
    !mxb_gl_client_lookup(s,MXB_GL_COLOR_ARRAY,&color)||
    !mxb_gl_client_lookup(s,MXB_GL_TEXTURE_COORD_ARRAY,&texcoord)||
    !vertex.enabled||!vertex.guest_pointer||
    vertex.components!=3u||vertex.type!=MXB_GL_FLOAT)
  return MXB_GL_GUEST_RENDER_REJECTED;
 float initial[4],initial_uv[2];
 if(!mxb_gl_current_color(s,initial)||!mxb_gl_current_uv(s,initial_uv))return MXB_GL_GUEST_RENDER_REJECTED;
 /* Stage every guest pointer read before starting any renderer primitive. */
 MXBIndexedVertex out[MXB_GL_MAX_INDEXED];
 unsigned index_size=(type==MXB_GL_UNSIGNED_SHORT?2u:4u);
 unsigned pos_stride=vertex.stride?vertex.stride:vertex.components*4u;
 unsigned col_stride=color.stride?color.stride:
  color.components*(color.type==MXB_GL_FLOAT?4u:1u);
 for(unsigned i=0;i<count;i++){
  uint32_t index=indexed?0u:(uint32_t)(g->rdx+i);
  if(indexed&&index_size==2u){
   uint16_t short_index=0;
   if(!read_at(cb,ctx,g->r9,(uint64_t)i*2u,&short_index,2u))
    return MXB_GL_GUEST_UNMAPPED_POINTER;
   index=short_index;
  }else if(indexed&&!read_at(cb,ctx,g->r9,(uint64_t)i*4u,&index,4u))
   return MXB_GL_GUEST_UNMAPPED_POINTER;
  if(index>65535u)return MXB_GL_GUEST_RENDER_REJECTED;
  if(!read_at(cb,ctx,vertex.guest_pointer,(uint64_t)index*pos_stride,
              out[i].vertex,sizeof(out[i].vertex)))
   return MXB_GL_GUEST_UNMAPPED_POINTER;
  for(unsigned k=0;k<3u;k++)
   if(!__builtin_isfinite(out[i].vertex[k]))
    return MXB_GL_GUEST_RENDER_REJECTED;
  __builtin_memcpy(out[i].color,initial,sizeof(initial));
  __builtin_memcpy(out[i].uv,initial_uv,sizeof(initial_uv));
  if(texcoord.enabled){
   if(texcoord.type!=MXB_GL_FLOAT||texcoord.components!=2u||!texcoord.guest_pointer)
    return MXB_GL_GUEST_RENDER_REJECTED;
   unsigned uv_stride=texcoord.stride?texcoord.stride:8u;
   if(!read_at(cb,ctx,texcoord.guest_pointer,(uint64_t)index*uv_stride,
               out[i].uv,sizeof(out[i].uv)))return MXB_GL_GUEST_UNMAPPED_POINTER;
   if(!__builtin_isfinite(out[i].uv[0])||!__builtin_isfinite(out[i].uv[1]))
    return MXB_GL_GUEST_RENDER_REJECTED;
  }
  if(color.enabled){
   if(!color.guest_pointer||
      (color.components!=3u&&color.components!=4u))
    return MXB_GL_GUEST_RENDER_REJECTED;
   if(color.type==MXB_GL_UNSIGNED_BYTE){
    uint8_t value[4]={255u,255u,255u,255u};
    if(!read_at(cb,ctx,color.guest_pointer,(uint64_t)index*col_stride,
                value,color.components))
     return MXB_GL_GUEST_UNMAPPED_POINTER;
    for(unsigned k=0;k<color.components;k++)
     out[i].color[k]=value[k]/255.0f;
   }else if(color.type==MXB_GL_FLOAT){
    if(!read_at(cb,ctx,color.guest_pointer,(uint64_t)index*col_stride,
                out[i].color,color.components*4u))
     return MXB_GL_GUEST_UNMAPPED_POINTER;
    if(color.components==3u)out[i].color[3]=1.0f;
   }else return MXB_GL_GUEST_RENDER_REJECTED;
   for(unsigned k=0;k<4u;k++)
    if(!__builtin_isfinite(out[i].color[k]))
     return MXB_GL_GUEST_RENDER_REJECTED;
  }
 }
 if(!mxb_gl_begin(s,mode))return MXB_GL_GUEST_RENDER_REJECTED;
 int ok=1;
 for(unsigned i=0;i<count;i++){
  if(!mxb_gl_tex_coord2f(s,out[i].uv[0],out[i].uv[1])||
     !mxb_gl_color4f(s,out[i].color[0],out[i].color[1],
                   out[i].color[2],out[i].color[3])||
     !mxb_gl_vertex3f(s,out[i].vertex[0],out[i].vertex[1],
                     out[i].vertex[2])){
   ok=0;break;
  }
 }
 if(ok)ok=mxb_gl_end(s);
 if(!ok)mxb_gl_abort(s);
 if(!mxb_gl_tex_coord2f(s,initial_uv[0],initial_uv[1])||
    !mxb_gl_color4f(s,initial[0],initial[1],initial[2],initial[3]))
  return MXB_GL_GUEST_RENDER_REJECTED;
 return ok?MXB_GL_GUEST_OK:MXB_GL_GUEST_RENDER_REJECTED;
}

enum MXBGLGuestStatus mxb_gl_dispatch_win64(
 MXBGLSurface*s,const char*library,const char*name,
 const MXBGLWin64Call*g,MXBGLGuestRead read_guest,void*ctx){
 if(!s||!library||!name||!g||((g->rsp&15u)!=8u)||!g->rsp)
  return MXB_GL_GUEST_INVALID_STATE;
 if(!same(library,"OPENGL32.dll"))
  return MXB_GL_GUEST_UNSUPPORTED;
 if(same(name,"glEnableClientState")||same(name,"glDisableClientState"))
  return rendered(mxb_gl_client_enable(s,(unsigned)g->rcx,
                        same(name,"glEnableClientState")));
 if(same(name,"glVertexPointer")||same(name,"glColorPointer")||
    same(name,"glTexCoordPointer"))
  return rendered(mxb_gl_client_pointer(s,
    same(name,"glVertexPointer")?MXB_GL_VERTEX_ARRAY:
    same(name,"glColorPointer")?MXB_GL_COLOR_ARRAY:MXB_GL_TEXTURE_COORD_ARRAY,
    (unsigned)g->rcx,(unsigned)g->rdx,(unsigned)g->r8,g->r9));
 if(same(name,"glDrawElements")||same(name,"glDrawArrays"))
  return draw_elements(s,g,read_guest,ctx,same(name,"glDrawElements"));
 if(same(name,"glTexCoord2fv")){
  float uv[2];
  if(!readable(read_guest,ctx,g->rcx,uv,sizeof(uv)))
   return MXB_GL_GUEST_UNMAPPED_POINTER;
  return rendered(mxb_gl_tex_coord2f(s,uv[0],uv[1]));
 }
 if(same(name,"glBegin")||same(name,"glMatrixMode"))
  return rendered(mxb_gl_dispatch_import(s,library,name,(unsigned)g->rcx,0,0));
 if(same(name,"glEnd")||same(name,"glLoadIdentity"))
  return rendered(mxb_gl_dispatch_import(s,library,name,0,0,0));

 if(same(name,"glVertex3f")||same(name,"glColor3f")||same(name,"glColor4f")){
  float args[4]={0.0f,0.0f,0.0f,0.0f};
  size_t count=same(name,"glColor4f")?4u:3u;
  for(size_t i=0;i<count;i++)args[i]=xmm_float(g->xmm_low64[i]);
  return rendered(mxb_gl_dispatch_import(s,library,name,0,args,count));
 }

 if(same(name,"glVertex3fv")||same(name,"glColor3fv")||
    same(name,"glLoadMatrixf")||same(name,"glMultMatrixf")){
  float args[16]={0};
  size_t count=(same(name,"glLoadMatrixf")||same(name,"glMultMatrixf"))?16u:3u;
  if(!readable(read_guest,ctx,g->rcx,args,count*sizeof(float)))
   return MXB_GL_GUEST_UNMAPPED_POINTER;
  return rendered(mxb_gl_dispatch_import(s,library,name,0,args,count));
 }
 if(same(name,"glColor4ubv")){
  uint8_t rgba[4];
  if(!readable(read_guest,ctx,g->rcx,rgba,sizeof(rgba)))
   return MXB_GL_GUEST_UNMAPPED_POINTER;
  return rendered(mxb_gl_color4ubv(s,rgba));
 }
 if(same(name,"glOrtho")||same(name,"glFrustum")){
  /* x64 Windows: 4 double args in XMM0..XMM3; 5th and 6th on
   * caller-allocated stack after return address and 32B shadow. */
  double args64[6];
  float args[6];
  for(unsigned i=0;i<4u;i++)args64[i]=xmm_double(g->xmm_low64[i]);
  if(g->rsp>UINT64_MAX-0x38u ||
     !readable(read_guest,ctx,g->rsp+0x28u,&args64[4],8u)||
     !readable(read_guest,ctx,g->rsp+0x30u,&args64[5],8u))
   return MXB_GL_GUEST_UNMAPPED_POINTER;
  for(unsigned i=0;i<6u;i++)args[i]=(float)args64[i];
  return rendered(mxb_gl_dispatch_import(s,library,name,0,args,6u));
 }
 /* Textures, WGL, lighting, normal/texcoord arrays etc. not implemented.
  * Never return success simply because an import exists in the original IAT. */
 return MXB_GL_GUEST_UNSUPPORTED;
}
