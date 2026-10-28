#include "mxb_gl_texture.h"
extern void *calloc(size_t,size_t);
extern void free(void *);

typedef struct {
 uint32_t id;
 uint16_t width,height;
 uint8_t *rgba;
} Texture;
struct MXBGLTextures {
 Texture slots[MXB_GL_MAX_TEXTURES];
 uint32_t current,next_name;
 unsigned enabled,unpack_alignment,filter;
};
static int same(const char*a,const char*b){
 if(!a||!b)return 0;
 for(unsigned i=0;i<80u;i++){
  if(a[i]!=b[i])return 0;
  if(a[i]==0)return 1;
 }return 0;
}
static int read_guest(MXBGLGuestRead read,void*ctx,uint64_t base,
                      uint64_t offset,void*out,size_t size){
 if(!read||!base||base>UINT64_MAX-offset||size>128u||
    base+offset>UINT64_MAX-size)return 0;
 return read(ctx,base+offset,out,size)!=0;
}
static int write_guest(MXBGLGuestWrite write,void*ctx,uint64_t addr,
                       const void*src,size_t size){
 if(!write||!addr||addr>UINT64_MAX-size||size>128u)return 0;
 return write(ctx,addr,src,size)!=0;
}
static int stack(const MXBGLWin64Call*g,MXBGLGuestRead cb,void*ctx,
                 unsigned arg_num,uint64_t*out){
 if(arg_num<5u||arg_num>9u||g->rsp>UINT64_MAX-(8u*arg_num))
  return 0;
 /* Fifth Win64 argument is [callee RSP+0x28]. */
 return read_guest(cb,ctx,g->rsp,(uint64_t)arg_num*8u,out,8u);
}
static Texture* find(MXBGLTextures*t,uint32_t name){
 for(unsigned i=0;i<MXB_GL_MAX_TEXTURES;i++)
  if(t->slots[i].id==name)return &t->slots[i];
 return 0;
}
static Texture* ensure(MXBGLTextures*t,uint32_t name){
 Texture*x=find(t,name);if(x)return x;
 for(unsigned i=0;i<MXB_GL_MAX_TEXTURES;i++)
  if(!t->slots[i].id){t->slots[i].id=name;return &t->slots[i];}
 return 0;
}
MXBGLTextures*mxb_tex_create(void){
 MXBGLTextures*t=(MXBGLTextures*)calloc(1,sizeof(*t));
 if(t)mxb_tex_reset(t);
 return t;
}
void mxb_tex_reset(MXBGLTextures*t){
 if(!t)return;
 for(unsigned i=0;i<MXB_GL_MAX_TEXTURES;i++)
  free(t->slots[i].rgba);
 __builtin_memset(t,0,sizeof(*t));
 t->next_name=1u;t->unpack_alignment=4u;t->filter=MXB_GL_NEAREST;
}
void mxb_tex_destroy(MXBGLTextures*t){
 if(t){mxb_tex_reset(t);free(t);}
}
int mxb_tex_enabled(const MXBGLTextures*t){return t&&t->enabled;}
const uint8_t*mxb_tex_current_rgba(const MXBGLTextures*t,unsigned*w,unsigned*h){
 if(w)*w=0u;
 if(h)*h=0u;
 if(!t||!t->enabled||!t->current)return 0;
 for(unsigned i=0;i<MXB_GL_MAX_TEXTURES;i++){
  const Texture*x=&t->slots[i];
  if(x->id==t->current&&x->rgba){
   if(w)*w=x->width;
   if(h)*h=x->height;
   return x->rgba;
  }
 }
 return 0;
}
enum MXBGLGuestStatus mxb_tex_dispatch_win64(
 MXBGLTextures*t,const char*lib,const char*name,const MXBGLWin64Call*g,
 MXBGLGuestRead read,MXBGLGuestWrite write,void*ctx){
 if(!t||!g||!name||!lib||!g->rsp||(g->rsp&15u)!=8u)
  return MXB_GL_GUEST_INVALID_STATE;
 if(!same(lib,"OPENGL32.dll"))return MXB_GL_GUEST_UNSUPPORTED;
 if(same(name,"glEnable")||same(name,"glDisable")){
  if(g->rcx!=MXB_GL_TEXTURE_2D)return MXB_GL_GUEST_UNSUPPORTED;
  t->enabled=same(name,"glEnable");return MXB_GL_GUEST_OK;
 }
 if(same(name,"glPixelStorei")){
  if(g->rcx!=MXB_GL_UNPACK_ALIGNMENT||(g->rdx!=1u&&g->rdx!=4u))
   return MXB_GL_GUEST_UNSUPPORTED;
  t->unpack_alignment=(unsigned)g->rdx;return MXB_GL_GUEST_OK;
 }
 if(same(name,"glTexParameteri")){
  if(g->rcx!=MXB_GL_TEXTURE_2D||
     (g->rdx!=MXB_GL_TEXTURE_MAG_FILTER&&g->rdx!=MXB_GL_TEXTURE_MIN_FILTER)||
     (g->r8!=MXB_GL_NEAREST&&g->r8!=MXB_GL_LINEAR))
   return MXB_GL_GUEST_UNSUPPORTED;
  /* The prototype uses nearest filtering. Do not claim support for linear. */
  if(g->r8!=MXB_GL_NEAREST)return MXB_GL_GUEST_UNSUPPORTED;
  t->filter=(unsigned)g->r8;return MXB_GL_GUEST_OK;
 }
 if(same(name,"glBindTexture")){
  if(g->rcx!=MXB_GL_TEXTURE_2D||g->rdx>UINT32_MAX)
   return MXB_GL_GUEST_UNSUPPORTED;
  uint32_t id=(uint32_t)g->rdx;
  if(id&&!ensure(t,id))return MXB_GL_GUEST_RENDER_REJECTED;
  t->current=id;return MXB_GL_GUEST_OK;
 }
 if(same(name,"glGenTextures")){
  if(g->rcx==0||g->rcx>MXB_GL_MAX_TEXTURES)return MXB_GL_GUEST_UNSUPPORTED;
  uint32_t names[MXB_GL_MAX_TEXTURES];
  unsigned n=(unsigned)g->rcx;
  uint32_t cursor=t->next_name;
  for(unsigned i=0;i<n;i++){
   while(cursor&&find(t,cursor))cursor++;
   if(!cursor||!ensure(t,cursor))return MXB_GL_GUEST_RENDER_REJECTED;
   names[i]=cursor++;
  }
  if(!write_guest(write,ctx,g->rdx,names,n*4u)){
   for(unsigned i=0;i<n;i++){
    Texture*x=find(t,names[i]);if(x){x->id=0;}
   }
   return MXB_GL_GUEST_UNMAPPED_POINTER;
  }
  t->next_name=cursor;return MXB_GL_GUEST_OK;
 }
 if(same(name,"glDeleteTextures")){
  if(g->rcx>MXB_GL_MAX_TEXTURES)return MXB_GL_GUEST_UNSUPPORTED;
  for(unsigned i=0;i<(unsigned)g->rcx;i++){
   uint32_t id=0;
   if(!read_guest(read,ctx,g->rdx,(uint64_t)i*4u,&id,4u))
    return MXB_GL_GUEST_UNMAPPED_POINTER;
   Texture*x=find(t,id);
   if(x){free(x->rgba);__builtin_memset(x,0,sizeof(*x));}
   if(t->current==id)t->current=0;
  }
  return MXB_GL_GUEST_OK;
 }
 if(same(name,"glTexImage2D")){
  /* 9 Win64 integer args. Windows CALL entry RSP+0x28..0x48. */
  uint64_t height=0,border=0,format=0,type=0,pixels=0;
  if(!stack(g,read,ctx,5,&height)||!stack(g,read,ctx,6,&border)||
     !stack(g,read,ctx,7,&format)||!stack(g,read,ctx,8,&type)||
     !stack(g,read,ctx,9,&pixels))
   return MXB_GL_GUEST_UNMAPPED_POINTER;
  if(g->rcx!=MXB_GL_TEXTURE_2D||g->rdx!=0||
     (g->r8!=3&&g->r8!=4&&g->r8!=MXB_GL_RGB&&g->r8!=MXB_GL_RGBA)||
     !g->r9||g->r9>MXB_GL_MAX_TEX_DIM||
     !height||height>MXB_GL_MAX_TEX_DIM||border!=0||
     (format!=MXB_GL_RGB&&format!=MXB_GL_RGBA)||
     type!=MXB_GL_UNSIGNED_BYTE||!pixels||!t->current)
   return MXB_GL_GUEST_UNSUPPORTED;
  Texture*x=find(t,t->current);
  if(!x)return MXB_GL_GUEST_RENDER_REJECTED;
  unsigned w=(unsigned)g->r9,h=(unsigned)height;
  unsigned bpp=format==MXB_GL_RGB?3u:4u;
  unsigned row=w*bpp;
  unsigned aligned=(row+t->unpack_alignment-1u)&~(t->unpack_alignment-1u);
  uint8_t*rgba=(uint8_t*)calloc((size_t)w*h,4u);
  if(!rgba)return MXB_GL_GUEST_RENDER_REJECTED;
  uint8_t chunk[128];
  for(unsigned y=0;y<h;y++){
   for(unsigned start_byte=0;start_byte<row;){
    unsigned bytes=row-start_byte;
    if(bytes>sizeof(chunk))bytes=sizeof(chunk);
    if(!read_guest(read,ctx,pixels,(uint64_t)y*aligned+start_byte,chunk,bytes)){
     free(rgba);return MXB_GL_GUEST_UNMAPPED_POINTER;
    }
    /* Writing RGB->RGBA must preserve triples that span chunks.
     * Stage the row as RGBA through byte-offset tracking, no overreads. */
    for(unsigned i=0;i<bytes;i++){
     unsigned source_byte=start_byte+i;
     unsigned pixel=source_byte/bpp,channel=source_byte%bpp;
     rgba[((size_t)y*w+pixel)*4u+channel]=chunk[i];
    }
    start_byte+=bytes;
   }
   if(bpp==3u)for(unsigned xx=0;xx<w;xx++)rgba[((size_t)y*w+xx)*4u+3u]=255u;
  }
  free(x->rgba);
  x->rgba=rgba;x->width=(uint16_t)w;x->height=(uint16_t)h;
  return MXB_GL_GUEST_OK;
 }
 return MXB_GL_GUEST_UNSUPPORTED;
}
