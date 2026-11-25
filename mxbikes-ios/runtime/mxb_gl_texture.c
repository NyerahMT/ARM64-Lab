#include "mxb_gl_texture.h"
extern void *calloc(size_t,size_t);
extern void free(void *);

typedef struct {
 uint32_t id;
 uint16_t width,height;
 unsigned rgb_storage;
 uint8_t *rgba;
} Texture;
struct MXBGLTextures {
 Texture slots[MXB_GL_MAX_TEXTURES];
 uint32_t current,next_name;
 unsigned enabled,unpack_alignment,filter;
 size_t storage_bytes;
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
 if(!name)return 0;
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
size_t mxb_tex_storage_bytes(const MXBGLTextures*t){return t?t->storage_bytes:0u;}
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
/* Stage guest pixels before changing any texture; a failed late read is atomic. */
static enum MXBGLGuestStatus stage_pixels(uint8_t*rgba,unsigned w,unsigned h,
 unsigned format,unsigned alignment,unsigned rgb_storage,uint64_t pixels,
 MXBGLGuestRead read,void*ctx){
 unsigned bpp=format==MXB_GL_RGB?3u:4u;
 unsigned row=w*bpp,aligned=(row+alignment-1u)&~(alignment-1u);
 uint8_t chunk[128];
 for(unsigned y=0;y<h;y++){
  for(unsigned start=0;pixels&&start<row;){
   unsigned bytes=row-start;
   if(bytes>sizeof(chunk))bytes=sizeof(chunk);
   if(!read_guest(read,ctx,pixels,(uint64_t)y*aligned+start,chunk,bytes))
    return MXB_GL_GUEST_UNMAPPED_POINTER;
   for(unsigned i=0;i<bytes;i++){
    unsigned source=start+i;
    rgba[((size_t)y*w+source/bpp)*4u+source%bpp]=chunk[i];
   }
   start+=bytes;
  }
  if(bpp==3u||rgb_storage)
   for(unsigned xx=0;xx<w;xx++)rgba[((size_t)y*w+xx)*4u+3u]=255u;
 }
 return MXB_GL_GUEST_OK;
}
enum MXBGLGuestStatus mxb_tex_dispatch_win64(
 MXBGLTextures*t,const char*lib,const char*name,const MXBGLWin64Call*g,
 MXBGLGuestRead read,MXBGLGuestWrite write,void*ctx){
 if(!t||!g||!name||!lib||!g->rsp||(g->rsp&15u)!=8u)
  return MXB_GL_GUEST_INVALID_STATE;
 if(!same(lib,"OPENGL32.dll"))return MXB_GL_GUEST_UNSUPPORTED;
 /* GL scalar arguments are 32-bit; unused high register bits are unspecified
  * by Win64. Keep actual guest pointers at full 64-bit width. */
 uint32_t a=(uint32_t)g->rcx,b=(uint32_t)g->rdx,c=(uint32_t)g->r8,d=(uint32_t)g->r9;
 if(same(name,"glEnable")||same(name,"glDisable")){
  if(a!=MXB_GL_TEXTURE_2D)return MXB_GL_GUEST_UNSUPPORTED;
  t->enabled=same(name,"glEnable");return MXB_GL_GUEST_OK;
 }
 if(same(name,"glPixelStorei")){
  if(a!=MXB_GL_UNPACK_ALIGNMENT||(b!=1u&&b!=2u&&b!=4u&&b!=8u))
   return MXB_GL_GUEST_UNSUPPORTED;
  t->unpack_alignment=b;return MXB_GL_GUEST_OK;
 }
 if(same(name,"glTexParameteri")){
  if(a!=MXB_GL_TEXTURE_2D||
     (b!=MXB_GL_TEXTURE_MAG_FILTER&&b!=MXB_GL_TEXTURE_MIN_FILTER)||
     (c!=MXB_GL_NEAREST&&c!=MXB_GL_LINEAR))
   return MXB_GL_GUEST_UNSUPPORTED;
  /* The prototype uses nearest filtering. Do not claim support for linear. */
  if(c!=MXB_GL_NEAREST)return MXB_GL_GUEST_UNSUPPORTED;
  t->filter=c;return MXB_GL_GUEST_OK;
 }
 if(same(name,"glBindTexture")){
  if(a!=MXB_GL_TEXTURE_2D)return MXB_GL_GUEST_UNSUPPORTED;
  uint32_t id=b;
  if(id&&!ensure(t,id))return MXB_GL_GUEST_RENDER_REJECTED;
  t->current=id;return MXB_GL_GUEST_OK;
 }
 if(same(name,"glGenTextures")){
  if(a>MXB_GL_MAX_TEXTURE_NAMES_PER_CALL)return MXB_GL_GUEST_UNSUPPORTED;
  if(!a)return MXB_GL_GUEST_OK;
  unsigned free_count=0;
  for(unsigned i=0;i<MXB_GL_MAX_TEXTURES;i++)if(!t->slots[i].id)free_count++;
  if(a>free_count)return MXB_GL_GUEST_RENDER_REJECTED;
  uint32_t names[MXB_GL_MAX_TEXTURE_NAMES_PER_CALL],cursor=t->next_name;
  for(unsigned i=0;i<a;i++){
   while(cursor&&find(t,cursor))cursor++;
   if(!cursor)return MXB_GL_GUEST_RENDER_REJECTED;
   names[i]=cursor++;
  }
  /* No internal name reservation occurs unless the whole output is writable. */
  if(!write_guest(write,ctx,g->rdx,names,a*4u))return MXB_GL_GUEST_UNMAPPED_POINTER;
  for(unsigned i=0;i<a;i++)(void)ensure(t,names[i]);
  t->next_name=cursor;return MXB_GL_GUEST_OK;
 }
 if(same(name,"glDeleteTextures")){
  if(a>MXB_GL_MAX_TEXTURE_NAMES_PER_CALL)return MXB_GL_GUEST_UNSUPPORTED;
  if(!a)return MXB_GL_GUEST_OK;
  uint32_t names[MXB_GL_MAX_TEXTURE_NAMES_PER_CALL];
  if(!read_guest(read,ctx,g->rdx,0,names,a*4u))return MXB_GL_GUEST_UNMAPPED_POINTER;
  for(unsigned i=0;i<a;i++){
   uint32_t id=names[i];
   Texture*x=find(t,id);
   if(x){
    t->storage_bytes-=(size_t)x->width*x->height*4u;
    free(x->rgba);__builtin_memset(x,0,sizeof(*x));
   }
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
  height=(uint32_t)height;border=(uint32_t)border;
  format=(uint32_t)format;type=(uint32_t)type;
  if(a!=MXB_GL_TEXTURE_2D||b!=0||
     (c!=3&&c!=4&&c!=MXB_GL_RGB&&c!=MXB_GL_RGBA)||
     !d||d>MXB_GL_MAX_TEX_DIM||
     !height||height>MXB_GL_MAX_TEX_DIM||border!=0||
     (format!=MXB_GL_RGB&&format!=MXB_GL_RGBA)||
     type!=MXB_GL_UNSIGNED_BYTE||!t->current)
   return MXB_GL_GUEST_UNSUPPORTED;
  Texture*x=find(t,t->current);
  if(!x)return MXB_GL_GUEST_RENDER_REJECTED;
  unsigned w=d,h=(unsigned)height;
  size_t old_bytes=(size_t)x->width*x->height*4u,new_bytes=(size_t)w*h*4u;
  if(new_bytes>MXB_GL_MAX_TEX_BYTES-(t->storage_bytes-old_bytes))return MXB_GL_GUEST_RENDER_REJECTED;
  unsigned rgb_storage=c==3u||c==MXB_GL_RGB;
  uint8_t*rgba=(uint8_t*)calloc((size_t)w*h,4u);
  if(!rgba)return MXB_GL_GUEST_RENDER_REJECTED;
  enum MXBGLGuestStatus status=stage_pixels(rgba,w,h,(unsigned)format,
   t->unpack_alignment,rgb_storage,pixels,read,ctx);
  if(status){free(rgba);return status;}
  free(x->rgba);
  t->storage_bytes=t->storage_bytes-old_bytes+new_bytes;
  x->rgba=rgba;x->width=(uint16_t)w;x->height=(uint16_t)h;
  x->rgb_storage=rgb_storage;
  return MXB_GL_GUEST_OK;
 }
 if(same(name,"glTexSubImage2D")){
  /* target, level, xoffset, yoffset, width, height, format, type, pixels */
  uint64_t width=0,height=0,format=0,type=0,pixels=0;
  if(!stack(g,read,ctx,5,&width)||!stack(g,read,ctx,6,&height)||
     !stack(g,read,ctx,7,&format)||!stack(g,read,ctx,8,&type)||
     !stack(g,read,ctx,9,&pixels))return MXB_GL_GUEST_UNMAPPED_POINTER;
  width=(uint32_t)width;height=(uint32_t)height;
  format=(uint32_t)format;type=(uint32_t)type;
  if(a!=MXB_GL_TEXTURE_2D||b!=0||!t->current||
     (format!=MXB_GL_RGB&&format!=MXB_GL_RGBA)||
     type!=MXB_GL_UNSIGNED_BYTE)return MXB_GL_GUEST_UNSUPPORTED;
  Texture*x=find(t,t->current);
  if(!x||!x->rgba)return MXB_GL_GUEST_RENDER_REJECTED;
  /* Unsigned bounds also reject negative GLint/GLsizei and avoid overflow. */
  if(c>x->width||d>x->height||width>x->width-c||height>x->height-d)
   return MXB_GL_GUEST_UNSUPPORTED;
  if(!width||!height)return MXB_GL_GUEST_OK;
  if(!pixels)return MXB_GL_GUEST_UNMAPPED_POINTER;
  unsigned w=(unsigned)width,h=(unsigned)height;
  uint8_t*rgba=(uint8_t*)calloc((size_t)w*h,4u);
  if(!rgba)return MXB_GL_GUEST_RENDER_REJECTED;
  enum MXBGLGuestStatus status=stage_pixels(rgba,w,h,(unsigned)format,
   t->unpack_alignment,x->rgb_storage,pixels,read,ctx);
  if(!status)for(unsigned y=0;y<h;y++)
   __builtin_memcpy(x->rgba+((size_t)(d+y)*x->width+c)*4u,
                    rgba+(size_t)y*w*4u,(size_t)w*4u);
  free(rgba);
  return status;
 }
 return MXB_GL_GUEST_UNSUPPORTED;
}
