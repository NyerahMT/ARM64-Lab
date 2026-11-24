#include "mxb_guest_crt.h"
static int same(const char*a,const char*b){
 if(!a||!b)return 0;
 for(unsigned i=0;i<48;i++){if(a[i]!=b[i])return 0;if(!a[i])return 1;}
 return 0;
}
int mxb_guest_heap_init(MXBGuestState *s,uint64_t base,uint8_t *backing,size_t capacity){
 if(!s || s->heap.capacity || !base || (base & 15u) || capacity < 16 ||
    !mxb_guest_map(&s->memory,base,backing,capacity,MXB_MEM_READ | MXB_MEM_WRITE))
  return 0;
 s->heap.base=base;
 s->heap.capacity=capacity;
 return 1;
}

/* A bounded first-fit allocator. The Win64 caller observes NULL on exhaustion,
 * including the fixed metadata limit. A zero-byte request owns a minimum slot. */
static uint64_t heap_alloc(MXBGuestHeap *heap,uint64_t size){
 if(heap->count == MXB_HEAP_SLOTS || size > UINT64_MAX - 15u)return 0;
 uint64_t length=size ? (size + 15u) & ~UINT64_C(15) : 16u;
 uint64_t offset=0;
 unsigned index=0;
 while(index < heap->count && length > heap->live[index].offset - offset){
  offset=heap->live[index].offset + heap->live[index].length;
  index++;
 }
 if(length > heap->capacity - offset)return 0;
 for(unsigned i=heap->count;i>index;i--)heap->live[i]=heap->live[i-1];
 heap->live[index].offset=offset;
 heap->live[index].length=length;
 heap->count++;
 return heap->base + offset;
}

static int heap_release(MXBGuestHeap *heap,uint64_t pointer){
 if(!pointer)return 1;
 for(unsigned i=0;i<heap->count;i++){
  if(pointer != heap->base + heap->live[i].offset)continue;
  for(unsigned j=i+1;j<heap->count;j++)heap->live[j-1]=heap->live[j];
  heap->count--;
  return 1;
 }
 return 0;
}

/* Scan the complete source before a copy can alter guest bytes. Including
 * the terminator also gives strrchr(s, 0) its required result. */
static int scan_string(const MXBGuestMemory *memory,uint64_t start,uint8_t key,
                       size_t *length,uint64_t *match){
 *match=0;
 for(size_t i=0;i<65536u;i++){
  uint8_t byte;
  if(i>UINT64_MAX-start || !mxb_guest_read(memory,start+i,&byte,1))return 0;
  if(byte==key)*match=start+i;
  if(!byte){*length=i+1;return 1;}
 }
 return 0;
}

int mxb_guest_file_bind(MXBGuestState*s,const char*name,const uint8_t*bytes,size_t size){
 if(!s||s->file.bytes||!name||!bytes||!size||size>64u*1024u*1024u)return 0;
 size_t i=0;
 for(;i<sizeof(s->file.name);i++){
  unsigned char v=(unsigned char)name[i];
  if(!v)break;
  if(v<32||v>126||v=='/'||v=='\\'||v==':')return 0;
 }
 if(!i||i==sizeof(s->file.name))return 0;
 for(size_t j=0;j<=i;j++)s->file.name[j]=name[j];
 s->file.bytes=bytes;s->file.length=size;
 return 1;
}
static int guest_string_eq(MXBGuestState*s,uint64_t va,const char*str){
 for(size_t i=0;i<64;i++){
  uint8_t v;
  if(i>UINT64_MAX-va||!mxb_guest_read(&s->memory,va+i,&v,1)||v!=(uint8_t)str[i])return 0;
  if(!v)return 1;
 }
 return 0;
}
/* Bounded, read-only data stream. No execution or platform authentication. */
static enum MXBGuestCRTStatus file_call(MXBGuestState*s,const char*name,uint64_t sp){
 MXBGuestReadFile*f=&s->file;
 uint64_t a=s->r[MXB_RCX],b=s->r[MXB_RDX],c=s->r[MXB_R8],d=s->r[MXB_R9],result=0;
 if(!f->bytes)return MXB_CRT_BAD_ARGUMENT;
 if(same(name,"fopen")){
  if(f->open||!guest_string_eq(s,a,f->name)||!guest_string_eq(s,b,"rb"))
   return MXB_CRT_BAD_ARGUMENT;
  f->position=0;f->open=1;f->opens++;result=MXB_GUEST_FILE_HANDLE;
 }else{
  int read=same(name,"fread");
  if(!f->open||(read?d:a)!=MXB_GUEST_FILE_HANDLE)return MXB_CRT_BAD_ARGUMENT;
  if(same(name,"fseek")){
   int64_t anchor=c==0?0:c==1?(int64_t)f->position:c==2?(int64_t)f->length:-1;
   int64_t offset=(int64_t)(int32_t)(uint32_t)b;
   int64_t pos=anchor+offset;
   if(anchor<0||pos<0||(uint64_t)pos>f->length)result=UINT32_MAX;
   else f->position=(uint64_t)pos;
   f->seeks++;
  }else if(same(name,"ftell")){
   result=f->position;f->tells++;
  }else if(read){
   if((b&&c>MXB_MEM_MAX_TRANSFER/b)||f->position>f->length)return MXB_CRT_BAD_ARGUMENT;
   uint64_t wanted=b*c,n=f->length-f->position;
   if(n>wanted)n=wanted;
   if(n>UINT64_MAX-a||(n&&a<sp+8&&sp<a+n)||n>64u*1024u*1024u-f->total_read)
    return MXB_CRT_BAD_ARGUMENT;
   if(n&&!mxb_guest_write(&s->memory,a,f->bytes+f->position,(size_t)n))
    return MXB_CRT_BAD_MEMORY;
   f->position+=n;f->total_read+=n;f->reads++;result=b?n/b:0;
  }else if(same(name,"fclose")){f->open=0;f->closes++;}
  else return MXB_CRT_UNSUPPORTED;
 }
 s->r[MXB_RAX]=result;s->r[MXB_RSP]=sp+8;s->completed_crt_calls++;
 return MXB_CRT_OK;
}
enum MXBGuestCRTStatus mxb_guest_crt_call(MXBGuestState*s,const char*library,
 const char*name,uint64_t expected_return){
 if(!s||s->fault)return MXB_CRT_BAD_ARGUMENT;
 if(!same(library,"MSVCR90.dll")&&!same(library,"msvcrt.dll"))
  return MXB_CRT_UNSUPPORTED;
 int fill=same(name,"memset"),copy=same(name,"memcpy"),move=same(name,"memmove");
 int allocate=same(name,"malloc"),release=same(name,"free");
 int string_copy=same(name,"strcpy"),find_last=same(name,"strrchr");
 int file=same(name,"fopen")||same(name,"fseek")||same(name,"ftell")||same(name,"fread")||same(name,"fclose");
 if(!fill&&!copy&&!move&&!allocate&&!release&&!string_copy&&!find_last&&!file)return MXB_CRT_UNSUPPORTED;
 uint64_t sp=s->r[MXB_RSP],n=s->r[MXB_R8],dst=s->r[MXB_RCX],src=s->r[MXB_RDX];
 if(!sp||(sp&15u)!=8u||sp>UINT64_MAX-40u||!expected_return)
  return MXB_CRT_BAD_STACK;
 uint8_t ret[8];uint64_t actual=0;
 if(!mxb_guest_read(&s->memory,sp,ret,8)||
    !mxb_guest_check(&s->memory,sp+8,32,MXB_MEM_WRITE))return MXB_CRT_BAD_STACK;
 for(unsigned i=0;i<8;i++)actual|=(uint64_t)ret[i]<<(8u*i);
 if(actual!=expected_return)return MXB_CRT_BAD_STACK;
 if(file)return file_call(s,name,sp);
 if(allocate || release){
  if(!s->heap.capacity)return MXB_CRT_BAD_MEMORY;
  if(allocate)s->r[MXB_RAX]=heap_alloc(&s->heap,dst);
  else if(!heap_release(&s->heap,dst))return MXB_CRT_BAD_ARGUMENT;
  s->r[MXB_RSP]=sp+8u;
  s->completed_crt_calls++;
  return MXB_CRT_OK;
 }
 if(string_copy || find_last){
  size_t length;uint64_t match;
  if(!scan_string(&s->memory,string_copy?src:dst,(uint8_t)src,&length,&match))
   return MXB_CRT_BAD_MEMORY;
  if(find_last){
   s->r[MXB_RAX]=match;s->r[MXB_RSP]=sp+8u;
   s->completed_crt_calls++;
  return MXB_CRT_OK;
  }
  n=length;copy=1;
 }
 if(n>MXB_MEM_MAX_TRANSFER||n>UINT64_MAX-dst)return MXB_CRT_BAD_ARGUMENT;
 /* Do not let a modeled call alter its own return slot. */
 if(n&&dst<sp+8&&sp<dst+n)return MXB_CRT_BAD_ARGUMENT;
 if(copy&&n&&((dst>=src&&dst-src<n)||(src>=dst&&src-dst<n)))
  return MXB_CRT_BAD_ARGUMENT; /* overlapping memcpy is undefined */
 int ok=fill?mxb_guest_fill(&s->memory,dst,(uint8_t)src,(size_t)n):
             mxb_guest_move(&s->memory,dst,src,(size_t)n);
 if(!ok)return MXB_CRT_BAD_MEMORY;
 s->r[MXB_RAX]=dst;s->r[MXB_RSP]=sp+8u;
 s->completed_crt_calls++;
  return MXB_CRT_OK;
}
int mxb_guest_crt_smoke(void){
 MXBGuestState s={0};uint8_t stack[64]={0},a[32],b[32];
 for(unsigned i=0;i<32;i++){a[i]=(uint8_t)i;b[i]=0;}
 const uint64_t sp=UINT64_C(0x700000008),base=UINT64_C(0x600000000);
 const uint64_t resume=UINT64_C(0x140001234);
 if(!mxb_guest_map(&s.memory,sp,stack,sizeof(stack),3)||
    !mxb_guest_map(&s.memory,base,a,32,3)||
    !mxb_guest_map(&s.memory,base+32,b,32,3))return 0;
 for(unsigned i=0;i<8;i++)stack[i]=(uint8_t)(resume>>(i*8u));
 s.r[MXB_RSP]=sp;s.r[MXB_RCX]=base+32;s.r[MXB_RDX]=base;s.r[MXB_R8]=32;
 if(mxb_guest_crt_call(&s,"MSVCR90.dll","memcpy",resume)!=MXB_CRT_OK||
    s.r[MXB_RAX]!=base+32||s.r[MXB_RSP]!=sp+8u)return 0;
 for(unsigned i=0;i<32;i++)if(b[i]!=i)return 0;
 s.r[MXB_RSP]=sp;s.r[MXB_RCX]=base+28;s.r[MXB_RDX]=0xab;s.r[MXB_R8]=8;
 if(mxb_guest_crt_call(&s,"MSVCR90.dll","memset",resume)!=MXB_CRT_OK)return 0;
 for(unsigned i=28;i<32;i++)if(a[i]!=0xab)return 0;
 for(unsigned i=0;i<4;i++)if(b[i]!=0xab)return 0;
 s.r[MXB_RSP]=sp;s.r[MXB_RCX]=base+1;s.r[MXB_RDX]=base;s.r[MXB_R8]=16;
 if(mxb_guest_crt_call(&s,"MSVCR90.dll","memcpy",resume)!=MXB_CRT_BAD_ARGUMENT||
    s.r[MXB_RSP]!=sp||a[1]!=1)return 0;
 if(mxb_guest_crt_call(&s,"MSVCR90.dll","memmove",resume)!=MXB_CRT_OK||
    a[1]!=0||a[16]!=15)return 0;
 s.r[MXB_RSP]=sp;s.r[MXB_RCX]=base+60;s.r[MXB_RDX]=1;s.r[MXB_R8]=8;
 if(mxb_guest_crt_call(&s,"MSVCR90.dll","memset",resume)!=MXB_CRT_BAD_MEMORY||
    s.r[MXB_RSP]!=sp||b[28]!=28)return 0;
 if(mxb_guest_crt_call(&s,"steam_api64.dll","SteamAPI_Init",resume)!=MXB_CRT_UNSUPPORTED||
    mxb_guest_crt_call(&s,"MSVCR90.dll","memset",resume+1)!=MXB_CRT_BAD_STACK)return 0;
 s.r[MXB_RCX]=UINT64_MAX;s.r[MXB_RDX]=0;s.r[MXB_R8]=0;
 if(mxb_guest_crt_call(&s,"MSVCR90.dll","memmove",resume)!=MXB_CRT_OK||
    s.r[MXB_RAX]!=UINT64_MAX)return 0;
 /* Copy a terminated string across two guest mappings, then find its
  * last character and terminator. Failed calls leave the return slot live. */
 a[30]='x';a[31]='y';b[0]='x';b[1]=0;
 s.r[MXB_RSP]=sp;s.r[MXB_RCX]=base+9;s.r[MXB_RDX]=base+30;
 if(mxb_guest_crt_call(&s,"MSVCR90.dll","strcpy",resume)!=MXB_CRT_OK ||
    a[9]!='x' || a[10]!='y' || a[11]!='x' || a[12])return 0;
 for(unsigned i=0;i<3;i++){
  const unsigned keys[3]={'x',0,'z'};
  const uint64_t expected[3]={base+11,base+12,0};
  s.r[MXB_RSP]=sp;s.r[MXB_RDX]=keys[i];
  if(mxb_guest_crt_call(&s,"MSVCR90.dll","strrchr",resume)!=MXB_CRT_OK ||
     s.r[MXB_RAX]!=expected[i])return 0;
 }
 s.r[MXB_RSP]=sp;s.r[MXB_RCX]=base+9;s.r[MXB_RDX]=base+63;b[31]='x';
 if(mxb_guest_crt_call(&s,"MSVCR90.dll","strcpy",resume)!=MXB_CRT_BAD_MEMORY ||
    s.r[MXB_RSP]!=sp || a[9]!='x')return 0;
 uint8_t arena[64];
 if(!mxb_guest_heap_init(&s,base+64,arena,sizeof(arena)) ||
    mxb_guest_heap_init(&s,base+128,arena,sizeof(arena)))return 0;
 const uint64_t sizes[]={0,17,16,1,UINT64_MAX};
 const uint64_t pointers[]={base+64,base+80,base+112,0,0};
 for(unsigned i=0;i<5;i++){
  s.r[MXB_RSP]=sp;s.r[MXB_RCX]=sizes[i];
  if(mxb_guest_crt_call(&s,"MSVCR90.dll","malloc",resume)!=MXB_CRT_OK ||
     s.r[MXB_RAX]!=pointers[i])return 0;
 }
 s.r[MXB_RSP]=sp;s.r[MXB_RCX]=base+81;
 if(mxb_guest_crt_call(&s,"MSVCR90.dll","free",resume)!=MXB_CRT_BAD_ARGUMENT ||
    s.heap.count!=3 || s.r[MXB_RSP]!=sp)return 0;
 s.r[MXB_RCX]=base+80;
 if(mxb_guest_crt_call(&s,"MSVCR90.dll","free",resume)!=MXB_CRT_OK)return 0;
 s.r[MXB_RSP]=sp;
 if(mxb_guest_crt_call(&s,"MSVCR90.dll","free",resume)!=MXB_CRT_BAD_ARGUMENT)return 0;
 s.r[MXB_RCX]=32;
 if(mxb_guest_crt_call(&s,"MSVCR90.dll","malloc",resume)!=MXB_CRT_OK ||
    s.r[MXB_RAX]!=base+80)return 0;
 /* Register actual immutable bytes, validate filename/mode and the complete
  * guest destination. Reject a second open, invalid handle and unsafe path. */
 static const uint8_t payload[]={1,2,3,4,5};
 static const char filename[]="owned.dat",mode[]="rb";
 if(!mxb_guest_file_bind(&s,filename,payload,sizeof(payload))||
    mxb_guest_file_bind(&s,"../unsafe",payload,sizeof(payload))||
    !mxb_guest_write(&s.memory,base,filename,sizeof(filename))||
    !mxb_guest_write(&s.memory,base+16,mode,sizeof(mode)))return 0;
 s.r[MXB_RSP]=sp;s.r[MXB_RCX]=base;s.r[MXB_RDX]=base+16;
 if(mxb_guest_crt_call(&s,"MSVCR90.dll","fopen",resume)!=MXB_CRT_OK||
    s.r[MXB_RAX]!=MXB_GUEST_FILE_HANDLE||!s.file.open)return 0;
 s.r[MXB_RSP]=sp;s.r[MXB_RCX]=MXB_GUEST_FILE_HANDLE;s.r[MXB_RDX]=0;s.r[MXB_R8]=2;
 if(mxb_guest_crt_call(&s,"MSVCR90.dll","fseek",resume)!=MXB_CRT_OK||s.file.position!=5)return 0;
 s.r[MXB_RSP]=sp;
 if(mxb_guest_crt_call(&s,"MSVCR90.dll","ftell",resume)!=MXB_CRT_OK||s.r[MXB_RAX]!=5)return 0;
 s.r[MXB_RSP]=sp;s.r[MXB_R8]=0;
 if(mxb_guest_crt_call(&s,"MSVCR90.dll","fseek",resume)!=MXB_CRT_OK||s.file.position)return 0;
 s.r[MXB_RSP]=sp;s.r[MXB_RCX]=base+63;s.r[MXB_RDX]=1;s.r[MXB_R8]=5;s.r[MXB_R9]=MXB_GUEST_FILE_HANDLE+1;
 if(mxb_guest_crt_call(&s,"MSVCR90.dll","fread",resume)!=MXB_CRT_BAD_ARGUMENT||s.file.position)return 0;
 s.r[MXB_R9]=MXB_GUEST_FILE_HANDLE;s.r[MXB_RCX]=base+28;s.r[MXB_RDX]=2;s.r[MXB_R8]=3;
 if(mxb_guest_crt_call(&s,"MSVCR90.dll","fread",resume)!=MXB_CRT_OK||s.r[MXB_RAX]!=2||
    a[28]!=1||a[31]!=4||b[0]!=5||s.file.position!=5||s.file.total_read!=5)return 0;
 s.r[MXB_RSP]=sp;s.r[MXB_RCX]=MXB_GUEST_FILE_HANDLE;
 if(mxb_guest_crt_call(&s,"MSVCR90.dll","fclose",resume)!=MXB_CRT_OK||s.file.open||
    s.file.opens!=1||s.file.seeks!=2||s.file.tells!=1||s.file.reads!=1||s.file.closes!=1)return 0;
 return 1;
}
