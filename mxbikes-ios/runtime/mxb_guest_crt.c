#include "mxb_guest_crt.h"
static int same(const char*a,const char*b){
 if(!a||!b)return 0;
 for(unsigned i=0;i<48;i++){if(a[i]!=b[i])return 0;if(!a[i])return 1;}
 return 0;
}
enum MXBGuestCRTStatus mxb_guest_crt_call(MXBGuestState*s,const char*library,
 const char*name,uint64_t expected_return){
 if(!s||s->fault)return MXB_CRT_BAD_ARGUMENT;
 if(!same(library,"MSVCR90.dll")&&!same(library,"msvcrt.dll"))
  return MXB_CRT_UNSUPPORTED;
 int fill=same(name,"memset"),copy=same(name,"memcpy"),move=same(name,"memmove");
 if(!fill&&!copy&&!move)return MXB_CRT_UNSUPPORTED;
 uint64_t sp=s->r[MXB_RSP],n=s->r[MXB_R8],dst=s->r[MXB_RCX],src=s->r[MXB_RDX];
 if(!sp||(sp&15u)!=8u||sp>UINT64_MAX-40u||!expected_return)
  return MXB_CRT_BAD_STACK;
 uint8_t ret[8];uint64_t actual=0;
 if(!mxb_guest_read(&s->memory,sp,ret,8)||
    !mxb_guest_check(&s->memory,sp+8,32,MXB_MEM_WRITE))return MXB_CRT_BAD_STACK;
 for(unsigned i=0;i<8;i++)actual|=(uint64_t)ret[i]<<(8u*i);
 if(actual!=expected_return)return MXB_CRT_BAD_STACK;
 if(n>MXB_MEM_MAX_TRANSFER||n>UINT64_MAX-dst)return MXB_CRT_BAD_ARGUMENT;
 /* Do not let a modeled call alter its own return slot. */
 if(n&&dst<sp+8&&sp<dst+n)return MXB_CRT_BAD_ARGUMENT;
 if(copy&&n&&((dst>=src&&dst-src<n)||(src>=dst&&src-dst<n)))
  return MXB_CRT_BAD_ARGUMENT; /* overlapping memcpy is undefined */
 int ok=fill?mxb_guest_fill(&s->memory,dst,(uint8_t)src,(size_t)n):
             mxb_guest_move(&s->memory,dst,src,(size_t)n);
 if(!ok)return MXB_CRT_BAD_MEMORY;
 s->r[MXB_RAX]=dst;s->r[MXB_RSP]=sp+8u;
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
 return 1;
}
