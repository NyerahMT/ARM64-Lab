#include "mxb_config_file.h"
#include <string.h>

static int read64(const MXBGuestMemory*m,uint64_t a,uint64_t*v){
 uint8_t b[8];if(!mxb_guest_read(m,a,b,8))return 0;
 *v=0;for(unsigned i=0;i<8;i++)*v|=(uint64_t)b[i]<<(8*i);
 return 1;
}
int mxb_config_file_call(MXBGuestState*s,MXBConfigFile*f,const char*symbol,uint64_t ret){
 if(!s||!f||!symbol||!ret||s->fault||!f->last_write)return 0;
 uint64_t sp=s->r[MXB_RSP],actual;
 if((sp&15)!=8||sp>UINT64_MAX-64||!read64(&s->memory,sp,&actual)||actual!=ret||
    !mxb_guest_check(&s->memory,sp+8,32,MXB_MEM_WRITE))return 0;
 uint64_t result;
 if(!strcmp(symbol,"CreateFileA")){
  char path[9];
  uint64_t creation,flags,templ;
  if(f->open||s->r[MXB_RDX]!=0x80000000||s->r[MXB_R8]!=1||s->r[MXB_R9]||
     !read64(&s->memory,sp+0x28,&creation)||!read64(&s->memory,sp+0x30,&flags)||
     !read64(&s->memory,sp+0x38,&templ)||(uint32_t)creation!=3||(uint32_t)flags||templ||
     !mxb_guest_read(&s->memory,s->r[MXB_RCX],path,sizeof(path))||
     memcmp(path,"core.ini",sizeof(path)))return 0;
  f->open=1;f->opens++;result=MXB_CONFIG_HANDLE;
 }else if(!strcmp(symbol,"GetFileTime")){
  uint64_t out=s->r[MXB_R9];
  if(!f->open||s->r[MXB_RCX]!=MXB_CONFIG_HANDLE||s->r[MXB_RDX]||s->r[MXB_R8]||
     !out||(out&3)||out>UINT64_MAX-8||(out<sp+8&&sp<out+8))return 0;
  uint8_t b[8];for(unsigned i=0;i<8;i++)b[i]=(uint8_t)(f->last_write>>(8*i));
  if(!mxb_guest_write(&s->memory,out,b,8))return 0;
  f->queries++;result=1;
 }else if(!strcmp(symbol,"CloseHandle")){
  if(!f->open||s->r[MXB_RCX]!=MXB_CONFIG_HANDLE)return 0;
  f->open=0;f->closes++;result=1;
 }else return 0;
 s->r[MXB_RAX]=result;s->r[MXB_RSP]=sp+8;
 return 1;
}
int mxb_config_file_smoke(void){
 MXBGuestState s={0};MXBConfigFile f={.last_write=UINT64_C(0x123456789abcdef)};
 uint64_t frame[8]={0x12345678,0,0,0,0,3,0,0},out=0;
 char filename[]="core.ini";const uint64_t sp=0x1008,ret=frame[0];
 if(!mxb_guest_map(&s.memory,sp,(uint8_t*)frame,sizeof(frame),3)||
    !mxb_guest_map(&s.memory,0x2000,(uint8_t*)filename,sizeof(filename),1)||
    !mxb_guest_map(&s.memory,0x3000,(uint8_t*)&out,8,3))return 0;
 s.r[MXB_RSP]=sp;s.r[MXB_RCX]=0x2000;s.r[MXB_RDX]=0x80000000;
 s.r[MXB_R8]=1;
 if(mxb_config_file_call(&s,&f,"CreateFileA",ret+1)||f.open||s.r[MXB_RSP]!=sp)return 0;
 if(!mxb_config_file_call(&s,&f,"CreateFileA",ret)||s.r[MXB_RAX]!=MXB_CONFIG_HANDLE||!f.open)return 0;
 s.r[MXB_RSP]=sp;s.r[MXB_RCX]=MXB_CONFIG_HANDLE;s.r[MXB_RDX]=0;s.r[MXB_R8]=0;
 s.r[MXB_R9]=0x2000;
 if(mxb_config_file_call(&s,&f,"GetFileTime",ret)||f.queries||s.r[MXB_RSP]!=sp)return 0;
 s.r[MXB_R9]=0x3000;
 if(!mxb_config_file_call(&s,&f,"GetFileTime",ret)||out!=f.last_write)return 0;
 s.r[MXB_RSP]=sp;
 if(!mxb_config_file_call(&s,&f,"CloseHandle",ret)||f.open)return 0;
 s.r[MXB_RSP]=sp;
 if(mxb_config_file_call(&s,&f,"CloseHandle",ret)||f.opens!=1||f.queries!=1||f.closes!=1)return 0;
 return 1;
}
