#include "mxb_standalone_crt.h"
#define B UINT64_C(0x140000000)
static uint8_t mem[512],page[MXB_CRT_PAGE];
static unsigned writes;
static void put(uint8_t *p,uint64_t v,size_t n){for(size_t i=0;i<n;i++){p[i]=(uint8_t)v;v>>=8;}}
static uint64_t get(const uint8_t *p,size_t n){uint64_t v=0;for(size_t i=n;i>0;i--)v=(v<<8)|p[i-1];return v;}
static int valid(void *c,uint64_t a,size_t n){(void)c;return a>=B&&n<=sizeof(mem)&&a-B<=sizeof(mem)-n;}
static int rd(void *c,uint64_t a,uint8_t *p,size_t n){if(!valid(c,a,n))return 0;for(size_t i=0;i<n;i++)p[i]=mem[a-B+i];return 1;}
static void wr(void *c,uint64_t a,const uint8_t *p,size_t n){(void)c;writes++;for(size_t i=0;i<n;i++)mem[a-B+i]=p[i];}
static int canwrite(void *c,uint64_t a,size_t n){return valid(c,a,n)&&a>=B+128;}
static int canexec(void *c,uint64_t a){(void)c;return a>=B+0x1000&&a<B+0x1100;}
int smoke(void){
    const uint8_t exe[]="mxbikes.exe";
    mxb_crt_memory m={0,rd,canwrite,wr,canexec};mxb_crt_process p={.locale_mode=2,.pointer_key=UINT64_C(0x7d91ca346f289b15)};
    mxb_crt_regs r={B+128,B+136,B+144,0,B+8,99};
    put(mem+48,B+80,8);
    if(mxb_crt_data_page(page,sizeof(page),B+1000,B+2000,exe,sizeof(exe))!=1)return 1;
    if(get(page,8)!=B+1000||get(page+8,8)!=B+2000||get(page+16,4)!=0x4000||get(page+20,4))return 2;
    if(get(page+64,8)!=MXB_CRT_ARGV0||get(page+72,8)||get(page+96,8))return 3;
    for(size_t i=0;i<sizeof(exe);i++)if(page[256+i]!=exe[i])return 4;
    if(mxb_crt_data_page(page,sizeof(page),0,1,exe,sizeof(exe))!=-1||get(page,8)!=B+1000)return 5;
    if(mxb_crt_data_page(page,sizeof(page),1,2,page+256,sizeof(exe))!=1||page[256]!='m')return 6;
    if(mxb_crt_data_address("MSVCR90.DLL","_acmdln")!=MXB_CRT_BASE||mxb_crt_data_address("msvcr90.dll","_wcmdln")!=MXB_CRT_BASE+8||mxb_crt_data_address("msvcr90.dll","_fmode")!=MXB_CRT_BASE+16||mxb_crt_data_address("msvcr90.dll","_commode")!=MXB_CRT_BASE+20)return 7;
    if(mxb_crt_data_address("other.dll","_fmode")||mxb_crt_data_address("msvcr90.dll","_FMODE"))return 8;
    if(mxb_crt_dispatch(&p,&m,"MSVCR90.dll","__getmainargs",&r)!=1||r.rax||writes!=3||get(mem+128,4)!=1||get(mem+136,8)!=MXB_CRT_ARGV||get(mem+144,8)!=MXB_CRT_ENVP)return 9;
    r.rax=99;r.rcx=B+134;
    if(mxb_crt_dispatch(&p,&m,"MSVCR90.dll","__getmainargs",&r)!=-1||r.rax!=99||writes!=3)return 10;
    r.rcx=B+128;r.r8=B+504;r.r9=1;
    if(mxb_crt_dispatch(&p,&m,"MSVCR90.dll","__getmainargs",&r)!=-1||writes!=3)return 11;
    r.r9=UINT64_C(0xffff00000000);r.r8=B+508;
    if(mxb_crt_dispatch(&p,&m,"MSVCR90.dll","__getmainargs",&r)!=-1||writes!=3)return 12;
    r.r8=B+64;
    if(mxb_crt_dispatch(&p,&m,"MSVCR90.dll","__getmainargs",&r)!=-1||writes!=3)return 13;
    r.r8=B+144;mem[80]=1;
    if(mxb_crt_dispatch(&p,&m,"MSVCR90.dll","__getmainargs",&r)!=-1||writes!=3)return 14;
    mem[80]=0;r.rcx=UINT64_C(0xffff00000002);
    if(mxb_crt_dispatch(&p,&m,"MSVCR90.dll","__set_app_type",&r)!=1||p.app_type!=2||r.rax!=99)return 15;
    r.rcx=1;if(mxb_crt_dispatch(&p,&m,"MSVCR90.dll","_configthreadlocale",&r)!=1||p.locale_mode!=1||r.rax!=2)return 16;
    r.rcx=0;if(mxb_crt_dispatch(&p,&m,"MSVCR90.dll","_configthreadlocale",&r)!=1||r.rax!=1||p.locale_mode!=1)return 17;
    r.rcx=3;if(mxb_crt_dispatch(&p,&m,"MSVCR90.dll","_configthreadlocale",&r)!=-1||r.rax!=1||p.locale_mode!=1)return 18;
    r.rsp=B+16;if(mxb_crt_dispatch(&p,&m,"MSVCR90.dll","__set_app_type",&r)!=-1||p.app_type!=2)return 19;
    if(mxb_crt_dispatch(&p,&m,"other.dll","__set_app_type",&r)!=0||mxb_crt_dispatch(&p,&m,"MSVCR90.dll","unknown",&r)!=0)return 20;
    r.rsp=B+8;r.rcx=B+128;r.r9=UINT64_C(0xffff00000000);
    if(mxb_crt_dispatch(&p,&m,"MSVCR90.dll","__getmainargs",&r)!=1||writes!=6||r.rax)return 21;
    r.rcx=UINT64_MAX;
    if(mxb_crt_dispatch(&p,&m,"MSVCR90.dll","_encode_pointer",&r)!=1||r.rax==UINT64_MAX)return 22;
    r.rcx=r.rax;
    if(mxb_crt_dispatch(&p,&m,"MSVCR90.dll","_decode_pointer",&r)!=1||r.rax!=UINT64_MAX)return 23;
    r.rcx=0;
    if(mxb_crt_dispatch(&p,&m,"MSVCR90.dll","_encode_pointer",&r)!=1||!r.rax)return 24;
    r.rcx=r.rax;
    if(mxb_crt_dispatch(&p,&m,"MSVCR90.dll","_decode_pointer",&r)!=1||r.rax)return 25;
    p.pointer_key=0;r.rcx=1;r.rax=77;
    if(mxb_crt_dispatch(&p,&m,"MSVCR90.dll","_encode_pointer",&r)!=-1||r.rax!=77)return 26;
    r.rcx=B+0x1000;
    if(mxb_crt_dispatch(&p,&m,"MSVCR90.dll","_onexit",&r)!=1||r.rax!=r.rcx||p.exit_count!=1||p.exit_callbacks[0]!=r.rcx)return 27;
    r.rcx=B+128;
    if(mxb_crt_dispatch(&p,&m,"MSVCR90.dll","_onexit",&r)!=-1||p.exit_count!=1)return 28;
    for(unsigned i=1;i<32;i++){r.rcx=B+0x1000+i;if(mxb_crt_dispatch(&p,&m,"MSVCR90.dll","_onexit",&r)!=1)return 29;}
    r.rcx=B+0x1080;
    if(mxb_crt_dispatch(&p,&m,"MSVCR90.dll","_onexit",&r)!=-1||p.exit_count!=32)return 30;
    r.rcx=UINT64_C(0xffff00000041);
    if(mxb_crt_dispatch(&p,&m,"MSVCR90.dll","_ismbblead",&r)!=1||r.rax)return 31;
    r.rcx=0x81;r.rax=77;
    if(mxb_crt_dispatch(&p,&m,"MSVCR90.dll","_ismbblead",&r)!=-1||r.rax!=77)return 32;
    return 0;
}
#ifdef HOST
int main(void){return smoke();}
#endif
