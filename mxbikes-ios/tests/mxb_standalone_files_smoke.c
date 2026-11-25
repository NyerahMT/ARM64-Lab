#include "mxb_standalone_imports.h"
#define B UINT64_C(0x140000000)
static uint8_t memory[1024];static unsigned writes;
static int valid(void *c,uint64_t a,size_t n){(void)c;return a>=B&&n<=sizeof(memory)&&a-B<=sizeof(memory)-n;}
static int rd(void *c,uint64_t a,uint8_t *p,size_t n){if(!valid(c,a,n))return 0;for(size_t i=0;i<n;i++)p[i]=memory[a-B+i];return 1;}
static void wr(void *c,uint64_t a,const uint8_t *p,size_t n){(void)c;writes++;for(size_t i=0;i<n;i++)memory[a-B+i]=p[i];}
static void str(uint8_t *p,const char *s){while((*p++=(uint8_t)*s++));}
static int same(const uint8_t *p,const char *s){while(*s)if(*p++!=(uint8_t)*s++)return 0;return !*p;}
#define CRT(n) mxb_startup_dispatch(&s,&m,"MSVCR90.dll",n,&r)
int smoke(void){
    static const uint8_t asset[]="hello\nworld";
    mxb_startup_imports s={0};mxb_crt_memory m={0,rd,valid,wr,0};mxb_crt_regs r={.rsp=B+8,.rcx=B+64,.rdx=B+200};
    if(!mxb_files_mount(&s.files,"fixture.ini",asset,sizeof(asset)-1))return 1;
    if(mxb_files_mount(&s.files,"FIXTURE.INI",asset,sizeof(asset)-1)||mxb_files_mount(&s.files,"../x.ini",asset,1))return 2;
    str(memory+64,"missing.ini");str(memory+200,"rb");if(CRT("fopen")!=0)return 3;
    str(memory+64,"fixture.ini");str(memory+200,"wb");if(CRT("fopen")!=0)return 4;
    str(memory+64,"FIXTURE.INI");str(memory+200,"rb");if(CRT("fopen")!=1||!r.rax)return 5;
    uint64_t token=r.rax;
    if(CRT("fopen")!=1||r.rax==token)return 6;
    uint64_t other=r.rax;
    r.rcx=B+300;r.rdx=16;r.r8=token;if(CRT("fgets")!=1||r.rax!=B+300||!same(memory+300,"hello\n"))return 7;
    r.rcx=token;if(CRT("ftell")!=1||r.rax!=6||CRT("feof")!=1||r.rax)return 8;
    r.rcx=other;if(CRT("ftell")!=1||r.rax)return 9;
    r.rcx=B+300;r.rdx=2;r.r8=3;r.r9=token;if(CRT("fread")!=1||r.rax!=2||memory[300]!='w'||memory[304]!='d')return 10;
    r.rcx=token;if(CRT("ftell")!=1||r.rax!=11||CRT("feof")!=1||r.rax!=1)return 11;
    r.rdx=(uint32_t)-5;r.r8=2;if(CRT("fseek")!=1||r.rax||CRT("feof")!=1||r.rax||CRT("ftell")!=1||r.rax!=6)return 12;
    r.rcx=B+1023;r.rdx=1;r.r8=5;r.r9=token;unsigned before=writes;if(CRT("fread")!=-1||writes!=before)return 13;
    r.rcx=token;if(CRT("ftell")!=1||r.rax!=6)return 14;
    r.rdx=(uint32_t)-7;r.r8=0;if(CRT("fseek")!=1||r.rax!=UINT32_MAX||CRT("ftell")!=1||r.rax!=6)return 15;
    r.rcx=B+300;r.rdx=16;r.r8=token;if(CRT("fgets")!=1||!same(memory+300,"world"))return 16;
    if(CRT("fgets")!=1||r.rax)return 17;
    r.rcx=token;if(CRT("fclose")!=1||r.rax||CRT("fclose")!=-1)return 18;
    r.rcx=B+64;r.rdx=B+200;if(CRT("fopen")!=1||r.rax==token||r.rax==other)return 19;
    r.rcx=other;if(CRT("fclose")!=1)return 20;
    return 0;
}
#ifdef HOST
int main(void){return smoke();}
#endif
