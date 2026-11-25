#include "mxb_standalone_imports.h"
#define B UINT64_C(0x140000000)
#define P(s) (const uint8_t *)(s),sizeof(s)
static uint8_t mem[1024];static unsigned writes;
static int valid(void *x,uint64_t a,size_t n){(void)x;return a>=B&&n<=sizeof(mem)&&a-B<=sizeof(mem)-n;}
static int rd(void *x,uint64_t a,uint8_t *d,size_t n){if(!valid(x,a,n))return 0;for(size_t i=0;i<n;i++)d[i]=mem[a-B+i];return 1;}
static void wr(void *x,uint64_t a,const uint8_t *d,size_t n){(void)x;writes++;for(size_t i=0;i<n;i++)mem[a-B+i]=d[i];}
static int canwrite(void *x,uint64_t a,size_t n){return valid(x,a,n)&&a>=B+128;}
static int canexec(void *x,uint64_t a){(void)x;return a>=B+0x1000&&a<B+0x1100;}
static void set(size_t off,const char *s){size_t i=0;do{mem[off+i]=(uint8_t)s[i];}while(s[i++]);}
static int same(size_t off,const char *s){size_t i=0;while(s[i]){if(mem[off+i]!=(uint8_t)s[i])return 0;i++;}return !mem[off+i];}
int smoke(void){
 mxb_startup_imports p={0};mxb_crt_memory m={0,rd,canwrite,wr,canexec};mxb_crt_regs r={0,0,0,0,B+8,99};
 if(!mxb_startup_init(&p,P("C:\\MXBReference"),P("C:\\MXBReference\\mxbikes.exe"),B,0xfffffffeu,123))return 1;
#define CALL(d,n) mxb_startup_dispatch(&p,&m,d,n,&r)
#define K(n) CALL("KERNEL32.dll",n)
#define C(n) CALL("MSVCR90.dll",n)
#define M(n) CALL("WINMM.dll",n)
 r.rdx=B+128;r.r8=260;if(K("GetModuleFileNameA")!=1||r.rax!=27||!same(128,"C:\\MXBReference\\mxbikes.exe"))return 2;
 r.r8=10;r.rax=99;if(K("GetModuleFileNameA")!=-1||r.rax!=99||writes!=1)return 3;
 set(32,"c:/");r.rcx=B+32;if(K("SetCurrentDirectoryA")!=1||r.rax!=1)return 4;
 r.rcx=3;r.rdx=B+256;if(K("GetCurrentDirectoryA")!=1||r.rax!=4||writes!=1)return 5;
 r.rcx=4;if(K("GetCurrentDirectoryA")!=1||r.rax!=3||!same(256,"C:\\"))return 6;
 set(32,"C:\\missing");r.rcx=B+32;if(K("SetCurrentDirectoryA")!=1||r.rax||K("GetLastError")!=1||r.rax!=3)return 7;
 r.rcx=UINT64_C(0xabcd00000009);r.rax=99;if(K("SetLastError")!=1||r.rax!=99||K("GetLastError")!=1||r.rax!=9)return 8;
 r.rcx=B+128;r.rdx=B+32;if(C("strcpy")!=1||r.rax!=B+128||!same(128,"C:\\missing"))return 9;
 r.rdx='\\';if(C("strrchr")!=1||r.rax!=B+130)return 10;
 r.rdx=0;if(C("strrchr")!=1||r.rax!=B+138)return 11;
 r.rdx='z';if(C("strrchr")!=1||r.rax)return 12;
 r.rcx=B+10;r.rdx=B+32;r.rax=99;if(C("strcpy")!=-1||r.rax!=99)return 13;
 r.rcx=B+1023;mem[1023]='x';if(C("strrchr")!=-1)return 14;
 if(M("timeGetTime")!=1||r.rax!=0xfffffffeu||!mxb_platform_advance(&p.platform,3)||K("GetTickCount")!=1||r.rax!=1)return 15;
 if(K("GetTickCount64")!=1||r.rax!=UINT64_C(0x100000001))return 16;
 r.rcx=UINT64_C(0xaaaa00000001);if(M("timeBeginPeriod")!=1||r.rax||p.platform.timer_refs!=1)return 17;
 if(M("timeEndPeriod")!=1||r.rax||p.platform.timer_refs)return 18;
 r.rcx=B+0x1000;if(K("SetUnhandledExceptionFilter")!=1||r.rax||p.exception_filter!=r.rcx)return 19;
 r.rcx=B+128;if(K("SetUnhandledExceptionFilter")!=-1||p.exception_filter!=B+0x1000)return 20;
 r.rcx=0;if(K("SetUnhandledExceptionFilter")!=1||r.rax!=B+0x1000||p.exception_filter)return 21;
 r.rcx=2;r.rax=99;if(C("__set_app_type")!=1||p.crt.app_type!=2||r.rax!=99)return 22;
 r.rsp=B+16;if(C("__set_app_type")!=-1||K("GetTickCount")!=-1)return 23;
 r.rsp=B+8;if(CALL("other.dll","strcpy")!=0||K("Unknown")!=0||C("Unknown")!=0)return 24;
 r.rcx=0;r.rdx=B+32;r.r8=260;r.rax=99;if(K("GetModuleFileNameA")!=-1||r.rax!=99)return 25;
 return 0;
}
#ifdef HOST
int main(void){return smoke();}
#endif
