#include "mxb_standalone_imports.h"
#define B UINT64_C(0x140000000)
static uint8_t mem[2048],heap[4096];static unsigned writes;
static uint8_t *loc(uint64_t a,size_t n){if(a>=B&&n<=sizeof(mem)&&a-B<=sizeof(mem)-n)return mem+(a-B);if(a>=MXB_HEAP_BASE&&n<=sizeof(heap)&&a-MXB_HEAP_BASE<=sizeof(heap)-n)return heap+(a-MXB_HEAP_BASE);return 0;}
static int rd(void *c,uint64_t a,uint8_t *p,size_t n){(void)c;uint8_t *s=loc(a,n);if(!s)return 0;for(size_t i=0;i<n;i++)p[i]=s[i];return 1;}
static int valid(void *c,uint64_t a,size_t n){(void)c;return loc(a,n)!=0;}
static void wr(void *c,uint64_t a,const uint8_t *p,size_t n){(void)c;uint8_t *s=loc(a,n);writes++;for(size_t i=0;i<n;i++)s[i]=p[i];}
static void put(uint8_t *p,uint64_t v){for(unsigned i=0;i<8;i++){p[i]=(uint8_t)v;v>>=8;}}
static uint64_t get(uint8_t *p){uint64_t v=0;for(unsigned i=8;i;i--)v=(v<<8)|p[i-1];return v;}
static void str(uint8_t *p,const char *s){while((*p++=(uint8_t)*s++));}
static int same(const uint8_t *p,const char *s){while(*s)if(*p++!=(uint8_t)*s++)return 0;return !*p;}
#define WS(n) mxb_startup_dispatch(&s,&m,"WS2_32.dll",n,&r)
#define CRT(n) mxb_startup_dispatch(&s,&m,"MSVCR90.dll",n,&r)
int smoke(void){
 mxb_startup_imports s={0};mxb_crt_memory m={0,rd,valid,wr,0};mxb_crt_regs r={.rsp=B+8};
 r.rcx=2;r.rdx=B+512;if(WS("#115")!=1||r.rax||s.winsock.refs!=1||mem[512]!=2||mem[513]||mem[514]!=2||mem[515]!=2||!same(mem+785,"No network transport"))return 1;
 r.rcx=0x999900000202u;if(WS("WSAStartup")!=1||s.winsock.refs!=2||mem[513]!=2)return 2;
 r.rcx=1;if(WS("#115")!=1||r.rax!=10092||s.winsock.refs!=2)return 3;
 r.rcx=2;r.rdx=B+2000;if(WS("#115")!=1||r.rax!=10014||s.winsock.refs!=2)return 4;
 if(WS("#116")!=1||r.rax||WS("WSACleanup")!=1||r.rax||WS("#116")!=1||r.rax!=UINT32_MAX||s.winsock.refs)return 5;
 if(WS("#111")!=1||r.rax!=10093)return 6;
 r.rcx=0x12345678;if(WS("#8")!=1||r.rax!=0x78563412||WS("#9")!=1||r.rax!=0x7856)return 7;
 r.rcx=2;r.rdx=B+128;r.r8=B+256;str(mem+128,"127.0.0.1");if(WS("inet_pton")!=1||r.rax!=1||mem[256]!=127||mem[259]!=1)return 8;
 str(mem+128,"01.0.0.1");unsigned old=writes;if(WS("inet_pton")!=1||r.rax||writes!=old)return 9;
 str(mem+128,"256.0.0.1");if(WS("inet_pton")!=1||r.rax||writes!=old)return 10;
 r.rdx=B+256;r.r8=B+300;r.r9=16;if(WS("inet_ntop")!=1||r.rax!=B+300||!same(mem+300,"127.0.0.1"))return 11;
 r.r9=5;old=writes;if(WS("inet_ntop")!=1||r.rax||writes!=old)return 12;
 mem[320]=2;mem[324]=127;mem[327]=1;r.rcx=B+320;r.rdx=16;r.r8=B+300;r.r9=16;
 if(WS("getnameinfo")!=1||r.rax||!same(mem+300,"localhost"))return 13;
 put(mem+64,2);if(WS("getnameinfo")!=1||r.rax||!same(mem+300,"127.0.0.1"))return 14;
 put(mem+64,0);mem[324]=1;old=writes;if(WS("getnameinfo")!=0||writes!=old)return 15;
 str(mem+128,"localhost");r.rcx=B+128;r.rdx=r.r8=0;r.r9=B+400;
 if(WS("getaddrinfo")!=1||r.rax||get(mem+400)!=MXB_HEAP_BASE||get(heap+32)!=MXB_HEAP_BASE+48||heap[52]!=127||heap[55]!=1)return 16;
 r.rcx=MXB_HEAP_BASE;if(WS("freeaddrinfo")!=1||s.winsock.results[0]||WS("freeaddrinfo")!=-1)return 17;
 r.rcx=B+128;str(mem+128,"otherhost");old=writes;if(WS("getaddrinfo")!=0||writes!=old)return 18;
 if(WS("#23")!=0)return 19;
 str(mem+128,"%lu.%lu.%lu.%lu");r.rcx=B+300;r.rdx=B+128;r.r8=0xabcdef000000007fu;r.r9=0;put(mem+48,0);put(mem+56,1);
 if(CRT("sprintf")!=1||r.rax!=9||!same(mem+300,"127.0.0.1"))return 20;
 str(mem+128,"%d %X %% %s");r.r8=0x80000000u;r.r9=0xabcdef;put(mem+48,B+400);str(mem+400,"hello");
 if(CRT("sprintf")!=1||!same(mem+300,"-2147483648 ABCDEF % hello"))return 21;
 str(mem+128,"%n");old=writes;if(CRT("sprintf")!=0||writes!=old)return 22;
 str(mem+128,"%s");r.r8=B+2048;if(CRT("sprintf")!=-1||writes!=old)return 23;
 str(mem+128,"%u");r.r8=42;r.rcx=B+2047;if(CRT("sprintf")!=-1||writes!=old)return 24;
 return 0;
}
#ifdef HOST
int main(void){return smoke();}
#endif
