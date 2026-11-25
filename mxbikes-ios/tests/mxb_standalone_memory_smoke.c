#include "mxb_standalone_memory.h"
#define B UINT64_C(0x100000)
static uint8_t mem[2048];static unsigned writes;
static int valid(void *c,uint64_t a,size_t n){(void)c;return a>=B&&n<=sizeof(mem)&&a-B<=sizeof(mem)-n;}
static int rd(void *c,uint64_t a,uint8_t *v,size_t n){if(!valid(c,a,n))return 0;for(size_t i=0;i<n;i++)v[i]=mem[a-B+i];return 1;}
static void wr(void *c,uint64_t a,const uint8_t *v,size_t n){(void)c;writes++;for(size_t i=0;i<n;i++)mem[a-B+i]=v[i];}
int smoke(void){
 mxb_crt_memory m={0,rd,valid,wr,0};mxb_crt_regs r={B+1000,0x1234,600,0,0x1008,99};
#define D(n) mxb_memory_dispatch(&m,n,&r)
 if(D("memset")!=1||r.rax!=B+1000||writes!=3||mem[999]||mem[1600])return 1;
 for(size_t i=1000;i<1600;i++)if(mem[i]!=0x34)return 2;
 for(size_t i=0;i<700;i++)mem[i]=(uint8_t)(i*3);
 r.rcx=B+1000;r.rdx=B;r.r8=700;if(D("memcpy")!=1||writes!=6)return 3;
 for(size_t i=0;i<700;i++)if(mem[i]!=mem[i+1000])return 4;
 r.rcx=B+1;r.rdx=B;r.r8=699;r.rax=99;if(D("memcpy")!=-1||writes!=6||r.rax!=99)return 5;
 if(D("memmove")!=1)return 6;
 for(size_t i=0;i<699;i++)if(mem[i+1]!=(uint8_t)(i*3))return 7;
 r.rcx=B;r.rdx=B+1;if(D("memmove")!=1)return 8;
 for(size_t i=0;i<699;i++)if(mem[i]!=(uint8_t)(i*3))return 9;
 r.rcx=B;r.rdx=B+1000;r.r8=699;if(D("memcmp")!=1||r.rax)return 10;
 mem[1000]=255;if(D("memcmp")!=1||(uint32_t)r.rax!=UINT32_MAX)return 11;
 r.rcx=B+1000;r.rdx=B;if(D("memcmp")!=1||r.rax!=1)return 12;
 unsigned old=writes;r.rcx=B+1000;r.rdx=B+2040;r.r8=20;r.rax=99;if(D("memmove")!=-1||writes!=old||r.rax!=99)return 13;
 r.rcx=B+2040;r.rdx=0;if(D("memset")!=-1||writes!=old)return 14;
 r.rcx=0;r.r8=0;if(D("memset")!=1||r.rax||writes!=old)return 15;
 r.r8=MXB_MEM_LIMIT+1u;if(D("memset")!=-1||writes!=old)return 16;
 return 0;
}
#ifdef HOST
int main(void){return smoke();}
#endif
