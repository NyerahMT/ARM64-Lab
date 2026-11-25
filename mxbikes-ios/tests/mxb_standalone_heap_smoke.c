#include "mxb_standalone_heap.h"
static mxb_heap h;static uint8_t mem[MXB_HEAP_CAP];static unsigned writes;
static int can(void *ctx,uint64_t a,size_t n){(void)ctx;return a>=MXB_HEAP_BASE&&n<=MXB_HEAP_CAP&&a-MXB_HEAP_BASE<=MXB_HEAP_CAP-n;}
static void wr(void *ctx,uint64_t a,const uint8_t *b,size_t n){(void)ctx;writes++;for(size_t i=0;i<n;i++)mem[a-MXB_HEAP_BASE+i]=b[i];}
int smoke(void){
    mxb_crt_memory m={0,0,can,wr,0};mxb_crt_regs r={1,0,0,0,0x1008,99};
#define D(n) mxb_heap_dispatch(&h,&m,n,&r)
    if(D("malloc")!=1||r.rax!=MXB_HEAP_BASE||h.blocks[0].size!=16)return 1;
    r.rcx=17;if(D("malloc")!=1||r.rax!=MXB_HEAP_BASE+16||h.blocks[1].size!=32)return 2;
    r.rcx=MXB_HEAP_BASE;r.rax=99;if(D("free")!=1||r.rax!=99||h.blocks[0].address)return 3;
    if(D("free")!=-1)return 4;
    r.rcx=MXB_HEAP_BASE+17;if(D("free")!=-1)return 5;
    mem[0]=0xff;r.rcx=2;r.rdx=4;if(D("calloc")!=1||r.rax!=MXB_HEAP_BASE||mem[0]||writes!=1)return 6;
    r.rcx=UINT64_MAX;r.rdx=2;if(D("calloc")!=1||r.rax||writes!=1)return 7;
    r.rcx=MXB_HEAP_CAP;if(D("malloc")!=1||r.rax)return 8;
    r.rcx=0;if(D("free")!=1||D("malloc")!=1||r.rax!=MXB_HEAP_BASE+48)return 9;
    r.rcx=MXB_HEAP_BASE+16;if(D("free")!=1)return 10;
    r.rcx=32;if(D("malloc")!=1||r.rax!=MXB_HEAP_BASE+16)return 11;
    r.rsp=0x1000;if(D("malloc")!=-1)return 12;
    r.rsp=0x1008;if(D("realloc")!=0)return 13;
    for(unsigned i=3;i<MXB_HEAP_SLOTS;i++){r.rcx=1;if(D("malloc")!=1||!r.rax)return 14;}
    if(D("malloc")!=1||r.rax)return 15;
    r.rcx=MXB_HEAP_BASE+64;if(D("free")!=1)return 16;
    r.rcx=16;if(D("malloc")!=1||r.rax!=MXB_HEAP_BASE+64)return 17;
    return 0;
}
#ifdef HOST
int main(void){return smoke();}
#endif
