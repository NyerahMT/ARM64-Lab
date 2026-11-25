#include "mxb_standalone_heap.h"
static int eq(const char *a,const char *b){if(!a||!b)return 0;while(*a&&*a==*b){a++;b++;}return *a==*b;}
static unsigned find(const mxb_heap *h,uint64_t a){for(unsigned i=0;i<MXB_HEAP_SLOTS;i++)if(h->blocks[i].address==a)return i;return MXB_HEAP_SLOTS;}
static uint64_t allocate(mxb_heap *h,const mxb_crt_memory *m,uint64_t n,int zero){
    if(n>MXB_HEAP_CAP)return 0;
    uint64_t size=(n?n:1u);size=(size+15u)&~UINT64_C(15);
    unsigned slot=find(h,0);if(slot==MXB_HEAP_SLOTS)return 0;
    uint64_t a=MXB_HEAP_BASE,end=MXB_HEAP_BASE+MXB_HEAP_CAP;
    while(a<=end-size){
        uint64_t next=a;
        for(unsigned i=0;i<MXB_HEAP_SLOTS;i++){
            mxb_heap_block b=h->blocks[i];
            if(b.address&&a<b.address+b.size&&b.address<a+size&&b.address+b.size>next)next=b.address+b.size;
        }
        if(next!=a){a=next;continue;}
        if(!m->writable(m->ctx,a,(size_t)size))return 0;
        if(zero){uint8_t bytes[256]={0};for(uint64_t off=0;off<size;){size_t count=(size-off>sizeof(bytes))?sizeof(bytes):(size_t)(size-off);m->write(m->ctx,a+off,bytes,count);off+=count;}}
        h->blocks[slot]=(mxb_heap_block){a,size};return a;
    }return 0;
}
int mxb_heap_dispatch(mxb_heap *h,const mxb_crt_memory *m,const char *name,mxb_crt_regs *r){
    int alloc=eq(name,"malloc"),zero=eq(name,"calloc"),release=eq(name,"free");
    if(!alloc&&!zero&&!release)return 0;
    if(!h||!r||(r->rsp&15u)!=8u||!r->rsp||!m||!m->writable||!m->write)return -1;
    if(release){if(!r->rcx)return 1;unsigned i=find(h,r->rcx);if(i==MXB_HEAP_SLOTS)return -1;h->blocks[i]=(mxb_heap_block){0,0};return 1;}
    uint64_t n=r->rcx;
    if(zero){if(n&&r->rdx>UINT64_MAX/n){r->rax=0;return 1;}n*=r->rdx;}
    r->rax=allocate(h,m,n,zero);return 1;
}
