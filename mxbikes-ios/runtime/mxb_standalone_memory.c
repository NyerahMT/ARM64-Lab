#include "mxb_standalone_memory.h"
static int eq(const char *a,const char *b){if(!a||!b)return 0;while(*a&&*a==*b){a++;b++;}return *a==*b;}
static int span(uint64_t a,uint64_t n){return a&&a<=UINT64_MAX-n;}
static size_t chunk(uint64_t n){return n>256u?256u:(size_t)n;}
int mxb_memory_dispatch(const mxb_crt_memory *m,const char *name,mxb_crt_regs *r){
    int fill=eq(name,"memset"),copy=eq(name,"memcpy"),move=eq(name,"memmove"),cmp=eq(name,"memcmp");
    if(!fill&&!copy&&!move&&!cmp)return 0;
    if(!r||(r->rsp&15u)!=8u||!r->rsp||r->r8>MXB_MEM_LIMIT)return -1;
    uint64_t a=r->rcx,b=r->rdx,n=r->r8;
    if(!n){r->rax=cmp?0:a;return 1;}
    if(!m||!span(a,n)||(!fill&&!span(b,n)))return -1;
    uint8_t buf[256],other[256];
    if(cmp){
        if(!m->read)return -1;
        for(uint64_t off=0;off<n;){size_t k=chunk(n-off);if(!m->read(m->ctx,a+off,buf,k)||!m->read(m->ctx,b+off,other,k))return -1;
            for(size_t j=0;j<k;j++)if(buf[j]!=other[j]){r->rax=(uint32_t)(buf[j]<other[j]?-1:1);return 1;}
            off+=k;}
        r->rax=0;return 1;
    }
    if(!m->writable||!m->write||!m->writable(m->ctx,a,(size_t)n))return -1;
    if(fill){for(size_t j=0;j<sizeof(buf);j++)buf[j]=(uint8_t)b;
        for(uint64_t off=0;off<n;){size_t k=chunk(n-off);m->write(m->ctx,a+off,buf,k);off+=k;}}
    else{
        if(!m->read||(copy&&a!=b&&a<b+n&&b<a+n))return -1;
        /* Verify the complete source before committing destination bytes. */
        for(uint64_t off=0;off<n;){size_t k=chunk(n-off);if(!m->read(m->ctx,b+off,buf,k))return -1;off+=k;}
        if(a>b&&a<b+n){for(uint64_t end=n;end;){size_t k=chunk(end);end-=k;if(!m->read(m->ctx,b+end,buf,k))return -1;m->write(m->ctx,a+end,buf,k);}}
        else{for(uint64_t off=0;off<n;){size_t k=chunk(n-off);if(!m->read(m->ctx,b+off,buf,k))return -1;m->write(m->ctx,a+off,buf,k);off+=k;}}
    }
    r->rax=a;return 1;
}
