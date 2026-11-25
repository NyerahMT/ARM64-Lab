#include "mxb_standalone_crt.h"
static int equal(const char *a,const char *b,int fold){
    if(!a||!b)return 0;
    while(*a&&*b){unsigned x=(unsigned char)*a++,y=(unsigned char)*b++;
        if(fold&&x>='A'&&x<='Z')x+='a'-'A';
        if(fold&&y>='A'&&y<='Z')y+='a'-'A';
        if(x!=y)return 0;
    }
    return *a==*b;
}
static void put(uint8_t *p,uint64_t v,size_t n){
    for(size_t i=0;i<n;i++){p[i]=(uint8_t)v;v>>=8;}
}
static uint64_t get(const uint8_t *p,size_t n){
    uint64_t v=0;for(size_t i=n;i>0;i--)v=(v<<8)|p[i-1];return v;
}
static int span(uint64_t a,size_t n){return a&&n&&a<=UINT64_MAX-n;}
static int overlaps(uint64_t a,size_t n,uint64_t b,size_t k){return a<b+k&&b<a+n;}
int mxb_crt_data_page(uint8_t *page,size_t size,uint64_t a,uint64_t w,
                      const uint8_t *argv0,size_t n){
    if(!page||size!=MXB_CRT_PAGE||!a||!w||!argv0||n<2||n>256||argv0[n-1])return -1;
    uint8_t copy[256];
    for(size_t i=0;i<n;i++){if(i+1<n&&!argv0[i])return -1;copy[i]=argv0[i];}
    for(size_t i=0;i<size;i++)page[i]=0;
    put(page,a,8);put(page+8,w,8);put(page+16,0x4000,4);
    put(page+0x40,MXB_CRT_ARGV0,8);
    for(size_t i=0;i<n;i++)page[0x100+i]=copy[i];
    return 1;
}
uint64_t mxb_crt_data_address(const char *library,const char *symbol){
    if(!equal(library,"msvcr90.dll",1))return 0;
    if(equal(symbol,"_acmdln",0))return MXB_CRT_BASE;
    if(equal(symbol,"_wcmdln",0))return MXB_CRT_BASE+8;
    if(equal(symbol,"_fmode",0))return MXB_CRT_BASE+16;
    if(equal(symbol,"_commode",0))return MXB_CRT_BASE+20;
    return 0;
}
int mxb_crt_dispatch(mxb_crt_process *p,const mxb_crt_memory *m,
                     const char *library,const char *symbol,mxb_crt_regs *r){
    if(!equal(library,"msvcr90.dll",1))return 0;
    int app=equal(symbol,"__set_app_type",0),locale=equal(symbol,"_configthreadlocale",0),
        args=equal(symbol,"__getmainargs",0);
    if(!app&&!locale&&!args)return 0;
    if(!p||!r||!span(r->rsp,48)||(r->rsp&15u)!=8u)return -1;
    uint32_t a=(uint32_t)r->rcx;
    if(app){if(a!=1&&a!=2)return -1;p->app_type=a;return 1;}
    if(locale){if(a>2||(p->locale_mode!=1&&p->locale_mode!=2))return -1;
        r->rax=p->locale_mode;if(a)p->locale_mode=a;return 1;}
    if(!m||!m->read||!m->writable||!m->write||(uint32_t)r->r9)return -1;
    uint8_t buf[8];
    if(!m->read(m->ctx,r->rsp+40,buf,8))return -1;
    uint64_t startup=get(buf,8);
    if(!span(startup,4)||(startup&3u)||!m->read(m->ctx,startup,buf,4)||get(buf,4))return -1;
    uint64_t out[3]={r->rcx,r->rdx,r->r8},value[3]={1,MXB_CRT_ARGV,MXB_CRT_ENVP};
    size_t n[3]={4,8,8};
    for(size_t i=0;i<3;i++){
        if(!span(out[i],n[i])||!m->writable(m->ctx,out[i],n[i]))return -1;
        for(size_t j=0;j<i;j++)if(overlaps(out[i],n[i],out[j],n[j]))return -1;
    }
    for(size_t i=0;i<3;i++){put(buf,value[i],n[i]);m->write(m->ctx,out[i],buf,n[i]);}
    r->rax=0;return 1;
}
