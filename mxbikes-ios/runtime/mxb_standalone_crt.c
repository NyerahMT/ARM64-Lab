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
/* Reversible process-local pointer tokens; not Windows token compatibility. */
static uint64_t rotate_left(uint64_t x,unsigned n){return (x<<n)|(x>>(64u-n));}
static uint64_t rotate_right(uint64_t x,unsigned n){return (x>>n)|(x<<(64u-n));}
/* Win64 struct tm is nine little-endian signed 32-bit integers.
 * Deterministic UTC matches the virtual ZIP/DOS timestamp reference.
 * Reject unsupported domain before changing the guest struct or RAX. */
static int leap(int y){return y%4==0&&(y%100!=0||y%400==0);}
static int month_days(int y,int m){
    static const uint8_t days[12]={31,28,31,30,31,30,31,31,30,31,30,31};
    return days[m]+(m==1&&leap(y));
}
static int64_t signed32(const uint8_t *p){
    uint64_t v=get(p,4);return v>=UINT64_C(0x80000000)?(int64_t)v-INT64_C(0x100000000):(int64_t)v;
}
static int mktime_utc(const mxb_crt_memory *m,mxb_crt_regs *r){
    uint8_t tm[36];
    if(!m||!m->read||!m->write||!m->writable||!span(r->rcx,sizeof(tm))||
       !m->read(m->ctx,r->rcx,tm,sizeof(tm)))return -1;
    int64_t f[9];for(unsigned i=0;i<9;i++)f[i]=signed32(tm+4u*i);
    if(f[5]<0||f[5]>1100||f[4]<-120||f[4]>120||f[3]<-366||f[3]>366||
       f[0]<-86400||f[0]>86400||f[1]<-1440||f[1]>1440||
       f[2]<-48||f[2]>48||(f[8]!=-1&&f[8]!=0))return -1;
    int y=1900+(int)f[5],mo=(int)f[4];
    while(mo<0){--y;mo+=12;}while(mo>=12){++y;mo-=12;}
    int64_t days=0;
    for(int i=1970;i<y;i++)days+=365+leap(i);
    for(int i=y;i<1970;i++)days-=365+leap(i);
    for(int i=0;i<mo;i++)days+=month_days(y,i);
    days+=f[3]-1;
    int64_t stamp=days*86400+f[2]*3600+f[1]*60+f[0];
    if(stamp<0)return -1;
    days=stamp/86400;int64_t left=days,sec=stamp%86400;
    y=1970;while(y<=3000&&left>=365+leap(y)){left-=365+leap(y);y++;}
    if(y>3000)return -1;
    int64_t yday=left;mo=0;
    while(mo<11&&left>=month_days(y,mo)){left-=month_days(y,mo);mo++;}
    int64_t normalized[9]={sec%60,(sec/60)%60,sec/3600,left+1,mo,y-1900,(days+4)%7,yday,0};
    for(unsigned i=0;i<9;i++)put(tm+4u*i,(uint64_t)normalized[i],4);
    if(!m->writable(m->ctx,r->rcx,sizeof(tm)))return -1;
    m->write(m->ctx,r->rcx,tm,sizeof(tm));r->rax=(uint64_t)stamp;return 1;
}
int mxb_crt_dispatch(mxb_crt_process *p,const mxb_crt_memory *m,
                     const char *library,const char *symbol,mxb_crt_regs *r){
    if(!equal(library,"msvcr90.dll",1))return 0;
    int app=equal(symbol,"__set_app_type",0),locale=equal(symbol,"_configthreadlocale",0),
        args=equal(symbol,"__getmainargs",0),
        encode=equal(symbol,"_encode_pointer",0),decode=equal(symbol,"_decode_pointer",0),onexit=equal(symbol,"_onexit",0),
        lead=equal(symbol,"_ismbblead",0),clock=equal(symbol,"_mktime64",0);
    if(!app&&!locale&&!args&&!encode&&!decode&&!onexit&&!lead&&!clock)return 0;
    if(!p||!r||!span(r->rsp,48)||(r->rsp&15u)!=8u)return -1;
    if(clock)return mktime_utc(m,r);
    if(encode||decode){
        if(!p->pointer_key)return -1;
        r->rax=encode?rotate_left(r->rcx^p->pointer_key,17u):
                      rotate_right(r->rcx,17u)^p->pointer_key;
        return 1;
    }
    if(onexit){
        if(!m||!m->executable||!r->rcx||!m->executable(m->ctx,r->rcx)||p->exit_count>=32)return -1;
        p->exit_callbacks[p->exit_count++]=r->rcx;r->rax=r->rcx;return 1;
    }
    uint32_t a=(uint32_t)r->rcx;
    /* Only ASCII under the modeled initial C locale; reject other bytes. */
    if(lead){if(a>127u)return -1;r->rax=0;return 1;}
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
