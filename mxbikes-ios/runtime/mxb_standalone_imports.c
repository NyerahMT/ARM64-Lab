#include "mxb_standalone_imports.h"
#include "mxb_standalone_memory.h"
static int eq(const char *a,const char *b,int fold){
    if(!a||!b)return 0;
    while(*a&&*b){unsigned x=(unsigned char)*a++,y=(unsigned char)*b++;
        if(fold&&x>='A'&&x<='Z')x+=32;
        if(fold&&y>='A'&&y<='Z')y+=32;
        if(x!=y)return 0;
    }return *a==*b;
}
static int span(uint64_t a,size_t n){return a&&n&&a<=UINT64_MAX-n;}
static size_t length(const uint8_t *s){size_t n=0;while(n<MXB_PATH_CAP&&s[n])n++;return n;}
static int readstr(const mxb_crt_memory *m,uint64_t a,uint8_t *s,size_t *n){
    if(!span(a,MXB_PATH_CAP)||!m||!m->read)return 0;
    for(size_t i=0;i<MXB_PATH_CAP;i++){
        if(!m->read(m->ctx,a+i,s+i,1))return 0;
        if(!s[i]){*n=i+1;return 1;}
    }return 0;
}
static int output(const mxb_crt_memory *m,uint64_t a,const uint8_t *s,size_t n){
    if(!span(a,n)||!m||!m->writable||!m->write||!m->writable(m->ctx,a,n))return 0;
    m->write(m->ctx,a,s,n);return 1;
}
int mxb_startup_init(mxb_startup_imports *p,const uint8_t *root,size_t rn,
                     const uint8_t *path,size_t pn,uint64_t image,uint64_t ticks,uint64_t key){
    if(!p||!path||!pn||pn>MXB_PATH_CAP||!image||!key||path[pn-1])return 0;
    mxb_startup_imports v={0};
    if(!mxb_platform_init(&v.platform,root,rn,ticks))return 0;
    for(size_t i=0;i<pn;i++){if(i+1<pn&&!path[i])return 0;v.module_path[i]=path[i];}
    v.image_base=image;v.crt.locale_mode=2;v.crt.pointer_key=key;*p=v;return 1;
}
int mxb_startup_dispatch(mxb_startup_imports *p,const mxb_crt_memory *m,
                         const char *dll,const char *name,mxb_crt_regs *r){
    int crt=eq(dll,"msvcr90.dll",1),win=eq(dll,"kernel32.dll",1)||eq(dll,"kernelbase.dll",1),mm=eq(dll,"winmm.dll",1);
    if(!crt&&!win&&!mm)return 0;
    if(!p||!r||(r->rsp&15)!=8||!span(r->rsp,48))return -1;
    uint8_t buf[MXB_PATH_CAP];size_t n=0;uint32_t cap=(uint32_t)r->rdx;
    if(crt){
        int memory=mxb_memory_dispatch(m,name,r);
        if(memory!=0)return memory;
        int heap=mxb_heap_dispatch(&p->heap,m,name,r);
        if(heap!=0)return heap;
        if(eq(name,"strcpy",0)){
            if(!readstr(m,r->rdx,buf,&n)||!output(m,r->rcx,buf,n))return -1;
            r->rax=r->rcx;return 1;
        }
        if(eq(name,"strrchr",0)){
            if(!readstr(m,r->rcx,buf,&n))return -1;
            r->rax=0;while(n){n--;if(buf[n]==(uint8_t)r->rdx){r->rax=r->rcx+n;break;}}return 1;
        }
        return mxb_crt_dispatch(&p->crt,m,dll,name,r);
    }
    if(mm){
        if(eq(name,"timeGetTime",0))r->rax=mxb_platform_ticks(&p->platform);
        else if(eq(name,"timeBeginPeriod",0))r->rax=mxb_platform_timer_begin(&p->platform,(uint32_t)r->rcx);
        else if(eq(name,"timeEndPeriod",0))r->rax=mxb_platform_timer_end(&p->platform,(uint32_t)r->rcx);
        else return 0;
        return 1;
    }
    if(eq(name,"GetTickCount",0))r->rax=mxb_platform_ticks(&p->platform);
    else if(eq(name,"GetTickCount64",0))r->rax=p->platform.elapsed_ms;
    else if(eq(name,"GetLastError",0))r->rax=p->platform.last_error;
    else if(eq(name,"SetLastError",0))p->platform.last_error=(uint32_t)r->rcx;
    else if(eq(name,"SetCurrentDirectoryA",0)){
        if(!readstr(m,r->rcx,buf,&n))return -1;
        r->rax=mxb_platform_set_directory(&p->platform,buf,n);
    }else if(eq(name,"GetCurrentDirectoryA",0)){
        cap=(uint32_t)r->rcx;n=length(p->platform.cwd);
        if(!n||n>=MXB_PATH_CAP)return -1;
        if(cap<=n)r->rax=n+1;
        else{if(!output(m,r->rdx,p->platform.cwd,n+1))return -1;r->rax=n;}
    }else if(eq(name,"GetModuleFileNameA",0)){
        if(r->rcx&&r->rcx!=p->image_base)return -1;
        cap=(uint32_t)r->r8;n=length(p->module_path);
        /* Exact nontruncated path only; other cases remain unsupported. */
        if(!n||n>=MXB_PATH_CAP||cap<=n||!output(m,r->rdx,p->module_path,n+1))return -1;
        r->rax=n;
    }else if(eq(name,"SetUnhandledExceptionFilter",0)){
        if(r->rcx&&(!m||!m->executable||!m->executable(m->ctx,r->rcx)))return -1;
        r->rax=p->exception_filter;p->exception_filter=r->rcx;
    }else return 0;
    return 1;
}
