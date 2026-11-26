#include "mxb_observed_graphics.h"
static int equal(const char*a,const char*b){
    if(!a||!b)return 0;
    while(*a&&*a==*b){++a;++b;}
    return *a==*b;
}
static int guest_read(void *ctx,uint64_t addr,void *out,size_t n){
    mxb_observed_memory *mem=ctx;
    uint8_t *bytes=out;
    if(!out||!n||!mxb_observed_permitted(mem,addr,n,MXB_MEM_R))return 0;
    for(size_t i=0;i<n;i++){
        uint64_t value;
        if(!mxb_observed_read(mem,addr+i,1,&value))return 0;
        bytes[i]=(uint8_t)value;
    }
    return 1;
}
static int graphics_dispatch(void *ctx,const mxb_observed_import_site *site,mxb_observed_cpu *cpu){
    mxb_observed_graphics *g=ctx;
    if(!g||!site||!cpu||!g->surface||cpu->ctx!=g->memory)return -1;
    if(!equal(site->library,"OPENGL32.dll"))return 0;
    if(g->completed_calls==UINT64_MAX)return -1;
    MXBGLWin64Call call={0};
    call.rcx=cpu->r[1];call.rdx=cpu->r[2];call.r8=cpu->r[8];
    call.r9=cpu->r[9];call.rsp=cpu->r[4];
    for(unsigned i=0;i<4;i++)call.xmm_low64[i]=cpu->xmm[i].lo;
    g->last_status=mxb_gl_dispatch_win64(g->surface,site->library,site->symbol,
                                       &call,guest_read,g->memory);
    if(g->last_status==MXB_GL_GUEST_UNSUPPORTED)return 0;
    if(g->last_status!=MXB_GL_GUEST_OK)return -1;
    ++g->completed_calls;
    return 1;
}
int mxb_observed_graphics_attach(mxb_observed_session *s,mxb_observed_graphics *g,MXBGLSurface *surface){
    if(!s||!g||!surface||g->surface||!s->initialized||!s->imports.memory)return 0;
    if(!mxb_observed_session_attach_platform(s,graphics_dispatch,g))return 0;
    g->surface=surface;g->memory=s->imports.memory;g->completed_calls=0;
    g->last_status=MXB_GL_GUEST_OK;
    return 1;
}
