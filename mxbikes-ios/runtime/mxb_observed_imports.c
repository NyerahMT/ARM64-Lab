#include "mxb_observed_imports.h"

#define SITE_CAP 65536u
static int read_bytes(void *ctx,uint64_t addr,uint8_t *dst,size_t n){
    mxb_observed_memory *mem=ctx;
    if(!dst||!mxb_observed_permitted(mem,addr,n,MXB_MEM_R))return 0;
    for(size_t i=0;i<n;i++){
        uint64_t value;
        if(!mxb_observed_read(mem,addr+i,1,&value))return 0;
        dst[i]=(uint8_t)value;
    }
    return 1;
}
static int writable(void *ctx,uint64_t addr,size_t n){
    return mxb_observed_permitted(ctx,addr,n,MXB_MEM_W);
}
static void write_bytes(void *ctx,uint64_t addr,const uint8_t *src,size_t n){
    /* The underlying service validates the full output span first; the
     * caller owns a stable, single-threaded mapping for this dispatch. */
    if(!src||!writable(ctx,addr,n))return;
    for(size_t i=0;i<n;i++)mxb_observed_write(ctx,addr+i,1,src[i]);
}
static int executable(void *ctx,uint64_t addr){
    return mxb_observed_permitted(ctx,addr,1,MXB_MEM_X);
}
int mxb_observed_import_dispatch(void *context,mxb_observed_cpu *cpu){
    mxb_observed_imports *env=context;
    if(!env||!cpu||!env->memory||!env->startup||
       env->count>SITE_CAP||(env->count&&!env->sites))return -1;
    if(cpu->ctx!=env->memory||cpu->read!=mxb_observed_read||
       cpu->write!=mxb_observed_write||cpu->write128!=mxb_observed_write128)return -1;
    size_t i;int known=0;
    for(i=0;i<env->count;i++)if(env->sites[i].token==cpu->rip){known=1;break;}
    if(!known)return 0;
    if(executable(env->memory,cpu->rip))return -1;
    uint64_t rsp=cpu->r[4],ret=0;
    if((rsp&15u)!=8u||rsp>UINT64_MAX-48||
       !mxb_observed_permitted(env->memory,rsp,40,MXB_MEM_R)||
       !mxb_observed_read(env->memory,rsp,8,&ret)||
       !executable(env->memory,ret))return -1;
    const mxb_observed_import_site *site=0;
    for(;i<env->count;i++){
        const mxb_observed_import_site *row=&env->sites[i];
        if(row->token==cpu->rip&&row->return_pc==ret){
            if(site)return -1;
            site=row;
        }
    }
    if(!site||!site->library||!site->symbol)return -1;
    mxb_crt_memory mem={env->memory,read_bytes,writable,write_bytes,executable};
    mxb_crt_regs regs={cpu->r[1],cpu->r[2],cpu->r[8],cpu->r[9],rsp,cpu->r[0]};
    int status=mxb_startup_dispatch(env->startup,&mem,site->library,site->symbol,&regs);
    if(status==0&&env->platform_service){
        status=env->platform_service(env->platform_context,site,cpu);
        if(cpu->rip!=site->token||cpu->r[4]!=rsp)return -1;
        if(status==1)regs.rax=cpu->r[0];
    }
    if(status!=1)return status<0?status:0;
    cpu->r[0]=regs.rax;
    cpu->r[4]=rsp+8;
    cpu->rip=ret;
    return 1;
}
