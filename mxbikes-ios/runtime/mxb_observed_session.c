#include "mxb_observed_session.h"

int mxb_observed_session_init(mxb_observed_session *s,mxb_observed_memory *mem,
    mxb_startup_imports *startup,const mxb_observed_import_site *sites,size_t count,
    mxb_observed_step step,uint64_t entry,uint64_t stack,uint64_t stop){
    if(!s||s->initialized||!mem||!startup||!step||!entry||!stack||
       (count&&!sites)||count>65536u||(stack&15u)||stack<40||
       !mxb_observed_permitted(mem,entry,1,MXB_MEM_X)||
       !mxb_observed_permitted(mem,stack-40,40,MXB_MEM_R|MXB_MEM_W))
        return 0;
    mxb_observed_session ready={0};
    ready.cpu.ctx=mem;ready.cpu.read=mxb_observed_read;
    ready.cpu.write=mxb_observed_write;ready.cpu.write128=mxb_observed_write128;
    ready.cpu.rip=entry;ready.cpu.r[4]=stack;
    ready.cpu.flags=2;ready.cpu.mxcsr=0x1f80;
    ready.imports=(mxb_observed_imports){mem,startup,sites,count,0,0};
    ready.step=step;ready.stop=stop;ready.initialized=1;ready.status=MXB_RUN_BUDGET;
    *s=ready;return 1;
}
int mxb_observed_session_attach_platform(mxb_observed_session *s,mxb_observed_platform_service service,void *ctx){
    if(!s||!s->initialized||s->terminal||s->instructions||s->services||!service||!ctx||s->imports.platform_service)return 0;
    s->imports.platform_service=service;s->imports.platform_context=ctx;return 1;
}
mxb_observed_result mxb_observed_session_tick(mxb_observed_session *s,uint64_t budget){
    mxb_observed_result result={0,0,s?s->cpu.rip:0,MXB_RUN_INVALID};
    if(!s||!s->initialized||!budget||budget>MXB_SESSION_SLICE_MAX)return result;
    if(s->terminal){result.status=s->status;return result;}
    if(s->instructions>UINT64_MAX-budget||s->services>UINT64_MAX-budget){
        s->terminal=1;s->status=MXB_RUN_INVALID;return result;
    }
    result=mxb_observed_run(&s->cpu,s->step,mxb_observed_import_dispatch,
                            &s->imports,s->stop,budget);
    s->instructions+=result.instructions;s->services+=result.imports;
    s->status=result.status;
    if(result.status!=MXB_RUN_BUDGET)s->terminal=1;
    return result;
}
