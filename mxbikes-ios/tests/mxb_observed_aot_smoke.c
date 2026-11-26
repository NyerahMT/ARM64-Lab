/* Linked against actual generated AOT shards by the Python fixture. */
#include "mxb_observed_runtime.h"
#include "mxb_observed_memory.h"
extern int mxb_auto_step(mxb_observed_cpu *);
static unsigned calls;
static int service(void *ctx,mxb_observed_cpu *s){
    if(s->rip!=0x2000)return 0;
    uint64_t ret=0;
    if(s->r[4]!=0x80f8||!mxb_observed_read(ctx,s->r[4],8,&ret)||ret!=0x100c)return -3;
    s->r[4]+=8;s->rip=ret;s->r[0]=7;calls++;return 1;
}
int main(void){
    mxb_observed_memory m={0};
    uint8_t a[2]={0},b[14]={0},stack[256]={0},ro[8]={0};
    if(!mxb_observed_map(&m,0x3000,2,a,MXB_MEM_R|MXB_MEM_W)||
       !mxb_observed_map(&m,0x3002,14,b,MXB_MEM_R|MXB_MEM_W)||
       !mxb_observed_map(&m,0x8000,sizeof(stack),stack,MXB_MEM_R|MXB_MEM_W)||
       !mxb_observed_map(&m,0x3010,8,ro,MXB_MEM_R))return 1;
    if(mxb_observed_map(&m,0x3001,2,a,MXB_MEM_R)||
       mxb_observed_map(&m,0x9000,2,a,MXB_MEM_W|MXB_MEM_X)||
       mxb_observed_map(&m,UINT64_MAX-1,2,a,MXB_MEM_R))return 2;
    uint64_t v=99;
    if(!mxb_observed_write128(&m,0x3000,UINT64_C(0x0706050403020100),UINT64_C(0x0f0e0d0c0b0a0908))||
       !mxb_observed_read(&m,0x3000,8,&v)||v!=UINT64_C(0x0706050403020100))return 3;
    if(mxb_observed_write128(&m,0x3008,0,0)||
       !mxb_observed_read(&m,0x3008,8,&v)||v!=UINT64_C(0x0f0e0d0c0b0a0908))return 4;
    if(mxb_observed_write(&m,0x300f,2,0)||b[13]!=15||ro[0])return 5;
    v=99;if(mxb_observed_read(&m,0x3017,2,&v)||v!=99||
       mxb_observed_read(&m,0x3000,3,&v)||v!=99)return 6;
    mxb_observed_cpu cpu={0};
    cpu.ctx=&m;cpu.read=mxb_observed_read;cpu.write=mxb_observed_write;
    cpu.write128=mxb_observed_write128;cpu.rip=0x1000;
    cpu.r[1]=0x3000;cpu.r[4]=0x8100;cpu.mxcsr=0x1f80;
    mxb_observed_result r=mxb_observed_run(&cpu,mxb_auto_step,service,&m,0x100f,3);
    if(r.status!=MXB_RUN_BUDGET||r.instructions!=3||r.imports||
       cpu.rip!=0x2000||cpu.r[4]!=0x80f8||calls)return 7;
    if(!mxb_observed_read(&m,0x3000,4,&v)||v!=0x12345678)return 8;
    r=mxb_observed_run(&cpu,mxb_auto_step,service,&m,0x100f,3);
    if(r.status!=MXB_RUN_STOP||r.instructions!=2||r.imports!=1||
       cpu.r[0]!=7||cpu.r[2]!=0x12345678||cpu.r[4]!=0x8100||calls!=1)return 9;
    cpu.rip=0x1004;
    r=mxb_observed_run(&cpu,mxb_auto_step,service,&m,0,1);
    if(r.status!=MXB_RUN_UNKNOWN||r.instructions||r.imports||cpu.rip!=0x1004)return 10;
    /* Actual translated store must fail without partially updating the guest. */
    cpu.rip=0x1005;cpu.r[1]=0x300f;cpu.r[0]=0xffffffff;
    r=mxb_observed_run(&cpu,mxb_auto_step,service,&m,0,1);
    if(r.status!=-2||r.instructions||b[13]!=15||ro[0])return 11;
    return 0;
}

#ifdef MXB_FREESTANDING_SMOKE
void *memset(void *p,int v,size_t n){
    volatile uint8_t *d=(volatile uint8_t*)p;
    for(size_t i=0;i<n;i++)d[i]=(uint8_t)v;
    return p;
}
void *memcpy(void *p,const void *q,size_t n){
    volatile uint8_t *d=(volatile uint8_t*)p;
    const volatile uint8_t *src=(const volatile uint8_t*)q;
    for(size_t i=0;i<n;i++)d[i]=src[i];
    return p;
}
#endif
