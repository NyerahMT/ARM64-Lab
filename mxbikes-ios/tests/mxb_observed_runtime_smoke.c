#include "mxb_observed_runtime.h"
#define IMPORT UINT64_C(0x700000000)
static unsigned calls;
static int step(mxb_observed_cpu *s){
    switch(s->rip){
    case 0x1000:s->r[0]++;s->rip=0x1001;return 1;
    case 0x1001:s->rip=IMPORT;return 1;
    case 0x1002:s->r[0]+=2;s->rip=0x1003;return 1;
    case 0x2000:return -7;
    case 0x3000:s->rip++;return 2;
    case 0x4000:return 0;
    case 0x5000:return 1; /* legitimate self loop, bounded by budget */
    default:return 2;
    }
}
static int service(void *p,mxb_observed_cpu *s){
    (void)p;++calls;
    if(s->rip!=IMPORT)return 0;
    s->r[0]+=10;s->rip=0x1002;return 1;
}
static int stalled(void*p,mxb_observed_cpu*s){(void)p;(void)s;return 1;}
int main(void){
    mxb_observed_cpu cpu={0};mxb_observed_result r;
    cpu.rip=0x1000;
    r=mxb_observed_run(&cpu,step,service,0,0x1003,4);
    if(r.status!=MXB_RUN_STOP||r.instructions!=3||r.imports!=1||r.terminal_pc!=0x1003||cpu.r[0]!=13||calls!=1)return 1;
    cpu.rip=0x1000;cpu.r[0]=0;calls=0;
    r=mxb_observed_run(&cpu,step,service,0,0x1003,2);
    if(r.status!=MXB_RUN_BUDGET||r.instructions!=2||r.imports||r.terminal_pc!=IMPORT||calls)return 2;
    r=mxb_observed_run(&cpu,step,0,0,0x1003,10);
    if(r.status!=MXB_RUN_UNKNOWN||r.instructions||r.imports||r.terminal_pc!=IMPORT)return 3;
    r=mxb_observed_run(&cpu,step,stalled,0,0x1003,10);
    if(r.status!=MXB_RUN_IMPORT_NO_PROGRESS||r.imports)return 4;
    r=mxb_observed_run(&cpu,step,service,0,0x1003,2);
    if(r.status!=MXB_RUN_STOP||r.instructions!=1||r.imports!=1||cpu.r[0]!=13)return 5;
    cpu.rip=0x2000;r=mxb_observed_run(&cpu,step,service,0,0,1);
    if(r.status!=-7||r.instructions||r.imports||calls!=1)return 6;
    cpu.rip=0x3000;r=mxb_observed_run(&cpu,step,service,0,0,1);
    if(r.status!=MXB_RUN_STEP_CONTRACT||r.imports||calls!=1)return 7;
    cpu.rip=0x4000;r=mxb_observed_run(&cpu,step,service,0,0,1);
    if(r.status!=MXB_RUN_STEP_CONTRACT||r.instructions)return 8;
    cpu.rip=0x5000;r=mxb_observed_run(&cpu,step,service,0,0,9);
    if(r.status!=MXB_RUN_BUDGET||r.instructions!=9||r.terminal_pc!=0x5000)return 9;
    r=mxb_observed_run(&cpu,step,service,0,0,UINT64_C(16777217));
    if(r.status!=MXB_RUN_INVALID||r.instructions)return 10;
    r=mxb_observed_run(0,step,service,0,0,1);
    if(r.status!=MXB_RUN_INVALID)return 11;
    return 0;
}
