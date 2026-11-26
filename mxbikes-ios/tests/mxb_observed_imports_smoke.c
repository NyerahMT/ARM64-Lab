#include "mxb_observed_imports.h"
extern int mxb_auto_step(mxb_observed_cpu *);
static mxb_startup_imports startup;
static mxb_observed_memory memory;
static uint8_t stack[256],code[32],data[32],readonly[16];
static int same(const uint8_t *p,const char *s){
    for(size_t i=0;;i++){if(p[i]!=(uint8_t)s[i])return 0;if(!s[i])return 1;}
}
static const mxb_observed_import_site sites[]={
    {0x2000,0x100a,"MSVCR90.dll","_strupr"},
    {0x2010,0x100f,"KERNEL32.dll","GetTickCount"},
    {0x2020,0x100a,"MSVCR90.dll","unsupported_fixture"},
};
int main(void){
    static const uint8_t root[]="C:\\MXBReference",module[]="C:\\MXBReference\\mxbikes.exe";
    if(!mxb_startup_init(&startup,root,sizeof(root),module,sizeof(module),0x1000,123,42))return 1;
    if(!mxb_observed_map(&memory,0x1000,sizeof(code),code,MXB_MEM_R|MXB_MEM_X)||
       !mxb_observed_map(&memory,0x3000,sizeof(data),data,MXB_MEM_R|MXB_MEM_W)||
       !mxb_observed_map(&memory,0x4000,sizeof(readonly),readonly,MXB_MEM_R)||
       !mxb_observed_map(&memory,0x8000,sizeof(stack),stack,MXB_MEM_R|MXB_MEM_W))return 2;
    data[0]='a';data[1]='B';data[2]='c';
    mxb_observed_imports env={&memory,&startup,sites,sizeof(sites)/sizeof(sites[0])};
    mxb_observed_cpu cpu={0};cpu.ctx=&memory;cpu.read=mxb_observed_read;
    cpu.write=mxb_observed_write;cpu.write128=mxb_observed_write128;
    cpu.rip=0x1000;cpu.r[4]=0x80c0;
    mxb_observed_result r=mxb_observed_run(&cpu,mxb_auto_step,mxb_observed_import_dispatch,&env,0x1010,6);
    if(r.status!=MXB_RUN_STOP||r.instructions!=4||r.imports!=2||
       cpu.r[0]!=123||cpu.r[4]!=0x80c0||!same(data,"ABC"))return 3;
    /* Known target but unverified return address must fail closed. */
    cpu.rip=0x2000;cpu.r[4]=0x80b8;cpu.r[0]=99;cpu.r[1]=0x3000;
    data[0]='a';
    if(!mxb_observed_write(&memory,cpu.r[4],8,0x100b))return 4;
    if(mxb_observed_import_dispatch(&env,&cpu)!=-1||cpu.rip!=0x2000||cpu.r[4]!=0x80b8||cpu.r[0]!=99||data[0]!='a')return 5;
    if(!mxb_observed_write(&memory,cpu.r[4],8,0x100a))return 6;
    cpu.rip=0x2020;
    if(mxb_observed_import_dispatch(&env,&cpu)!=0||cpu.rip!=0x2020||cpu.r[4]!=0x80b8||cpu.r[0]!=99)return 7;
    cpu.rip=0x2000;cpu.r[1]=0x4000;readonly[0]='a';
    if(mxb_observed_import_dispatch(&env,&cpu)!=-1||readonly[0]!='a'||cpu.r[0]!=99||cpu.r[4]!=0x80b8)return 8;
    cpu.r[1]=0x3000;cpu.r[4]=0x80bc;
    if(mxb_observed_import_dispatch(&env,&cpu)!=-1||data[0]!='a')return 9;
    cpu.r[4]=0x80b8;
    if(mxb_observed_import_dispatch(&env,&cpu)!=1||cpu.rip!=0x100a||cpu.r[4]!=0x80c0||cpu.r[0]!=0x3000||!same(data,"ABC"))return 10;
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
