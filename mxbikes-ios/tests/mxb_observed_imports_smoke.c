#include "mxb_observed_session.h"
extern int mxb_auto_step(mxb_observed_cpu *);
static mxb_startup_imports startup;
static mxb_observed_memory memory;
static uint8_t stack[256],code[32],data[256],readonly[16];
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
    mxb_observed_session session={0};
    if(mxb_observed_session_init(&session,&memory,&startup,sites,3,mxb_auto_step,0x3000,0x80c0,0x1010))return 19;
    if(mxb_observed_session_init(&session,&memory,&startup,sites,3,mxb_auto_step,0x1000,0x4000,0x1010))return 20;
    if(!mxb_observed_session_init(&session,&memory,&startup,sites,3,mxb_auto_step,0x1000,0x80c0,0x1010))return 21;
    if(mxb_observed_session_tick(&session,MXB_SESSION_SLICE_MAX+1).status!=MXB_RUN_INVALID||session.instructions)return 22;
    mxb_observed_result r=mxb_observed_session_tick(&session,2);
    if(r.status!=MXB_RUN_BUDGET||r.instructions!=2||r.imports||session.cpu.rip!=0x2000)return 23;
    r=mxb_observed_session_tick(&session,4);
    mxb_observed_cpu cpu=session.cpu;
    if(r.status!=MXB_RUN_STOP||session.instructions!=4||session.services!=2||
       cpu.r[0]!=123||cpu.r[4]!=0x80c0||!same(data,"ABC"))return 3;
    r=mxb_observed_session_tick(&session,1);
    if(r.status!=MXB_RUN_STOP||r.instructions||r.imports||!session.terminal)return 24;
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
    static const uint8_t asset[]={1,2,3};
    if(!mxb_files_mount(&startup.files,"series.pkz",asset,sizeof(asset))||
       !mxb_files_mark_absent_directory(&startup.files,"SeRiEs")||
       !mxb_files_mark_absent_directory(&startup.files,"series")||
       mxb_files_mark_absent_directory(&startup.files,"../series")||
       mxb_files_mount(&startup.files,"series",asset,sizeof(asset)))return 11;
    /* Exercise the identical native import boundary with a known return PC. */
    static const mxb_observed_import_site file_sites[]={
        {0x2030,0x100a,"MSVCR90.dll","fopen"},
        {0x2040,0x100a,"MSVCR90.dll","_findfirst64i32"},
    };
    mxb_observed_imports files_env={&memory,&startup,file_sites,2};
    static const char *const paths[]={"series/.pkz","SERIES\\sm\\test.ini","series/../outside","unverified/.pkz","series.pkz"};
    for(unsigned i=0;i<5;i++){
        const char *p=paths[i];size_t k=0;do{data[k]=(uint8_t)p[k];}while(p[k++]);
        data[128]='r';data[129]='b';data[130]=0;
        cpu.rip=0x2030;cpu.r[4]=0x80b8;cpu.r[0]=99;cpu.r[1]=0x3000;cpu.r[2]=0x3080;
        if(!mxb_observed_write(&memory,cpu.r[4],8,0x100a))return 12;
        int result=mxb_observed_import_dispatch(&files_env,&cpu);
        if(i<2){if(result!=1||cpu.r[0]||cpu.rip!=0x100a)return 13;}
        else if(i<4){if(result!=0||cpu.r[0]!=99||cpu.rip!=0x2030)return 14;}
        else if(result!=1||!cpu.r[0])return 15;
    }
    static const char *const patterns[]={"series/*.*","series/sm/*.pkz","series/*/x.ini","other/*.*"};
    for(unsigned i=0;i<4;i++){
        const char *p=patterns[i];size_t k=0;do{data[k]=(uint8_t)p[k];}while(p[k++]);
        data[128]=0x5a;
        cpu.rip=0x2040;cpu.r[4]=0x80b8;cpu.r[0]=99;cpu.r[1]=0x3000;cpu.r[2]=0x3080;
        int result=mxb_observed_import_dispatch(&files_env,&cpu);
        if(data[128]!=0x5a)return 16;
        if(i<2){if(result!=1||cpu.r[0]!=UINT64_MAX)return 17;}
        else if(result!=0||cpu.r[0]!=99)return 18;
    }
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
