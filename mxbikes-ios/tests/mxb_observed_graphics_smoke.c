/* Synthetic generated AOT calls, never original game rendering. */
#include "mxb_observed_graphics.h"
extern int mxb_auto_step(mxb_observed_cpu *);
static mxb_startup_imports startup;
static mxb_observed_memory mem;
static uint8_t code[64],stack[256];
static float vertices[9]={-0.5f,-0.5f,0.0f,0.5f,-0.5f,0.0f,0.0f,0.5f,0.0f};
static const mxb_observed_import_site sites[]={
    {0x2000,0x100a,"OPENGL32.dll","glBegin"},
    {0x2010,0x1014,"OPENGL32.dll","glVertex3fv"},
    {0x2010,0x101e,"OPENGL32.dll","glVertex3fv"},
    {0x2010,0x1028,"OPENGL32.dll","glVertex3fv"},
    {0x2020,0x102d,"OPENGL32.dll","glEnd"},
    {0x2030,0x102d,"OPENGL32.dll","glUnsupportedFixture"}
};
static int test(MXBGLSurface *surface){
    static const uint8_t root[]="C:\\MXBReference",module[]="C:\\MXBReference\\mxbikes.exe";
    if(!mxb_startup_init(&startup,root,sizeof(root),module,sizeof(module),0x1000,123,42))return 1;
    if(!mxb_observed_map(&mem,0x1000,sizeof(code),code,MXB_MEM_R|MXB_MEM_X)||
       !mxb_observed_map(&mem,0x3000,sizeof(vertices),(uint8_t*)vertices,MXB_MEM_R)||
       !mxb_observed_map(&mem,0x8000,sizeof(stack),stack,MXB_MEM_R|MXB_MEM_W))return 2;
    mxb_observed_session s={0};mxb_observed_graphics g={0};
    if(!mxb_observed_session_init(&s,&mem,&startup,sites,sizeof(sites)/sizeof(sites[0]),mxb_auto_step,0x1000,0x80c0,0x102d))return 3;
    if(!mxb_observed_graphics_attach(&s,&g,surface)||mxb_observed_graphics_attach(&s,&g,surface))return 4;
    mxb_observed_result r=mxb_observed_session_tick(&s,4);
    if(r.status!=MXB_RUN_BUDGET||g.completed_calls!=1)return 5;
    r=mxb_observed_session_tick(&s,32);
    if(r.status!=MXB_RUN_STOP||s.instructions!=9||s.services!=5||g.completed_calls!=5||s.cpu.r[4]!=0x80c0)return 6;
    if(mxb_gl_vertex_count(surface)!=3||mxb_gl_batch_count(surface)!=1)return 7;
    const MXBGLVertex *out=mxb_gl_vertices(surface);
    if(!out)return 8;
    for(unsigned i=0;i<3;i++)for(unsigned k=0;k<3;k++)if(out[i].position[k]!=vertices[i*3+k])return 9;
    /* Unknown symbol and forged return must not reach the renderer. */
    s.cpu.r[4]=0x80b8;s.cpu.rip=0x2030;
    if(!mxb_observed_write(&mem,s.cpu.r[4],8,0x102d))return 10;
    if(mxb_observed_import_dispatch(&s.imports,&s.cpu)!=0||g.completed_calls!=5||s.cpu.rip!=0x2030)return 11;
    s.cpu.rip=0x2000;
    if(mxb_observed_import_dispatch(&s.imports,&s.cpu)!=-1||g.completed_calls!=5)return 12;
    /* A valid import site but unmapped vertex must not commit a draw. */
    s.cpu.rip=0x2010;s.cpu.r[1]=0x5000;
    if(!mxb_observed_write(&mem,s.cpu.r[4],8,0x1014))return 13;
    if(mxb_observed_import_dispatch(&s.imports,&s.cpu)!=-1||g.completed_calls!=5||mxb_gl_vertex_count(surface)!=3)return 14;
    return 0;
}
int main(void){MXBGLSurface *s=mxb_gl_create();if(!s)return 15;int result=test(s);mxb_gl_destroy(s);return result;}

#ifdef MXB_FREESTANDING_SMOKE
/* Single bounded surface allocation for isolated ARM64 ELF fixture only. */
static _Alignas(16) uint8_t arena[512*1024];
static int allocated;
void *calloc(size_t count,size_t size){
    if(allocated||!size||count>sizeof(arena)/size)return 0;
    allocated=1;
    for(size_t i=0;i<count*size;i++)((volatile uint8_t*)arena)[i]=0;
    return arena;
}
void free(void *p){if(p==arena)allocated=0;}
void *memset(void *p,int v,size_t n){
    for(size_t i=0;i<n;i++)((volatile uint8_t*)p)[i]=(uint8_t)v;
    return p;
}
void *memcpy(void *p,const void *q,size_t n){
    for(size_t i=0;i<n;i++)((volatile uint8_t*)p)[i]=((const volatile uint8_t*)q)[i];
    return p;
}
#endif
