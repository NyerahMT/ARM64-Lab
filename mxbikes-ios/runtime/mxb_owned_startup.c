#if defined(__linux__) && !defined(_GNU_SOURCE)
#define _GNU_SOURCE
#endif
#include "mxb_owned_startup.h"
#include <stdlib.h>
void mxb_owned_startup_dispose(MXBOwnedStartup *p){
    if(!p)return;
    free(p->image_backing);p->image_backing=NULL;p->cpu.memory.count=0;
}
#if __has_include("private/mxb_private_startup.c")
#include "../../runtime/mx_import_registry.h"
#include <pthread.h>
#include <time.h>
#include <unistd.h>

extern int mxb_private_startup(MXBOwnedStartup *,const mx_import_runtime *);

static uint64_t read_clock(void *context,clockid_t clock){
    struct timespec t;
    if(clock_gettime(clock,&t)!=0 || t.tv_sec<0){
        *(int *)context=1;
        return 0;
    }
    return (uint64_t)t.tv_sec*1000000000u+(uint64_t)t.tv_nsec;
}
static uint64_t monotonic_ns(void *context){return read_clock(context,CLOCK_MONOTONIC);}
static uint64_t realtime_ns(void *context){return read_clock(context,CLOCK_REALTIME);}
static uint32_t process_id(void *context){(void)context;return (uint32_t)getpid();}
static uint32_t thread_id(void *context){
    (void)context;
#if defined(__APPLE__)
    uint64_t value=0;
    return pthread_threadid_np(NULL,&value)==0 && value<=UINT32_MAX ? (uint32_t)value : 0;
#else
    return (uint32_t)gettid();
#endif
}
static int write_guest(void *context,uint64_t address,const uint8_t *bytes,uint32_t count){
    return mxb_guest_write((MXBGuestMemory *)context,address,bytes,count);
}
int mxb_owned_startup(MXBOwnedStartup *p,const MXBGuestMemory *image,uint64_t entry){
    if(!p || !image || p->pc)return 0;
    p->cpu.memory=*image;
    const uint64_t stack_base=UINT64_C(0x720000000);
    if(!mxb_guest_map(&p->cpu.memory,stack_base,p->stack,sizeof(p->stack),MXB_MEM_READ|MXB_MEM_WRITE))return 0;
    p->pc=entry;p->cpu.r[MXB_RSP]=stack_base+MXB_STARTUP_STACK_OFFSET;p->cpu.flags=0x202;
    int clock_failed=0;
    const mx_clock_source clock={&clock_failed,monotonic_ns,realtime_ns,NULL};
    mx_import_runtime runtime={&clock,write_guest,&p->cpu.memory,NULL,process_id,thread_id};
    return mxb_private_startup(p,&runtime) && !clock_failed;
}
#include "private/mxb_launch.inc"
#else
int mxb_native_launch(MXBOwnedStartup *p){(void)p;return -1;}
int mxb_owned_startup(MXBOwnedStartup *p,const MXBGuestMemory *image,uint64_t entry){
    (void)p;(void)image;(void)entry;
    return -1;
}
#endif
