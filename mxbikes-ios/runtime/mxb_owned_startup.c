#include "mxb_owned_startup.h"
#include "../../runtime/mx_import_registry.h"
#include <pthread.h>
#include <time.h>
#include <unistd.h>

#if defined(__APPLE__)
#define MXB_OPTIONAL __attribute__((weak_import))
#else
#define MXB_OPTIONAL __attribute__((weak))
#endif
extern int mxb_private_startup(MXBOwnedStartup *,const mx_import_runtime *) MXB_OPTIONAL;

static uint64_t monotonic_ns(void *context){
    (void)context;
    struct timespec t;
    return clock_gettime(CLOCK_MONOTONIC,&t)==0 ? (uint64_t)t.tv_sec*1000000000u+(uint64_t)t.tv_nsec : 0;
}
static uint64_t realtime_ns(void *context){
    (void)context;
    struct timespec t;
    return clock_gettime(CLOCK_REALTIME,&t)==0 ? (uint64_t)t.tv_sec*1000000000u+(uint64_t)t.tv_nsec : 0;
}
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
    if(!mxb_private_startup)return -1;
    if(!p || !image || p->pc)return 0;
    p->cpu.memory=*image;
    const uint64_t stack_base=UINT64_C(0x720000000);
    if(!mxb_guest_map(&p->cpu.memory,stack_base,p->stack,sizeof(p->stack),MXB_MEM_READ|MXB_MEM_WRITE))return 0;
    p->pc=entry;p->cpu.r[MXB_RSP]=stack_base+0xc08u;p->cpu.flags=0x202;
    const mx_clock_source clock={NULL,monotonic_ns,realtime_ns,NULL};
    mx_import_runtime runtime={&clock,write_guest,&p->cpu.memory,NULL,process_id,thread_id};
    return mxb_private_startup(p,&runtime);
}
