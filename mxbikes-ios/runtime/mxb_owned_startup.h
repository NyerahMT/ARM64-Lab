#ifndef MXB_OWNED_STARTUP_H
#define MXB_OWNED_STARTUP_H
#include "mxb_guest_memory.h"
typedef struct {
    MXBGuestState cpu;
    uint8_t stack[4096];
    uint64_t pc;
    unsigned instructions, services;
} MXBOwnedStartup;
/* Zero-initialized, caller-owned process state. -1 means source-only build. */
int mxb_owned_startup(MXBOwnedStartup *process,const MXBGuestMemory *image,uint64_t entry);
#endif
