#ifndef MXB_OWNED_STARTUP_H
#define MXB_OWNED_STARTUP_H
#include "mxb_guest_memory.h"
typedef struct {
    MXBGuestState cpu;
    uint8_t stack[4096];
    uint8_t initial_globals[16];
    uint64_t import_values[6];
    uint64_t callback_metadata[32];
    uint32_t managed_app, app_type;
    uint32_t file_modes[2];
    uint64_t exit_bounds[2], exception_filter, first_exit_handler, other_exit_handlers[2];
    uint32_t argument_count;
    uint8_t argument_block[40], argument_globals[24], object_header[24], subobjects[0x4a0];
    uint64_t crt_lock;
    uint32_t crt_phase;
    uint64_t thread_environment[8];
    uint64_t pc;
    unsigned instructions, services;
} MXBOwnedStartup;
/* Zero-initialized, caller-owned process state. -1 means source-only build. */
int mxb_owned_startup(MXBOwnedStartup *process,const MXBGuestMemory *image,uint64_t entry);
int mxb_native_launch(MXBOwnedStartup *process);
#endif
