#ifndef MX_GUEST_IMPORTS_H
#define MX_GUEST_IMPORTS_H
#include <stdint.h>
#include "mx_time_compat.h"

/*
 * Register-oriented guest-call boundary for selected Win32/WinMM imports.
 * This does not implement instruction translation or Windows x64 stack args.
 */
typedef struct {
    uint64_t rcx;
    uint64_t rdx;
    uint64_t r8;
    uint64_t r9;
    uint64_t rax;
} mx_win64_call;

typedef int (*mx_guest_write)(void *userdata, uint64_t address,
                              const uint8_t *bytes, uint32_t count);

typedef struct {
    const mx_clock_source *clock;
    mx_guest_write write;
    void *write_userdata;
} mx_import_runtime;

/* Outcomes: 1 handled successfully, 0 unknown API, -1 recognized but failed. */
int mx_dispatch_timing_import(const mx_import_runtime *runtime,
                              const char *dll, const char *api,
                              mx_win64_call *call);
#endif
