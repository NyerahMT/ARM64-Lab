#ifndef MXB_NATIVE_EXEC_H
#define MXB_NATIVE_EXEC_H
#include "mxb_guest_memory.h"
#ifdef __cplusplus
extern "C" {
#endif
/* Caller-owned resumable cursor. Native code must report an original guest PC,
 * and never use a guest address as a host function pointer. */
typedef struct {uint64_t pc,trace;unsigned steps;} MXBNativeCursor;
enum {
 MXB_NATIVE_DONE=0, MXB_NATIVE_MEMORY_FAULT=90, MXB_NATIVE_BUDGET=91,
 MXB_NATIVE_UNKNOWN_PC=92, MXB_NATIVE_YIELD=93,
 MXB_NATIVE_BAD_IMPORT_RETURN=97, MXB_NATIVE_IMPORT_FAILED=98
};
/* Generated public synthetic module, never the commercial game binary. */
MXBNativeCursor mxb_native_probe_begin(void);
int mxb_native_probe_resume(MXBGuestState*s,MXBNativeCursor*c,unsigned quota);
int mxb_native_probe_smoke(void);
#ifdef __cplusplus
}
#endif
#endif
