#ifndef MXB_NATIVE_DISPATCH_H
#define MXB_NATIVE_DISPATCH_H
#include "mxb_native_exec.h"
#ifdef __cplusplus
extern "C" {
#endif
#define MXB_NATIVE_MAX_UNITS 64u
#define MXB_NATIVE_MAX_UNIT_PCS 4096u
enum { MXB_NATIVE_BAD_REGISTRY=99, MXB_NATIVE_BAD_PROGRESS=100 };
typedef int (*MXBNativeResume)(MXBGuestState*,MXBNativeCursor*,unsigned);
typedef struct {
 const uint64_t *pcs; /* sorted, verified original instruction/service PCs */
 size_t count;
 MXBNativeResume resume;
} MXBNativeUnit;
typedef struct {
 const MXBNativeUnit *units;
 size_t count;
} MXBNativeRegistry;
int mxb_native_registry_valid(const MXBNativeRegistry*r);
/* Dispatch verified translation units using one CPU, memory and cursor.
 * A unit's DONE is a local frontier, not necessarily overall completion. */
int mxb_native_dispatch(const MXBNativeRegistry*r,MXBGuestState*s,
                        MXBNativeCursor*c,unsigned quota,uint64_t final_pc);
#ifdef __cplusplus
}
#endif
#endif
