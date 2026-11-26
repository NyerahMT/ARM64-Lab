#ifndef MXB_OBSERVED_IMPORTS_H
#define MXB_OBSERVED_IMPORTS_H
#include "mxb_observed_memory.h"
#include "mxb_standalone_imports.h"
#ifdef __cplusplus
extern "C" {
#endif

/* Caller supplies a verified token / return-PC pair, derived from the
 * authenticated image's actual import and callsite. No guest strings or
 * host function pointers are used for import selection. Rows and strings
 * must remain immutable throughout the session. */
typedef struct {
    uint64_t token,return_pc;
    const char *library,*symbol;
} mxb_observed_import_site;
typedef struct {
    mxb_observed_memory *memory;
    mxb_startup_imports *startup;
    const mxb_observed_import_site *sites;
    size_t count;
} mxb_observed_imports;
/* Returns 1 for a supported service and completed guest return,
 * 0 for unknown service, negative for malformed/rejected call. */
int mxb_observed_import_dispatch(void *,mxb_observed_cpu *);
#ifdef __cplusplus
}
#endif
#endif
