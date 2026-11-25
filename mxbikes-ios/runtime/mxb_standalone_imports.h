#ifndef MXB_STANDALONE_IMPORTS_H
#define MXB_STANDALONE_IMPORTS_H
#include "mxb_standalone_platform.h"
#include "mxb_standalone_crt.h"
#include "mxb_standalone_heap.h"
/* Native import dispatcher for the standalone startup model. Callsite and
 * guest region provenance must be established by the caller. */
typedef struct {
    mxb_platform platform;
    mxb_crt_process crt;
    uint8_t module_path[MXB_PATH_CAP];
    uint64_t image_base, exception_filter;
    mxb_heap heap;
} mxb_startup_imports;
int mxb_startup_init(mxb_startup_imports *,const uint8_t *,size_t,
                     const uint8_t *,size_t,uint64_t,uint64_t,uint64_t);
int mxb_startup_dispatch(mxb_startup_imports *,const mxb_crt_memory *,
                         const char *,const char *,mxb_crt_regs *);
#endif
