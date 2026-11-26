#ifndef MXB_OBSERVED_SESSION_H
#define MXB_OBSERVED_SESSION_H
#include "mxb_observed_imports.h"
#ifdef __cplusplus
extern "C" {
#endif
/* Caller owns and prepares the authenticated guest image, stack, service
 * state and immutable verified import sites. No executable loader or
 * authorization service is provided by this controller. */
#define MXB_SESSION_SLICE_MAX UINT64_C(65536)
typedef struct {
    mxb_observed_cpu cpu;
    mxb_observed_imports imports;
    mxb_observed_step step;
    uint64_t stop,instructions,services;
    int initialized,terminal,status;
} mxb_observed_session;
/* Session must be zero-initialized and remain at a stable address.
 * The memory and startup state must outlive the session. */
int mxb_observed_session_init(mxb_observed_session *,mxb_observed_memory *,
    mxb_startup_imports *,const mxb_observed_import_site *,size_t,
    mxb_observed_step,uint64_t entry,uint64_t stack,uint64_t stop);
/* Platform adapter and context must outlive this session. Attach once, before execution. */
int mxb_observed_session_attach_platform(mxb_observed_session *,mxb_observed_platform_service,void *);
mxb_observed_result mxb_observed_session_tick(mxb_observed_session *,uint64_t budget);
#ifdef __cplusplus
}
#endif
#endif
