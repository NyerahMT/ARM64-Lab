#ifndef MX_CRT_STARTUP_BRIDGE_H
#define MX_CRT_STARTUP_BRIDGE_H
/* Native guest startup import-to-initializer bridge.
 * Guest addresses are prevalidated by the invoking runner.
 * The dispatcher must execute an independently verified callback body;
 * this bridge never invents a callback return value or a success.
 */
#include <stdint.h>
#include "mx_crt_init_imports.h"
#include "mx_crt_initializer_walk.h"

typedef struct {
    mx_cfg_memory *memory;
    mx_crt_init_callback_fn callback;
    void *callback_context;
    uint64_t checked_begin, checked_end;
    uint64_t plain_begin, plain_end;
    mx_crt_init_walk last;
    uint32_t checked_calls, plain_calls;
    uint32_t checked_callbacks, plain_callbacks;
    uint8_t stage;
} mx_crt_startup_bridge;

/* Invoked by mx_crt_invoke_init_thunk: stage 0 accepts _initterm_e;
 * stage 1 accepts _initterm; stage 2 is complete; stage 3 is early error.
 * Invalid/missing callback bodies are failures, not permitted to advance.
 */
static inline int mx_crt_startup_bridge_call(
        void *opaque, uint32_t kind, uint64_t first,
        uint64_t last, uint32_t *retval) {
    mx_crt_startup_bridge *b=(mx_crt_startup_bridge*)opaque;
    if (!b || !b->memory || !b->callback || !retval)
        return 0;
    if (kind==MX_CRT_INITTERM_E) {
        if (b->stage!=0U || first!=b->checked_begin ||
            last!=b->checked_end) return 0;
        mx_crt_init_walk trace={0};
        int outcome=mx_crt_walk_initializers(
            b->memory,first,last,1U,b->callback,b->callback_context,&trace);
        b->last=trace;
        if (outcome!=MX_CRT_INIT_TABLE_COMPLETE &&
            outcome!=MX_CRT_INIT_TABLE_EARLY_ERROR)return 0;
        b->checked_calls++;
        b->checked_callbacks+=trace.callbacks_invoked;
        *retval=trace.callback_error_status;
        b->stage=outcome==MX_CRT_INIT_TABLE_EARLY_ERROR?3U:1U;
        return 1;
    }
    if (kind==MX_CRT_INITTERM) {
        if (b->stage!=1U || first!=b->plain_begin ||
            last!=b->plain_end)return 0;
        mx_crt_init_walk trace={0};
        int outcome=mx_crt_walk_initializers(
            b->memory,first,last,0U,b->callback,b->callback_context,&trace);
        b->last=trace;
        if (outcome!=MX_CRT_INIT_TABLE_COMPLETE)return 0;
        b->plain_calls++;
        b->plain_callbacks+=trace.callbacks_invoked;
        *retval=0U;
        b->stage=2U;
        return 1;
    }
    return 0;
}
#endif
