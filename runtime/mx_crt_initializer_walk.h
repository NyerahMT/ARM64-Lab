#ifndef MX_CRT_INITIALIZER_WALK_H
#define MX_CRT_INITIALIZER_WALK_H
/*
 * Bounded Win64/MSVCR-style _initterm_e and _initterm callback traversal.
 * The guest pointer array is supplied as memory; non-null function pointers
 * are dispatched through an explicit per-target adapter. No callback is
 * silently skipped or assumed to succeed.
 *
 * This is a table iterator, not a Windows CRT, loader, ownership verifier,
 * scheduler, or interpreter. A callback returning 0 means unsupported, NOT
 * successful. A supported _initterm_e callback's nonzero 32-bit return must
 * stop the table. A supported _initterm callback's result is ignored because
 * that callback is void in the original CRT ABI.
 */
#include <stdint.h>
#include "mx_cfg_vm.h"

enum {
    MX_CRT_INIT_TABLE_COMPLETE=1,
    MX_CRT_INIT_TABLE_EARLY_ERROR=2,
    MX_CRT_INIT_TABLE_UNSUPPORTED=0,
    MX_CRT_INIT_TABLE_INVALID=-1,
    MX_CRT_INIT_TABLE_MEMORY_FAULT=-2,
    MX_CRT_INIT_TABLE_CALLBACK_FAULT=-3
};
typedef struct {
    uint64_t begin, end;
    uint64_t failed_slot_address, failed_function_address;
    uint32_t slots_examined, callbacks_invoked, skipped_nulls;
    uint32_t callback_error_status;
    uint8_t checked_e_callbacks;
} mx_crt_init_walk;
typedef int (*mx_crt_init_callback_fn)(
    void *ctx, uint64_t guest_function_address,
    uint32_t slot_index, uint8_t checked_e_callbacks,
    uint32_t *callback_result);

/* Inbound begin/end are mapped Win64 virtual addresses, not host pointers.
 * At most 64 eight-byte slots / 512 bytes per invocation. The caller must
 * supply a fail-closed callback dispatch that validates guest code identity.
 */
static inline int mx_crt_walk_initializers(
        mx_cfg_memory *guest, uint64_t begin, uint64_t end,
        uint8_t checked_e_callbacks, mx_crt_init_callback_fn dispatch,
        void *context, mx_crt_init_walk *out) {
    if (!guest || !dispatch || !out || checked_e_callbacks>1U ||
        begin==0 || end<begin || (begin&7U) || (end&7U) ||
        (end-begin)>512U)
        return MX_CRT_INIT_TABLE_INVALID;
    /* Initialize all observable fields before any guest-memory accesses. */
    mx_crt_init_walk state={0};
    state.begin=begin;state.end=end;
    state.checked_e_callbacks=checked_e_callbacks;
    for(uint32_t n=0;n<(uint32_t)((end-begin)/8U);n++){
        uint64_t slot=begin+8U*n;
        uint64_t function=0;
        state.slots_examined++;
        if (!mx_cfg_transfer(guest,slot,&function,8,0)){
            state.failed_slot_address=slot;
            *out=state;
            return MX_CRT_INIT_TABLE_MEMORY_FAULT;
        }
        if (!function) {
            state.skipped_nulls++;
            continue;
        }
        uint32_t result=0;
        int status=dispatch(context,function,n,checked_e_callbacks,&result);
        if(status!=1){
            state.failed_slot_address=slot;
            state.failed_function_address=function;
            *out=state;
            return status==0 ? MX_CRT_INIT_TABLE_UNSUPPORTED :
                               MX_CRT_INIT_TABLE_CALLBACK_FAULT;
        }
        state.callbacks_invoked++;
        if (checked_e_callbacks && result!=0){
            state.callback_error_status=result;
            state.failed_slot_address=slot;
            state.failed_function_address=function;
            *out=state;
            return MX_CRT_INIT_TABLE_EARLY_ERROR;
        }
    }
    *out=state;
    return MX_CRT_INIT_TABLE_COMPLETE;
}
#endif
