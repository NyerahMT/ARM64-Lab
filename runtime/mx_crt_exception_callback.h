#ifndef MX_CRT_EXCEPTION_CALLBACK_H
#define MX_CRT_EXCEPTION_CALLBACK_H

/* Bounded Win64 CRT callback shape: sub rsp,0x28; lea rcx,[rip+disp];
 * call [rip+IAT]; xor eax,eax; add rsp,0x28; ret.
 *
 * This models ONLY the six-instruction callback shape. It is not a Windows
 * exception dispatcher, real Kernel32, or a general callback translator.
 * The host handler-registration hook is injected, never silently assumed.
 */
#include <stdint.h>
#include "mx_crt_vm.h"

typedef int (*mx_crt_set_exception_filter_hook)(
    void *context, uint64_t new_filter, uint64_t *previous_filter);

/* original_pc and filter_addr have to be validated against private original
 * instructions by the caller; this generic runtime never embeds game bytes.
 * The nested CALL return slot survives in guest memory like real x64 CALL.
 */
static inline int mx_crt_exception_callback6(
    mx_crt_state *s, mx_cfg_memory *mem, uint64_t original_pc,
    uint64_t filter_addr, mx_crt_set_exception_filter_hook hook, void *context) {
    if (!s || !mem || !hook || s->fault || s->pending_import ||
        s->rip!=original_pc || original_pc>UINT64_MAX-17U ||
        s->rsp<0x30U || (s->rsp&15U)!=8U || s->rsp>UINT64_MAX-8U)
        return MX_CRT_INVALID;
    /* Fail closed if either portion of the guest CALL/RET stack is unmapped.
     * A return address of zero is legal; don't conflate it with a read fault.
     */
    uint64_t caller=mx_crt_read(s,mem,s->rsp,8U);
    if (s->fault) return MX_CRT_MEMORY_FAULT;
    if (!mx_crt_write(s,mem,s->rsp-0x30U,8U,original_pc+17U))
        return MX_CRT_MEMORY_FAULT;
    uint64_t previous=0;
    if (!hook(context,filter_addr,&previous)) return MX_CRT_INVALID;
    /* The original XOR EAX,EAX clears even a nonzero WinAPI return value.
     * ADD RSP,0x28 leaves ZF clear for any normally mapped guest stack.
     */
    s->rcx=filter_addr;
    s->rax=0;
    s->zf=0;
    s->rsp+=8U;
    s->rip=caller;
    s->imports++;
    s->instructions+=6U;
    s->visited|=UINT64_C(0x3f);
    return MX_CRT_RETURNED;
}
#endif
