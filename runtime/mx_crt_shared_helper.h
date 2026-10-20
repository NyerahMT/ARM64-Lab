#ifndef MX_CRT_SHARED_HELPER_H
#define MX_CRT_SHARED_HELPER_H
/* Bounded Win64 wrapper:
 * sub rsp,0x28; call rel32; neg rax; sbb eax,eax; neg eax;
 * dec eax; add rsp,0x28; ret.
 *
 * Models the wrapper AFTER validation of original direct-call identity.
 * The underlying registration routine is NOT executed here: a typed,
 * explicit injected hook returns its pointer/status. No real Windows
 * loader, CRT, exception registration or game engine is implied.
 */
#include <stdint.h>
#include "mx_crt_vm.h"
typedef int (*mx_crt_shared_callee_hook)(void *context,
                                        uint64_t rcx_arg,
                                        uint64_t *callee_result);

static inline int mx_crt_shared_helper8(
        mx_crt_state *s, mx_cfg_memory *mem, uint64_t entry_pc,
        mx_crt_shared_callee_hook hook, void *context) {
    if (!s || !mem || !hook || s->fault || s->pending_import ||
        s->rip!=entry_pc || entry_pc>UINT64_MAX-9U ||
        s->rsp<0x30U || (s->rsp&15U)!=8U || s->rsp>UINT64_MAX-8U)
        return MX_CRT_INVALID;
    uint64_t return_pc=mx_crt_read(s,mem,s->rsp,8U);
    if (s->fault) return MX_CRT_MEMORY_FAULT;
    /* Original near CALL begins 4 bytes after entry, length 5.
     * It leaves a guest return-slot at [entry RSP - 0x30].
     */
    if (!mx_crt_write(s,mem,s->rsp-0x30U,8U,entry_pc+9U))
        return MX_CRT_MEMORY_FAULT;
    uint64_t value=0;
    if (!hook(context,s->rcx,&value))return MX_CRT_INVALID;
    /* For nonzero RAX: NEG sets CF, SBB -> -1, NEG -> 1,
     * DEC -> 0. For zero RAX: CF clear, SBB/NEG -> 0,
     * DEC -> 0xffffffff. EAX operations zero-extend RAX.
     */
    s->rax=value ? UINT64_C(0) : UINT64_C(0xffffffff);
    s->zf=0; /* final ADD RSP,0x28 sets ZF=0 at valid guest SP */
    s->rsp+=8U;
    s->rip=return_pc;
    s->instructions+=8U;
    s->visited|=UINT64_C(0xff);
    return MX_CRT_RETURNED;
}
#endif
