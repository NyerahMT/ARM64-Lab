#ifndef MX_CRT_INIT_IMPORTS_H
#define MX_CRT_INIT_IMPORTS_H

/* Synthetic Windows CRT import-thunk continuation, not a real MSVCR90 DLL.
 * All original-game import target validation happens in PRIVATE tooling.
 * Only _initterm_e and _initterm may return; _amsg_exit is always terminal.
 */
#include <stdint.h>
#include "mx_crt_vm.h"

enum {
    MX_CRT_INITTERM_E=1U,
    MX_CRT_INITTERM=2U,
    MX_CRT_AMSG_EXIT=3U
};
typedef int (*mx_crt_init_hook)(void *context, uint32_t kind,
                               uint64_t first_arg, uint64_t second_arg,
                               uint32_t *return_value);

/* Return MX_CRT_BRANCH_BOUNDARY only after a verified synthetic callback.
 * x64 near CALL pushes its 64-bit return address then the thunk's JMP and
 * callee RET restore RSP; the bytes at guest [RSP-8] remain observable.
 * No general-purpose guest IAT loading, native Windows API, or concurrency.
 */
static inline int mx_crt_invoke_init_thunk(
        mx_crt_state *s, mx_cfg_memory *mem, uint32_t kind,
        uint64_t callsite_pc, uint64_t return_pc,
        uint64_t second_arg, mx_crt_init_hook hook, void *context) {
    if (!s || !mem || s->fault || s->rip!=callsite_pc ||
        callsite_pc>UINT64_MAX-5U || return_pc!=callsite_pc+5U)
        return MX_CRT_INVALID;
    if (kind==MX_CRT_AMSG_EXIT) {
        /* Original _amsg_exit aborts process; do not invent a return. */
        return MX_CRT_IMPORT_BOUNDARY;
    }
    if ((kind!=MX_CRT_INITTERM_E && kind!=MX_CRT_INITTERM) ||
        !hook || (s->rsp&15U)!=0U || s->rsp<8U)
        return MX_CRT_INVALID;
    if (!mx_crt_write(s,mem,s->rsp-8U,8U,return_pc))
        return MX_CRT_MEMORY_FAULT;
    uint32_t result=0U;
    if (!hook(context,kind,s->rcx,second_arg,&result))
        return MX_CRT_INVALID;
    /* _initterm_e has an int return; _initterm is void and does not
     * specify a new return value. Tests use a preserving synthetic thunk.
     */
    if (kind==MX_CRT_INITTERM_E)
        s->rax=(uint64_t)result;
    s->imports++;
    s->import_trace=s->import_trace*UINT64_C(16)+(uint64_t)kind;
    s->rip=return_pc;
    return MX_CRT_BRANCH_BOUNDARY;
}
#endif
