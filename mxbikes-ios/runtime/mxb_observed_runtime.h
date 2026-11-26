#ifndef MXB_OBSERVED_RUNTIME_H
#define MXB_OBSERVED_RUNTIME_H
#include <stdint.h>
#include <stddef.h>
#ifdef __cplusplus
extern "C" {
#endif

/* Exact ABI of the generated observed-PC AOT dispatcher. Guest addresses
 * are not host pointers. Only caller-provided checked memory callbacks may
 * dereference them. This is a runtime contract, not a full PE loader. */
typedef struct {uint64_t lo,hi;} mxb_observed_xmm;
typedef struct {
    uint64_t r[16],rip,flags,known;
    void *ctx;
    int (*read)(void *,uint64_t,unsigned,uint64_t *);
    int (*write)(void *,uint64_t,unsigned,uint64_t);
    mxb_observed_xmm xmm[16];
    uint32_t mxcsr;
    int (*write128)(void *,uint64_t,uint64_t,uint64_t);
    uint64_t gs_base;
    uint32_t exclusive_guest;
} mxb_observed_cpu;
#if defined(__cplusplus)
#define MXB_ABI_ASSERT(c,s) static_assert(c,s)
#else
#define MXB_ABI_ASSERT(c,s) _Static_assert(c,s)
#endif
MXB_ABI_ASSERT(sizeof(mxb_observed_cpu)==464,"AOT state size");
MXB_ABI_ASSERT(offsetof(mxb_observed_cpu,rip)==128,"AOT RIP");
MXB_ABI_ASSERT(offsetof(mxb_observed_cpu,known)==144,"AOT flags mask");
MXB_ABI_ASSERT(offsetof(mxb_observed_cpu,read)==160,"AOT memory read");
MXB_ABI_ASSERT(offsetof(mxb_observed_cpu,xmm)==176,"AOT vectors");
MXB_ABI_ASSERT(offsetof(mxb_observed_cpu,mxcsr)==432,"AOT MXCSR");
MXB_ABI_ASSERT(offsetof(mxb_observed_cpu,write128)==440,"AOT vector write");
MXB_ABI_ASSERT(offsetof(mxb_observed_cpu,gs_base)==448,"AOT GS base");
MXB_ABI_ASSERT(offsetof(mxb_observed_cpu,exclusive_guest)==456,"AOT exclusive guest");
#undef MXB_ABI_ASSERT

/* A step returns 1 for executed original instruction, 2 for unknown PC,
 * negative on rejected/unsupported state. An unknown step MUST not mutate
 * the CPU. An import callback returns 1 only for a verified service which
 * has performed guest return semantics; 0 for unknown, negative on fault.
 * Import callbacks must never invent success for unavailable services. */
typedef int (*mxb_observed_step)(mxb_observed_cpu *);
typedef int (*mxb_observed_import)(void *,mxb_observed_cpu *);
enum {
    MXB_RUN_BUDGET=0, MXB_RUN_STOP=1, MXB_RUN_UNKNOWN=2,
    MXB_RUN_INVALID=-100, MXB_RUN_IMPORT_NO_PROGRESS=-101,
    MXB_RUN_STEP_CONTRACT=-102
};
typedef struct {
    uint64_t instructions,imports,terminal_pc;
    int status;
} mxb_observed_result;
/* Count each original instruction or import as one budget unit. No native
 * fallback to x64 execution, unbounded loops, or unchecked pointer calls.
 * The state and callback context remain owned by the caller. */
mxb_observed_result mxb_observed_run(mxb_observed_cpu *,mxb_observed_step,
                                    mxb_observed_import,void *,uint64_t stop,
                                    uint64_t budget);
#ifdef __cplusplus
}
#endif
#endif
