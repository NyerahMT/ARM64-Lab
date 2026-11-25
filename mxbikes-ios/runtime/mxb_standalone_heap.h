#ifndef MXB_STANDALONE_HEAP_H
#define MXB_STANDALONE_HEAP_H
#include "mxb_standalone_crt.h"
#define MXB_HEAP_BASE UINT64_C(0x770000000)
#define MXB_HEAP_CAP (16u*1024u*1024u)
#define MXB_HEAP_SLOTS 256u
typedef struct {uint64_t address,size;} mxb_heap_block;
typedef struct {mxb_heap_block blocks[MXB_HEAP_SLOTS];} mxb_heap;
/* Guest-owned bounded arena; no host pointer escapes. The caller must map the
 * full arena RW, and provide stable memory callbacks. Unsupported realloc,
 * foreign/double-free, or bad pointers are rejected, not hidden. */
int mxb_heap_dispatch(mxb_heap *,const mxb_crt_memory *,const char *,mxb_crt_regs *);
#endif
