#ifndef MXB_STANDALONE_MEMORY_H
#define MXB_STANDALONE_MEMORY_H
#include "mxb_standalone_crt.h"
#define MXB_MEM_LIMIT (16u*1024u*1024u)
/* Bounded libc memory operations. Caller guarantees stable guest mappings
 * and reads/writes over the duration of a single call. */
int mxb_memory_dispatch(const mxb_crt_memory *,const char *,mxb_crt_regs *);
#endif
