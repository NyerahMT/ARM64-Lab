#ifndef MXB_STANDALONE_WINSOCK_H
#define MXB_STANDALONE_WINSOCK_H
#include "mxb_standalone_heap.h"
/* Offline process-local Winsock lifecycle and byte order; no network I/O. */
typedef struct { uint32_t refs,last_error; uint64_t results[16]; } mxb_winsock;
int mxb_winsock_dispatch(mxb_winsock *,mxb_heap *,const mxb_crt_memory *,const char *,mxb_crt_regs *);
#endif
