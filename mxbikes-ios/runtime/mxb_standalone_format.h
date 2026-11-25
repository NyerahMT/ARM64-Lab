#ifndef MXB_STANDALONE_FORMAT_H
#define MXB_STANDALONE_FORMAT_H
#include "mxb_standalone_crt.h"
/* Bounded Win64 integer/string sprintf subset. No host varargs or %n. */
int mxb_format_dispatch(const mxb_crt_memory *,const char *,mxb_crt_regs *);
#endif
