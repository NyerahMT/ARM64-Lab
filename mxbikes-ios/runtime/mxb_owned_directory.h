#ifndef MXB_OWNED_DIRECTORY_H
#define MXB_OWNED_DIRECTORY_H
#include "mxb_guest_memory.h"
/* Requires the validated original PE mapped by the caller. Returns -1 in a
 * public build, 0 on failure, and 1 with a NUL-terminated guest result. */
int mxb_owned_directory(MXBGuestMemory *image,const char *path,char *out,size_t capacity);
#endif
