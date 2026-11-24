#include "mxb_owned_directory.h"
#if defined(__APPLE__)
#define MXB_OPTIONAL __attribute__((weak_import))
#else
#define MXB_OPTIONAL __attribute__((weak))
#endif
extern int mxb_private_directory(MXBGuestMemory *,const char *,char *,size_t) MXB_OPTIONAL;

int mxb_owned_directory(MXBGuestMemory *image,const char *path,char *out,size_t capacity){
    if(!mxb_private_directory)return -1;
    return mxb_private_directory(image,path,out,capacity);
}
