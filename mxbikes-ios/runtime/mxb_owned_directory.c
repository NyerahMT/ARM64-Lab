#include "mxb_owned_directory.h"

#if __has_include("private/mxb_private_directory.c")
extern int mxb_private_directory(MXBGuestMemory *,const char *,char *,size_t);
int mxb_owned_directory(MXBGuestMemory *image,const char *path,char *out,size_t capacity){
    return mxb_private_directory(image,path,out,capacity);
}
#else
int mxb_owned_directory(MXBGuestMemory *image,const char *path,char *out,size_t capacity){
    (void)image;(void)path;(void)out;(void)capacity;
    return -1;
}
#endif
