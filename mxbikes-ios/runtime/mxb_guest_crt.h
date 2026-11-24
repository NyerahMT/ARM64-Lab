#ifndef MXB_GUEST_CRT_H
#define MXB_GUEST_CRT_H
#include "mxb_guest_memory.h"
#ifdef __cplusplus
extern "C" {
#endif
/* Exact CRT memory operations only. Guest imports are not host function
 * pointers. No licensing services, I/O, or general DLL resolution here. */
enum MXBGuestCRTStatus {
 MXB_CRT_OK=0, MXB_CRT_UNSUPPORTED=1, MXB_CRT_BAD_STACK=2,
 MXB_CRT_BAD_MEMORY=3, MXB_CRT_BAD_ARGUMENT=4
};
enum MXBGuestCRTStatus mxb_guest_crt_call(MXBGuestState *s,const char *library,
 const char *name,uint64_t expected_return);
int mxb_guest_crt_smoke(void);
#ifdef __cplusplus
}
#endif
#endif
