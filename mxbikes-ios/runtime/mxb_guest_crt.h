#ifndef MXB_GUEST_CRT_H
#define MXB_GUEST_CRT_H
#include "mxb_guest_memory.h"
#ifdef __cplusplus
extern "C" {
#endif
/* Exact bounded CRT memory and registered read-only file operations.
 * Guest imports are not host function pointers. No arbitrary host paths,
 * licensing services or general DLL resolution. */
enum MXBGuestCRTStatus {
 MXB_CRT_OK=0, MXB_CRT_UNSUPPORTED=1, MXB_CRT_BAD_STACK=2,
 MXB_CRT_BAD_MEMORY=3, MXB_CRT_BAD_ARGUMENT=4
};
/* The arena mapping must remain installed until the guest state is discarded.
 * One state owns one arena. Individual live allocations are 16-byte aligned. */
int mxb_guest_heap_init(MXBGuestState *s,uint64_t base,uint8_t *backing,size_t capacity);
/* Caller-owned immutable bytes must remain valid for the guest lifetime.
 * Exactly one explicitly registered basename, never a host path. */
#define MXB_GUEST_FILE_HANDLE UINT64_C(0x730050000)
int mxb_guest_file_bind(MXBGuestState*s,const char*name,const uint8_t*bytes,size_t size);
enum MXBGuestCRTStatus mxb_guest_crt_call(MXBGuestState *s,const char *library,
 const char *name,uint64_t expected_return);
int mxb_guest_crt_smoke(void);
#ifdef __cplusplus
}
#endif
#endif
