#ifndef MXB_STANDALONE_CRT_H
#define MXB_STANDALONE_CRT_H
#include <stdint.h>
#include <stddef.h>
/* Standalone reference process layout, native little-endian Win64 guest ABI.
 * This is a bounded process model, not an OS loader or full CRT. */
#define MXB_CRT_PAGE 4096u
#define MXB_CRT_BASE UINT64_C(0x760000000)
#define MXB_CRT_ARGV (MXB_CRT_BASE+0x40u)
#define MXB_CRT_ENVP (MXB_CRT_BASE+0x60u)
#define MXB_CRT_ARGV0 (MXB_CRT_BASE+0x100u)
typedef struct { uint32_t app_type, locale_mode; } mxb_crt_process;
typedef struct {
    void *ctx;
    int (*read)(void *,uint64_t,uint8_t *,size_t);
    /* Validate all output spans before any write. The caller must guarantee
     * that writes to prevalidated ranges cannot fail or change mappings. */
    int (*writable)(void *,uint64_t,size_t);
    void (*write)(void *,uint64_t,const uint8_t *,size_t);
} mxb_crt_memory;
typedef struct { uint64_t rcx,rdx,r8,r9,rsp,rax; } mxb_crt_regs;
enum { MXB_CRT_UNSUPPORTED=0, MXB_CRT_HANDLED=1, MXB_CRT_INVALID=-1 };
int mxb_crt_data_page(uint8_t *page,size_t size,uint64_t a,uint64_t w,
                      const uint8_t *argv0,size_t n);
uint64_t mxb_crt_data_address(const char *library,const char *symbol);
int mxb_crt_dispatch(mxb_crt_process *p,const mxb_crt_memory *m,
                     const char *library,const char *symbol,mxb_crt_regs *r);
#endif
