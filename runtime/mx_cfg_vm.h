#ifndef MX_CFG_VM_H
#define MX_CFG_VM_H
#include <stdint.h>
#include <stddef.h>
/* Bounded guest addresses, not real host pointers. Every dereference checks
 * its containing registered region. No arbitrary OS memory exposure. */
typedef struct {
    uint64_t base;
    uint8_t *data;
    uint64_t length;
} mx_cfg_region;
typedef struct {
    mx_cfg_region *regions;
    uint32_t count;
} mx_cfg_memory;
typedef struct {
    uint64_t rax, rcx, rdx, rsp, rip;
    uint8_t zf;
    uint8_t sf;
    uint8_t cf;
    uint8_t of;
    uint64_t rbx, rbp, rdi, r12, r13;
} mx_cfg_state;
static inline int mx_cfg_transfer(mx_cfg_memory *m, uint64_t address,
                                  void *host_buf, uint32_t size, int write) {
    if (!m || !m->regions || !host_buf || size==0 || size>8 || m->count>16)
        return 0;
    for (uint32_t i=0;i<m->count;i++) {
        mx_cfg_region *r=&m->regions[i];
        if (!r->data || address<r->base || size>r->length) continue;
        uint64_t off=address-r->base;
        if (off>r->length-size) continue;
        /* Volatile byte operations avoid unresolved libc memcpy in the
         * freestanding AArch64 test runtime; each access is range-checked. */
        volatile uint8_t *guest=(volatile uint8_t*)r->data;
        uint8_t *host=(uint8_t*)host_buf;
        for (uint32_t j=0;j<size;j++) {
            if (write) guest[off+j]=host[j];
            else host[j]=guest[off+j];
        }
        return 1;
    }
    return 0;
}
#endif
