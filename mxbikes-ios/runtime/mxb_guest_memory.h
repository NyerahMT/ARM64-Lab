#ifndef MXB_GUEST_MEMORY_H
#define MXB_GUEST_MEMORY_H
#include <stdint.h>
#include <stddef.h>
#ifdef __cplusplus
extern "C" {
#endif
/* Persistent guest virtual memory. All backing bytes are caller-owned.
 * Single-threaded guest execution; mappings may only change between steps.
 * A guest address is never cast to a host pointer. */
#define MXB_MEM_MAX_REGIONS 256u
#define MXB_MEM_MAX_TRANSFER (16u*1024u*1024u)
enum { MXB_MEM_READ=1u, MXB_MEM_WRITE=2u, MXB_MEM_EXEC=4u };
typedef struct {
 uint64_t base,length;
 uint8_t *bytes;
 unsigned permissions;
} MXBGuestRegion;
typedef struct {
 MXBGuestRegion regions[MXB_MEM_MAX_REGIONS];
 unsigned count;
} MXBGuestMemory;
/* Sorted live extents within one caller-owned, permanently mapped arena. */
#define MXB_HEAP_SLOTS 64u
typedef struct {
 uint64_t base, capacity;
 struct { uint64_t offset, length; } live[MXB_HEAP_SLOTS];
 unsigned count;
} MXBGuestHeap;
typedef struct {
 uint64_t r[16],flags;
 MXBGuestMemory memory;
 MXBGuestHeap heap;
 unsigned fault;
 /* Persistent Win64 SSE registers, low and high 64-bit lanes. */
 uint64_t xmm[16][2];
 uint64_t completed_crt_calls;
} MXBGuestState;
enum { MXB_RAX=0, MXB_RCX=1, MXB_RDX=2, MXB_RBX=3, MXB_RSP=4,
 MXB_RBP=5, MXB_RSI=6, MXB_RDI=7, MXB_R8=8, MXB_R9=9 };
void mxb_guest_memory_init(MXBGuestMemory *m);
int mxb_guest_map(MXBGuestMemory *m,uint64_t base,uint8_t *bytes,size_t length,unsigned permissions);
/* Fill previously unmapped portions of one non-executable image segment.
 * Existing narrower-permission overlays are retained. The entire operation
 * commits atomically, or leaves the original mapping table unchanged. */
int mxb_guest_map_gaps(MXBGuestMemory *m,uint64_t base,uint8_t *bytes,size_t length,unsigned permissions);
int mxb_guest_unmap(MXBGuestMemory *m,uint64_t base);
int mxb_guest_check(const MXBGuestMemory *m,uint64_t address,size_t n,unsigned permission);
int mxb_guest_read(const MXBGuestMemory *m,uint64_t address,void *out,size_t n);
int mxb_guest_write(MXBGuestMemory *m,uint64_t address,const void *in,size_t n);
int mxb_guest_fill(MXBGuestMemory *m,uint64_t address,uint8_t value,size_t n);
/* memmove semantics, with both complete ranges checked before mutation. */
int mxb_guest_move(MXBGuestMemory *m,uint64_t dst,uint64_t src,size_t n);
int mxb_guest_read_callback(void *ctx,uint64_t address,void *out,size_t n);
int mxb_guest_write_callback(void *ctx,uint64_t address,const void *in,size_t n);
int mxb_guest_memory_smoke(void);
#ifdef __cplusplus
}
#endif
#endif
