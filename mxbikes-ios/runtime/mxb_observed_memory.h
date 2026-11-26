#ifndef MXB_OBSERVED_MEMORY_H
#define MXB_OBSERVED_MEMORY_H
#include "mxb_observed_runtime.h"
#ifdef __cplusplus
extern "C" {
#endif
#define MXB_OBSERVED_REGION_CAP 256u
enum { MXB_MEM_R=1, MXB_MEM_W=2, MXB_MEM_X=4 };
typedef struct {
    uint64_t base,size;
    uint8_t *bytes;
    unsigned permissions;
} mxb_observed_region;
typedef struct {
    mxb_observed_region region[MXB_OBSERVED_REGION_CAP];
    unsigned count;
} mxb_observed_memory;
/* Region storage is caller-owned and must remain valid throughout execution.
 * No overlapping virtual ranges, no writable executable mappings. */
int mxb_observed_map(mxb_observed_memory *,uint64_t,size_t,uint8_t *,unsigned);
int mxb_observed_permitted(const mxb_observed_memory *,uint64_t,size_t,unsigned);
int mxb_observed_read(void *,uint64_t,unsigned,uint64_t *);
int mxb_observed_write(void *,uint64_t,unsigned,uint64_t);
int mxb_observed_write128(void *,uint64_t,uint64_t,uint64_t);
#ifdef __cplusplus
}
#endif
#endif
