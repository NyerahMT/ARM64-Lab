#ifndef MXB_STANDALONE_PLATFORM_H
#define MXB_STANDALONE_PLATFORM_H
#include <stdint.h>
#include <stddef.h>
#define MXB_PATH_CAP 260u
#define MXB_TIMER_NOCANDO 97u
/* Bounded virtual directory namespace and guest clock. No host chdir,
 * asset fabrication, physical timer resolution change, or Windows filesystem. */
typedef struct {
    uint8_t root[MXB_PATH_CAP], cwd[MXB_PATH_CAP];
    uint64_t elapsed_ms;
    uint32_t last_error, timer_refs;
} mxb_platform;
int mxb_platform_init(mxb_platform *, const uint8_t *, size_t, uint64_t);
uint32_t mxb_platform_set_directory(mxb_platform *, const uint8_t *, size_t);
uint32_t mxb_platform_get_directory(mxb_platform *, uint8_t *, size_t);
int mxb_platform_advance(mxb_platform *, uint64_t);
uint32_t mxb_platform_ticks(const mxb_platform *);
uint32_t mxb_platform_timer_begin(mxb_platform *, uint32_t);
uint32_t mxb_platform_timer_end(mxb_platform *, uint32_t);
#endif
