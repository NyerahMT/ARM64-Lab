#ifndef MX_TIME_COMPAT_H
#define MX_TIME_COMPAT_H
#include <stdint.h>
/* Win32 timing semantics; NOT a Windows ABI adapter or kernel32 replacement. */
#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    uint32_t low_datetime;
    uint32_t high_datetime;
} mx_filetime;

typedef struct {
    void *userdata;
    uint64_t (*monotonic_ns)(void *userdata);
    uint64_t (*realtime_unix_ns)(void *userdata);
    void (*sleep_ns)(void *userdata, uint64_t nanoseconds);
} mx_clock_source;

uint32_t mx_get_tick_count(const mx_clock_source *clock);
uint32_t mx_time_get_time(const mx_clock_source *clock);
int mx_query_performance_counter(const mx_clock_source *clock, int64_t *count);
int mx_query_performance_frequency(int64_t *frequency);
int mx_get_system_time_as_filetime(const mx_clock_source *clock, mx_filetime *output);
int mx_sleep(const mx_clock_source *clock, uint32_t milliseconds);

#ifdef __cplusplus
}
#endif
#endif
