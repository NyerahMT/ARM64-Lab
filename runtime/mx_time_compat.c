#include "mx_time_compat.h"

#define MX_NS_PER_MS UINT64_C(1000000)
#define MX_NS_PER_SEC UINT64_C(1000000000)
#define MX_FILETIME_EPOCH_OFFSET UINT64_C(116444736000000000)

uint32_t mx_get_tick_count(const mx_clock_source *clock) {
    if (clock == 0 || clock->monotonic_ns == 0)
        return 0;
    return (uint32_t)(clock->monotonic_ns(clock->userdata) / MX_NS_PER_MS);
}

uint32_t mx_time_get_time(const mx_clock_source *clock) {
    return mx_get_tick_count(clock);
}

int mx_query_performance_counter(const mx_clock_source *clock, int64_t *count) {
    if (clock == 0 || clock->monotonic_ns == 0 || count == 0)
        return 0;
    uint64_t ticks = clock->monotonic_ns(clock->userdata);
    if (ticks > INT64_MAX)
        return 0;
    *count = (int64_t)ticks;
    return 1;
}

int mx_query_performance_frequency(int64_t *frequency) {
    if (frequency == 0)
        return 0;
    *frequency = (int64_t)MX_NS_PER_SEC;
    return 1;
}

int mx_get_system_time_as_filetime(const mx_clock_source *clock, mx_filetime *output) {
    if (clock == 0 || clock->realtime_unix_ns == 0 || output == 0)
        return 0;
    uint64_t unix_ticks = clock->realtime_unix_ns(clock->userdata) / UINT64_C(100);
    if (unix_ticks > UINT64_MAX - MX_FILETIME_EPOCH_OFFSET)
        return 0;
    uint64_t filetime = unix_ticks + MX_FILETIME_EPOCH_OFFSET;
    output->low_datetime = (uint32_t)filetime;
    output->high_datetime = (uint32_t)(filetime >> 32);
    return 1;
}

int mx_sleep(const mx_clock_source *clock, uint32_t milliseconds) {
    if (clock == 0 || clock->sleep_ns == 0)
        return 0;
    clock->sleep_ns(clock->userdata, (uint64_t)milliseconds * MX_NS_PER_MS);
    return 1;
}
