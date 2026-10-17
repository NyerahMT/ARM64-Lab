#include <stdint.h>
#include <stdio.h>
#include "mx_time_compat.h"

typedef struct {
    uint64_t monotonic_ns;
    uint64_t realtime_ns;
    uint64_t total_sleep_ns;
    int sleep_calls;
} fake_clock_state;

static uint64_t fake_monotonic(void *ctx) {
    return ((fake_clock_state *)ctx)->monotonic_ns;
}
static uint64_t fake_realtime(void *ctx) {
    return ((fake_clock_state *)ctx)->realtime_ns;
}
static void fake_sleep(void *ctx, uint64_t ns) {
    fake_clock_state *state = (fake_clock_state *)ctx;
    state->total_sleep_ns += ns;
    state->sleep_calls++;
}
#define CHECK(condition) do { \
    if (!(condition)) { fprintf(stderr, "FAIL line %d: %s\n", __LINE__, #condition); return 1; } \
} while (0)

int main(void) {
    fake_clock_state state = {0};
    mx_clock_source src = {&state, fake_monotonic, fake_realtime, fake_sleep};
    int64_t count = 0;
    int64_t frequency = 0;
    mx_filetime filetime = {0, 0};

    CHECK(mx_query_performance_frequency(&frequency) == 1);
    CHECK(frequency == INT64_C(1000000000));
    CHECK(mx_query_performance_frequency(0) == 0);

    state.monotonic_ns = UINT64_C(4294967299) * UINT64_C(1000000);
    CHECK(mx_get_tick_count(&src) == 3);
    CHECK(mx_time_get_time(&src) == 3);
    CHECK(mx_query_performance_counter(&src, &count) == 1);
    CHECK((uint64_t)count == state.monotonic_ns);

    state.realtime_ns = 0;
    CHECK(mx_get_system_time_as_filetime(&src, &filetime) == 1);
    uint64_t ft = ((uint64_t)filetime.high_datetime << 32) | filetime.low_datetime;
    CHECK(ft == UINT64_C(116444736000000000));

    state.realtime_ns = UINT64_C(1234567890);
    CHECK(mx_get_system_time_as_filetime(&src, &filetime) == 1);
    ft = ((uint64_t)filetime.high_datetime << 32) | filetime.low_datetime;
    CHECK(ft == UINT64_C(116444736012345678));

    CHECK(mx_sleep(&src, 5) == 1);
    CHECK(state.sleep_calls == 1);
    CHECK(state.total_sleep_ns == UINT64_C(5000000));
    CHECK(mx_sleep(&src, UINT32_MAX) == 1);
    CHECK(state.total_sleep_ns == UINT64_C(5000000) + (uint64_t)UINT32_MAX * 1000000);

    CHECK(mx_get_tick_count(0) == 0);
    CHECK(mx_query_performance_counter(0, &count) == 0);
    CHECK(mx_get_system_time_as_filetime(0, &filetime) == 0);
    CHECK(mx_sleep(0, 1) == 0);
    puts("PASS: synthetic Win32 timing semantics (native host)");
    return 0;
}
