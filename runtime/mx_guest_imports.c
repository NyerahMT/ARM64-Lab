#include "mx_guest_imports.h"

static int same_ascii_ignore_case(const char *a, const char *b) {
    if (a == 0 || b == 0) return 0;
    for (; *a && *b; ++a, ++b) {
        char x = *a, y = *b;
        if (x >= 'A' && x <= 'Z') x = (char)(x - 'A' + 'a');
        if (y >= 'A' && y <= 'Z') y = (char)(y - 'A' + 'a');
        if (x != y) return 0;
    }
    return *a == 0 && *b == 0;
}

static int write_u64_le(const mx_import_runtime *rt, uint64_t guest_addr,
                        uint64_t value) {
    if (rt->write == 0 || guest_addr == 0) return 0;
    uint8_t bytes[8];
    for (unsigned int i=0; i<8; i++)
        bytes[i] = (uint8_t)(value >> (i*8));
    return rt->write(rt->write_userdata, guest_addr, bytes, 8);
}

int mx_dispatch_timing_import(const mx_import_runtime *rt,
                              const char *dll, const char *api,
                              mx_win64_call *call) {
    if (rt == 0 || call == 0 || rt->clock == 0 || dll == 0 || api == 0)
        return -1;

    int is_kernel = same_ascii_ignore_case(dll, "kernel32.dll");
    int is_winmm = same_ascii_ignore_case(dll, "winmm.dll");
    if (!is_kernel && !is_winmm) return 0;

    if (is_kernel && same_ascii_ignore_case(api, "GetTickCount")) {
        if (!rt->clock->monotonic_ns) return -1;
        call->rax = mx_get_tick_count(rt->clock);
        return 1;
    }
    if (is_winmm && same_ascii_ignore_case(api, "timeGetTime")) {
        if (!rt->clock->monotonic_ns) return -1;
        call->rax = mx_time_get_time(rt->clock);
        return 1;
    }
    if (is_kernel && same_ascii_ignore_case(api, "QueryPerformanceCounter")) {
        int64_t count;
        if (!mx_query_performance_counter(rt->clock, &count)) {
            call->rax = 0;
            return -1;
        }
        if (!write_u64_le(rt, call->rcx, (uint64_t)count)) {
            call->rax = 0;
            return -1;
        }
        call->rax = 1;
        return 1;
    }
    if (is_kernel && same_ascii_ignore_case(api, "QueryPerformanceFrequency")) {
        int64_t count;
        if (!mx_query_performance_frequency(&count) ||
            !write_u64_le(rt, call->rcx, (uint64_t)count)) {
            call->rax = 0;
            return -1;
        }
        call->rax = 1;
        return 1;
    }
    if (is_kernel && same_ascii_ignore_case(api, "GetSystemTimeAsFileTime")) {
        mx_filetime time;
        if (!mx_get_system_time_as_filetime(rt->clock, &time))
            return -1;
        uint64_t packed = ((uint64_t)time.high_datetime << 32) | time.low_datetime;
        if (!write_u64_le(rt, call->rcx, packed))
            return -1;
        /* Windows API has void return; leave guest RAX untouched. */
        return 1;
    }
    if (is_kernel && same_ascii_ignore_case(api, "Sleep")) {
        if (!mx_sleep(rt->clock, (uint32_t)call->rcx))
            return -1;
        /* Windows Sleep is void. */
        return 1;
    }
    return 0;
}
