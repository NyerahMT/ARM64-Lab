#include <stdint.h>
#include <stdio.h>
#include "mx_guest_imports.h"

typedef struct {
    uint64_t monotonic;
    uint64_t realtime;
    uint64_t slept;
    uint8_t guest_memory[128];
} fake_host;

static uint64_t monotonic_ns(void *ctx) { return ((fake_host *)ctx)->monotonic; }
static uint64_t realtime_ns(void *ctx) { return ((fake_host *)ctx)->realtime; }
static void sleep_ns(void *ctx, uint64_t ns) { ((fake_host *)ctx)->slept += ns; }
static int mem_write(void *ctx, uint64_t addr, const uint8_t *bytes, uint32_t size) {
    fake_host *f = (fake_host *)ctx;
    if (addr < 0x1000 || (addr - 0x1000) > sizeof(f->guest_memory) ||
        size > sizeof(f->guest_memory) - (addr - 0x1000))
        return 0;
    for (uint32_t i=0; i<size; i++)
        f->guest_memory[(addr - 0x1000) + i] = bytes[i];
    return 1;
}
static uint64_t u64_le(fake_host *f, uint64_t address) {
    uint64_t result = 0;
    for (unsigned int i=0; i<8; i++)
        result |= (uint64_t)f->guest_memory[(address - 0x1000) + i] << (8*i);
    return result;
}
#define CHECK(x) do { if (!(x)) { fprintf(stderr, "FAIL line %d: %s\n", __LINE__, #x); return 1; } } while (0)

int main(void) {
    fake_host fake = {0};
    fake.monotonic = UINT64_C(12000000000);
    mx_clock_source clock = {&fake,monotonic_ns,realtime_ns,sleep_ns};
    mx_import_runtime runtime = {&clock,mem_write,&fake,0,0,0};
    mx_win64_call call = {0};

    CHECK(mx_dispatch_timing_import(&runtime,"KERNEL32.DLL","gEtTiCkCoUnT",&call) == 1);
    CHECK(call.rax == 12000);

    call.rcx=0x1010;
    CHECK(mx_dispatch_timing_import(&runtime,"kernel32.dll","QueryPerformanceCounter",&call) == 1);
    CHECK(call.rax == 1);
    CHECK(u64_le(&fake,0x1010) == fake.monotonic);

    call.rcx=0x1020;
    CHECK(mx_dispatch_timing_import(&runtime,"kernel32.dll","QueryPerformanceFrequency",&call) == 1);
    CHECK(u64_le(&fake,0x1020) == UINT64_C(1000000000));

    call.rcx=0x1030;call.rax=77;
    CHECK(mx_dispatch_timing_import(&runtime,"kernel32.dll","GetSystemTimeAsFileTime",&call) == 1);
    CHECK(call.rax == 77); /* void WINAPI */
    CHECK(u64_le(&fake,0x1030) == UINT64_C(116444736000000000));

    call.rcx=13;
    CHECK(mx_dispatch_timing_import(&runtime,"KERNEL32.DLL","Sleep",&call) == 1);
    CHECK(fake.slept == UINT64_C(13000000));

    call.rcx=0;
    CHECK(mx_dispatch_timing_import(&runtime,"KERNEL32.DLL","QueryPerformanceCounter",&call) == -1);
    CHECK(call.rax == 0);

    CHECK(mx_dispatch_timing_import(&runtime,"KERNEL32.DLL","UnknownCall",&call) == 0);
    CHECK(mx_dispatch_timing_import(&runtime,"USER32.DLL","Sleep",&call) == 0);
    puts("PASS: Win64 timing import dispatch (synthetic guest memory)");
    return 0;
}
