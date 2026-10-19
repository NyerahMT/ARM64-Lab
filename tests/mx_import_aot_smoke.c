#include <stdint.h>
#include "mx_import_registry.h"

/* Generated from a purpose-built synthetic x64 function during CI. */
int lifted_import_sequence(const mx_import_runtime *, mx_win64_call *);

typedef struct {
    uint64_t now_ns;
    uint64_t slept_ns;
    unsigned int sleep_count;
} clock_state;

static uint64_t mono(void *ctx) { return ((clock_state *)ctx)->now_ns; }
static uint64_t real_time(void *ctx) { (void)ctx; return UINT64_C(0); }
static void sleeping(void *ctx, uint64_t duration) {
    clock_state *host=(clock_state *)ctx;
    host->slept_ns += duration;
    host->sleep_count++;
}
static int denied_write(void *ctx, uint64_t address, const uint8_t *b, uint32_t n) {
    (void)ctx; (void)address; (void)b; (void)n;
    return 0;
}

/* Returns 0 iff the guest-register, stack, and host effects are identical
 * to our independently executed x64 reference (synthetic source code).
 * Steam remains blocked, even if a translated function calls its import.
 */
int smoke(void) {
    clock_state host={UINT64_C(1234000000),0,0};
    mx_clock_source clock={&host,mono,real_time,sleeping};
    mx_import_runtime runtime={&clock,denied_write,&host,0,0,0};
    mx_win64_call state={0};
    state.rsp=UINT64_C(0x700008);
    if (lifted_import_sequence(&runtime,&state)!=1) return 11;
    if (state.rsp!=UINT64_C(0x700008)) return 12;
    if (state.rax!=UINT64_C(1234)) return 13;
    if (state.rcx!=UINT64_C(25)) return 14;
    if (host.slept_ns!=UINT64_C(25000000) || host.sleep_count!=1) return 15;
    if (mx_dispatch_supported_win64_import(
            &runtime,"steam_api64.dll","SteamAPI_Init",&state)!=0) return 16;
    if (state.rax!=UINT64_C(1234)) return 17;
    return 0;
}
#ifdef HOST_SMOKE
int main(void) { return smoke(); }
#endif
