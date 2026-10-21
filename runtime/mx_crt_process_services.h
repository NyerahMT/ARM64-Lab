#ifndef MX_CRT_PROCESS_SERVICES_H
#define MX_CRT_PROCESS_SERVICES_H
/*
 * Explicit, stateful subset of MSVCR90 startup imports for a bounded Win64
 * guest. Unlike injected per-call return fixtures, these services share a
 * process context and perform observable guest-memory writes.
 *
 * The loader MUST supply a parsed argv/env vector in mapped guest memory.
 * No host argv, wildcard expansion, Windows CRT heap, invalid-parameter
 * handler, locale database or Windows service is silently synthesized.
 * This is a portable compatibility component, not a complete MSVCR90.
 */
#include <stdint.h>
#include "mx_cfg_vm.h"

enum {
    MX_CRT_PROCESS_HANDLED=1,
    MX_CRT_PROCESS_UNSUPPORTED=0,
    MX_CRT_PROCESS_INVALID=-1,
    MX_CRT_PROCESS_LOCALE_ENABLE=1,
    MX_CRT_PROCESS_LOCALE_DISABLE=2,
    MX_CRT_PROCESS_CONSOLE_APP=1,
    MX_CRT_PROCESS_GUI_APP=2
};

typedef struct {
    mx_cfg_memory *guest;
    uint32_t argc;
    uint64_t argv, env;
    uint64_t math_handler;
    uint32_t app_type, thread_locale;
    uint8_t argv_ready, app_type_set;
} mx_crt_process;

/* The caller supplies already-parsed, guest-owned argv/env arrays, not
 * unchecked pointers into the host process. An actual loader must build the
 * NUL-terminated strings/vectors and verify their lifecycle separately. */
static inline int mx_crt_process_bind_args(
        mx_crt_process *p, mx_cfg_memory *guest, uint32_t argc,
        uint64_t argv, uint64_t env) {
    uint64_t probe=0;
    if (!p || !guest || argc<1U || argc>4096U ||
        !argv || !env || (argv&7U) || (env&7U) ||
        !mx_cfg_transfer(guest,argv,&probe,8U,0) ||
        !mx_cfg_transfer(guest,env,&probe,8U,0))
        return MX_CRT_PROCESS_INVALID;
    p->guest=guest;
    p->argc=argc;
    p->argv=argv;
    p->env=env;
    p->argv_ready=1U;
    if (p->thread_locale!=MX_CRT_PROCESS_LOCALE_ENABLE)
        p->thread_locale=MX_CRT_PROCESS_LOCALE_DISABLE;
    return MX_CRT_PROCESS_HANDLED;
}

static inline int mx_crt_process_ranges_overlap(
        uint64_t a, uint32_t n, uint64_t b, uint32_t m) {
    if (a>UINT64_MAX-n || b>UINT64_MAX-m) return 1;
    return a<b+m && b<a+n;
}

/* Win64 __getmainargs writes *argc, *argv, *envp and returns 0. Only the
 * pre-parsed, no-wildcard path is implemented. Preflight all guest destinations
 * before any write so failure leaves guest data and RAX unchanged.
 * The 5th _startupinfo argument must be checked by the caller's ABI layer. */
static inline int mx_crt_process_getmainargs(
        mx_crt_process *p, uint64_t argc_out, uint64_t argv_out,
        uint64_t env_out, uint32_t wildcard, uint64_t *guest_rax) {
    if (!p || !p->argv_ready || !p->guest || !guest_rax ||
        wildcard!=0U || !argc_out || !argv_out || !env_out ||
        mx_crt_process_ranges_overlap(argc_out,4U,argv_out,8U) ||
        mx_crt_process_ranges_overlap(argc_out,4U,env_out,8U) ||
        mx_crt_process_ranges_overlap(argv_out,8U,env_out,8U))
        return MX_CRT_PROCESS_INVALID;
    uint64_t old=0;
    uint32_t oldargc=0;
    if (!mx_cfg_transfer(p->guest,argc_out,&oldargc,4U,0) ||
        !mx_cfg_transfer(p->guest,argv_out,&old,8U,0) ||
        !mx_cfg_transfer(p->guest,env_out,&old,8U,0))
        return MX_CRT_PROCESS_INVALID;
    if (!mx_cfg_transfer(p->guest,argc_out,&p->argc,4U,1) ||
        !mx_cfg_transfer(p->guest,argv_out,&p->argv,8U,1) ||
        !mx_cfg_transfer(p->guest,env_out,&p->env,8U,1))
        return MX_CRT_PROCESS_INVALID;
    *guest_rax=0U;
    return MX_CRT_PROCESS_HANDLED;
}

/* __set_app_type and __setusermatherr return void (leave guest RAX alone).
 * _configthreadlocale returns the previous mode, or -1 for invalid inputs.
 * No actual setlocale() or math error callback is invoked here. */
static inline int mx_crt_process_set_app_type(mx_crt_process *p,uint32_t kind) {
    if (!p || !p->guest || (kind!=MX_CRT_PROCESS_CONSOLE_APP &&
                            kind!=MX_CRT_PROCESS_GUI_APP))
        return MX_CRT_PROCESS_INVALID;
    p->app_type=kind;
    p->app_type_set=1U;
    return MX_CRT_PROCESS_HANDLED;
}
static inline int mx_crt_process_set_matherr(mx_crt_process *p,uint64_t handler) {
    if (!p || !p->guest)return MX_CRT_PROCESS_INVALID;
    p->math_handler=handler;
    return MX_CRT_PROCESS_HANDLED;
}
static inline int mx_crt_process_configthreadlocale(
        mx_crt_process *p, uint32_t requested, uint64_t *guest_rax) {
    if (!p || !p->guest || !guest_rax ||
        (requested!=0U && requested!=MX_CRT_PROCESS_LOCALE_ENABLE &&
         requested!=MX_CRT_PROCESS_LOCALE_DISABLE))
        return MX_CRT_PROCESS_INVALID;
    uint32_t old=p->thread_locale;
    if (old!=MX_CRT_PROCESS_LOCALE_ENABLE &&
        old!=MX_CRT_PROCESS_LOCALE_DISABLE)return MX_CRT_PROCESS_INVALID;
    if (requested!=0U)p->thread_locale=requested;
    *guest_rax=(uint64_t)old;
    return MX_CRT_PROCESS_HANDLED;
}
#endif
