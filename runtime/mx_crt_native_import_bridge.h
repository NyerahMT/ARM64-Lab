#ifndef MX_CRT_NATIVE_IMPORT_BRIDGE_H
#define MX_CRT_NATIVE_IMPORT_BRIDGE_H
/*
 * Stateful import callback for verified x64-to-native CRT cluster functions.
 * Composes existing bounded process, pointer, registration and lock services
 * against ONE guest memory map. Caller must independently validate that its
 * IAT entry resolves to the selected MSVCR90 service.
 *
 * This is a portable test-domain process model, NOT Windows MSVCR90, a
 * production loader, Steam, or a complete native CRT startup. In particular:
 * pointer tokens are not Windows-compatible; locks are single-threaded;
 * exit registration has fixed capacity; no callbacks run on process exit.
 */
#include <stdint.h>
#include "mx_crt_cluster_guest.h"
#include "mx_crt_process_services.h"

typedef struct {
    mx_cfg_memory *guest;
    mx_crt_process *process;
    mx_crt_service_adapter *services;
    uint32_t calls_handled;
    mx_crt_service_id last_service;
} mx_crt_native_import_bridge;

/* Signature matches mx_crt_cluster_import_fn. The generated CALL has not
 * adjusted s->rsp; callee_rsp is the original caller RSP minus eight.
 * Win64 argument five is at [callee_rsp+40] after the pushed return PC.
 * Validating its pointer and startupinfo.newmode is mandatory before writing
 * process output globals. This subset accepts only newmode=0.
 */
static inline int mx_crt_native_import_callback(
        void *opaque, mx_crt_service_id service,
        mx_crt_cluster_state *s, mx_cfg_memory *mem,
        uint64_t callee_rsp) {
    mx_crt_native_import_bridge *bridge=(mx_crt_native_import_bridge*)opaque;
    uint64_t return_pc=0U;
    if (!bridge || !s || !mem || bridge->guest!=mem || s->fault ||
        !s->rip || s->rsp<8U || (s->rsp&15U)!=0U ||
        callee_rsp!=s->rsp-8U ||
        !mx_cfg_transfer(mem,callee_rsp,&return_pc,8U,0) || !return_pc)
        return 0;

    uint64_t result=s->rax;
    int handled=0;
    if (service>=MX_CRT_SERVICE_ENCODE_POINTER &&
        service<=MX_CRT_SERVICE_UNLOCK) {
        if (!bridge->services ||
            bridge->services->guest_memory!=mem)return 0;
        handled=mx_crt_dispatch_service(bridge->services,service,
                                         s->rcx,s->rdx,s->r8,&result)==1;
    } else {
        if (!bridge->process || bridge->process->guest!=mem)
            return 0;
        mx_crt_process *p=bridge->process;
        switch (service) {
        case MX_CRT_SERVICE_GETMAINARGS: {
            uint64_t startup=0U;
            uint32_t newmode=0U;
            if (callee_rsp>UINT64_MAX-40U ||
                !mx_cfg_transfer(mem,callee_rsp+40U,&startup,8U,0) ||
                !startup || (startup&3U) ||
                !mx_cfg_transfer(mem,startup,&newmode,4U,0) ||
                newmode!=0U)
                return 0;
            handled=mx_crt_process_getmainargs(
                p,s->rcx,s->rdx,s->r8,(uint32_t)s->r9,&result)==
                MX_CRT_PROCESS_HANDLED;
            break;
        }
        case MX_CRT_SERVICE_SET_APP_TYPE:
            handled=mx_crt_process_set_app_type(p,(uint32_t)s->rcx)==
                    MX_CRT_PROCESS_HANDLED;
            break;
        case MX_CRT_SERVICE_SET_USERMATHERR:
            handled=mx_crt_process_set_matherr(p,s->rcx)==
                    MX_CRT_PROCESS_HANDLED;
            break;
        case MX_CRT_SERVICE_CONFIGTHREADLOCALE:
            handled=mx_crt_process_configthreadlocale(
                p,(uint32_t)s->rcx,&result)==MX_CRT_PROCESS_HANDLED;
            break;
        default:
            return 0;
        }
    }
    if (!handled) return 0;
    s->rax=result;
    bridge->last_service=service;
    bridge->calls_handled++;
    return 1;
}
#endif
