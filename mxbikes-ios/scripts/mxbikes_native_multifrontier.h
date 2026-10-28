#ifndef MXBIKES_NATIVE_MULTIFRONTIER_H
#define MXBIKES_NATIVE_MULTIFRONTIER_H
/*
 * Checked Win64 guest CALL/RET with more than two AUTHENTICATED original
 * control-flow frontiers. This is a guest-state validator, not an emulator,
 * loader, DRM bypass, or license check override.
 *
 * Do not accept arbitrary PCs. All addresses come from proven disassembly
 * of the same pinned original executable; no fallbacks or default success.
 */
#include <stdint.h>
#include "mx_native_guest_linker.h"

static inline int mx_native_link_call_frontier_set(
    mx_native_link_registry *r, mx_crt_cluster_state *s, mx_cfg_memory *m,
    uint64_t target, uint64_t continuation,
    const uint64_t *permitted, uint32_t count) {
    if (mx_native_link_prepared(r)!=MX_NATIVE_LINK_OK)
        return MX_NATIVE_LINK_BAD_TABLE;
    if (!s||!m||s->fault||!target||!continuation||!permitted||
        count<2U||count>32U||!s->rip||s->rsp<8U||
        (s->rsp&15U)!=0U)
        return MX_NATIVE_LINK_INVALID;
    for (uint32_t i=0U;i<count;i++) {
        if (!permitted[i]||permitted[i]==continuation)
            return MX_NATIVE_LINK_BAD_FRONTIER;
        for (uint32_t j=0U;j<i;j++)
            if (permitted[i]==permitted[j])
                return MX_NATIVE_LINK_BAD_FRONTIER;
    }
    r->calls_attempted++;
    const mx_native_link_entry *e=mx_native_link_find(r,target);
    if (!e) {
        r->unresolved_calls++;
        r->last_unresolved_target=target;
        return MX_NATIVE_LINK_UNRESOLVED;
    }
    if (r->active_depth>=r->max_depth)
        return MX_NATIVE_LINK_RECURSION;
    const uint64_t old_rsp=s->rsp, new_rsp=old_rsp-8U;
    uint64_t previous=0U;
    if (!mx_cfg_transfer(m,new_rsp,&previous,8U,0)||
        !mx_cfg_transfer(m,new_rsp,&continuation,8U,1))
        return MX_NATIVE_LINK_STACK;
    s->rsp=new_rsp;
    s->rip=target;
    r->active_depth++;
    const int status=e->entry(s,m,e->context);
    r->active_depth--;
    uint64_t stored=0U;
    if (s->fault||!mx_cfg_transfer(m,new_rsp,&stored,8U,0)||
        stored!=continuation)
        return MX_NATIVE_LINK_BAD_RETURN;
    if (status==MX_NATIVE_LINK_OK) {
        if (s->rsp!=old_rsp||s->rip!=continuation)
            return MX_NATIVE_LINK_BAD_RETURN;
        r->calls_completed++;
        r->last_completed_target=target;
        return MX_NATIVE_LINK_OK;
    }
    if (status==MX_NATIVE_LINK_FRONTIER_REACHED) {
        if (s->rsp!=new_rsp)
            return MX_NATIVE_LINK_BAD_FRONTIER;
        uint32_t valid=0U;
        for (uint32_t i=0U;i<count;i++)
            valid+=(uint32_t)(s->rip==permitted[i]);
        if (valid!=1U)
            return MX_NATIVE_LINK_BAD_FRONTIER;
        r->last_completed_target=target;
        return MX_NATIVE_LINK_FRONTIER_REACHED;
    }
    return status;
}
#endif
