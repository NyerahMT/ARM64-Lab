#ifndef MX_NATIVE_GUEST_LINKER_H
#define MX_NATIVE_GUEST_LINKER_H
/*
 * Bounded original-VA -> native ARM64 function dispatch.
 * Entries MUST refer to independently verified native implementations.
 * An available LLVM object alone does NOT qualify as callable.
 *
 * No binary emulation, WinAPI loader, game boot or PE relocation is implied.
 * A target not present in this table always fails closed.
 */
#include <stdint.h>
#include <stddef.h>
#include "mx_crt_cluster_guest.h"

enum {
    MX_NATIVE_LINK_OK=MX_CRT_CLUSTER_RETURNED,
    MX_NATIVE_LINK_INVALID=-40,
    MX_NATIVE_LINK_UNRESOLVED=-41,
    MX_NATIVE_LINK_STACK=-42,
    MX_NATIVE_LINK_BAD_RETURN=-43,
    MX_NATIVE_LINK_RECURSION=-44,
    MX_NATIVE_LINK_BAD_TABLE=-45,
    MX_NATIVE_LINK_FRONTIER_REACHED=2,
    MX_NATIVE_LINK_BAD_FRONTIER=-46
};
typedef int (*mx_native_guest_function)(
    mx_crt_cluster_state *state, mx_cfg_memory *guest, void *context);

typedef struct {
    uint64_t original_va;
    mx_native_guest_function entry;
    void *context;
} mx_native_link_entry;

typedef struct {
    const mx_native_link_entry *entries; /* sorted by guest VA ascending */
    uint32_t count, max_depth, active_depth;
    uint32_t calls_attempted, calls_completed, unresolved_calls;
    uint64_t last_unresolved_target, last_completed_target;
    uint8_t table_sealed; /* immutable registry sorted and verified once */
} mx_native_link_registry;

static inline int mx_native_link_validate(const mx_native_link_registry *r){
    if(!r || !r->entries || !r->count || r->count>131072U ||
       !r->max_depth || r->max_depth>256U ||
       r->active_depth>r->max_depth)
        return MX_NATIVE_LINK_BAD_TABLE;
    for(uint32_t i=0;i<r->count;i++){
        if(!r->entries[i].original_va || !r->entries[i].entry ||
           (i && r->entries[i].original_va<=r->entries[i-1U].original_va))
            return MX_NATIVE_LINK_BAD_TABLE;
    }
    return MX_NATIVE_LINK_OK;
}

/* Verify table once for constant-time validation on subsequent calls.
 * Caller must not mutate registry entries after sealing. */
static inline int mx_native_link_seal(mx_native_link_registry *r){
    if(!r)return MX_NATIVE_LINK_BAD_TABLE;
    if(r->table_sealed)return MX_NATIVE_LINK_OK;
    if(mx_native_link_validate(r)!=MX_NATIVE_LINK_OK)
        return MX_NATIVE_LINK_BAD_TABLE;
    r->table_sealed=1U;
    return MX_NATIVE_LINK_OK;
}
static inline int mx_native_link_prepared(const mx_native_link_registry *r){
    if(!r)return MX_NATIVE_LINK_BAD_TABLE;
    if(r->table_sealed){
        if(!r->entries||!r->count||r->count>131072U ||
           !r->max_depth||r->max_depth>256U ||
           r->active_depth>r->max_depth)return MX_NATIVE_LINK_BAD_TABLE;
        return MX_NATIVE_LINK_OK;
    }
    return mx_native_link_validate(r);
}

static inline const mx_native_link_entry *mx_native_link_find(
        const mx_native_link_registry *r,uint64_t target_va){
    if(!r||!r->entries||!target_va)return NULL;
    uint32_t lo=0,hi=r->count;
    while(lo<hi){
        uint32_t mid=lo+(hi-lo)/2U;
        if(r->entries[mid].original_va<target_va)lo=mid+1U;
        else hi=mid;
    }
    return lo<r->count && r->entries[lo].original_va==target_va
           ? &r->entries[lo] : NULL;
}

/*
 * Native translation of original Win64 CALL:
 *  - an original x64 return address is pushed to guest stack;
 *  - target is dispatched by its original guest VA, not its host pointer;
 *  - the native body must return to the exact continuation and restore RSP;
 *  - unresolved direct/indirect targets are explicitly reported.
 *
 * Caller must supply the correct original continuation from verified machine
 * code. The guest Win64 caller owns its 32-byte shadow space.
 */
static inline int mx_native_link_call(
        mx_native_link_registry *r,mx_crt_cluster_state *s,
        mx_cfg_memory *mem,uint64_t target_va,uint64_t continuation_va){
    if(mx_native_link_prepared(r)!=MX_NATIVE_LINK_OK)return MX_NATIVE_LINK_BAD_TABLE;
    if(!s||!mem||s->fault||!continuation_va||!target_va||
       !s->rip||s->rsp<8U ||(s->rsp & 15U)!=0U)
        return MX_NATIVE_LINK_INVALID;
    r->calls_attempted++;
    const mx_native_link_entry *entry=mx_native_link_find(r,target_va);
    if(!entry){
        r->unresolved_calls++;
        r->last_unresolved_target=target_va;
        return MX_NATIVE_LINK_UNRESOLVED;
    }
    if(r->active_depth>=r->max_depth)
        return MX_NATIVE_LINK_RECURSION;
    const uint64_t original_rsp=s->rsp;
    const uint64_t new_rsp=original_rsp-8U;
    uint64_t old_stack=0U;
    if(!mx_cfg_transfer(mem,new_rsp,&old_stack,8U,0) ||
       !mx_cfg_transfer(mem,new_rsp,&continuation_va,8U,1))
        return MX_NATIVE_LINK_STACK;
    s->rsp=new_rsp;
    s->rip=target_va;
    r->active_depth++;
    const int status=entry->entry(s,mem,entry->context);
    r->active_depth--;
    if(status!=MX_NATIVE_LINK_OK)return status;
    if(s->fault ||s->rsp!=original_rsp||s->rip!=continuation_va){
        /* This is a hard semantic mismatch; do not pretend we returned. */
        return MX_NATIVE_LINK_BAD_RETURN;
    }
    r->calls_completed++;
    r->last_completed_target=target_va;
    return MX_NATIVE_LINK_OK;
}

/*
 * A verified native function may stop at an UNTRANSLATED branch without
 * returning. This deliberately does NOT use mx_native_link_call's successful
 * return contract. Both permitted frontiers must come from original machine
 * instruction validation, and the original guest return slot stays intact.
 *
 * The callback returns MX_NATIVE_LINK_FRONTIER_REACHED only if it executed a
 * verified prefix. Arbitrary return values, unregistered source targets,
 * mismatched stack states or unexpected PCs must fail closed.
 */
static inline int mx_native_link_call_frontier(
        mx_native_link_registry *r,mx_crt_cluster_state *s,
        mx_cfg_memory *mem,uint64_t target_va,uint64_t continuation_va,
        uint64_t stop_taken_va,uint64_t stop_fallthrough_va){
    if(mx_native_link_prepared(r)!=MX_NATIVE_LINK_OK)
        return MX_NATIVE_LINK_BAD_TABLE;
    if(!s||!mem||s->fault||!continuation_va||!target_va||
       !stop_taken_va||!stop_fallthrough_va||
       stop_taken_va==stop_fallthrough_va||
       !s->rip||s->rsp<8U||(s->rsp&15U)!=0U)
        return MX_NATIVE_LINK_INVALID;
    r->calls_attempted++;
    const mx_native_link_entry*entry=mx_native_link_find(r,target_va);
    if(!entry){
        r->unresolved_calls++;
        r->last_unresolved_target=target_va;
        return MX_NATIVE_LINK_UNRESOLVED;
    }
    if(r->active_depth>=r->max_depth)
        return MX_NATIVE_LINK_RECURSION;
    uint64_t prior=0U;
    if(!mx_cfg_transfer(mem,s->rsp-8U,&prior,8U,0) ||
       !mx_cfg_transfer(mem,s->rsp-8U,&continuation_va,8U,1))
        return MX_NATIVE_LINK_STACK;
    uint64_t guest_entry_rsp=s->rsp-8U;
    s->rsp=guest_entry_rsp;
    s->rip=target_va;
    r->active_depth++;
    int status=entry->entry(s,mem,entry->context);
    r->active_depth--;
    if(status!=MX_NATIVE_LINK_FRONTIER_REACHED)
        return status==MX_NATIVE_LINK_OK?MX_NATIVE_LINK_BAD_FRONTIER:status;
    uint64_t return_slot=0U;
    if(s->fault||s->rsp!=guest_entry_rsp||
       (s->rip!=stop_taken_va && s->rip!=stop_fallthrough_va)||
       !mx_cfg_transfer(mem,guest_entry_rsp,&return_slot,8U,0) ||
       return_slot!=continuation_va)
        return MX_NATIVE_LINK_BAD_FRONTIER;
    r->last_completed_target=target_va;
    return MX_NATIVE_LINK_FRONTIER_REACHED;
}

/*
 * Handles an original JMP / tail CALL without pushing another return slot.
 * Registered callee must consume the preexisting guest return address.
 */
static inline int mx_native_link_tail_jump(
        mx_native_link_registry *r,mx_crt_cluster_state *s,
        mx_cfg_memory *mem,uint64_t target_va){
    if(mx_native_link_prepared(r)!=MX_NATIVE_LINK_OK)return MX_NATIVE_LINK_BAD_TABLE;
    if(!s||!mem||s->fault||!target_va||s->rsp>UINT64_MAX-8U ||
       (s->rsp&15U)!=8U)return MX_NATIVE_LINK_INVALID;
    r->calls_attempted++;
    const mx_native_link_entry *entry=mx_native_link_find(r,target_va);
    if(!entry){
        r->unresolved_calls++;
        r->last_unresolved_target=target_va;
        return MX_NATIVE_LINK_UNRESOLVED;
    }
    if(r->active_depth>=r->max_depth)return MX_NATIVE_LINK_RECURSION;
    uint64_t ret=0U;
    if(!mx_cfg_transfer(mem,s->rsp,&ret,8U,0))
        return MX_NATIVE_LINK_STACK;
    const uint64_t old_rsp=s->rsp;
    s->rip=target_va;
    r->active_depth++;
    int status=entry->entry(s,mem,entry->context);
    r->active_depth--;
    if(status!=MX_NATIVE_LINK_OK)return status;
    if(s->fault||s->rip!=ret||s->rsp!=old_rsp+8U)
        return MX_NATIVE_LINK_BAD_RETURN;
    r->calls_completed++;
    r->last_completed_target=target_va;
    return MX_NATIVE_LINK_OK;
}
#endif
