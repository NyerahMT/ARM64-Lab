#ifndef MXB_ORIGINAL_CRC_CLUSTER_BRIDGE_H
#define MXB_ORIGINAL_CRC_CLUSTER_BRIDGE_H
#include <stdint.h>
#include "mx_crt_cluster_guest.h"
#include "mxbikes_original_crc_guest.h"

/* Bridge the verified checksum into the existing bounded Win64 guest runtime.
 * Original R14 is passed separately; mx_crt_cluster_state omits R14.
 */
static inline int mxb_crc_cluster_run(mx_crt_cluster_state *state,
                                      mx_cfg_memory *memory,
                                      uint64_t original_r14) {
 if(!state||!memory||state->fault||
    state->rip!=MXB_CRC_LOOP_VA||
    state->rdx==0U||state->rdx>MXB_CRC_MAX_CHUNK||
    state->instructions>UINT32_MAX-(uint32_t)(state->rdx*17U))
    return 0;
 /* Preflight one complete contiguous guest buffer before passing it
  * to the exact-byte CRC semantic routine. No unbounded pointer probing,
  * and no per-byte guest-memory translation calls within the hot loop.
  */
 if(!memory->regions||memory->count==0U||memory->count>16U)return 0;
 const uint8_t *input=0;
 for(uint32_t index=0U;index<memory->count;index++){
    const mx_cfg_region *page=&memory->regions[index];
    if(!page->data||state->rcx<page->base||
       state->rdx>page->length)continue;
    uint64_t offset=state->rcx-page->base;
    if(offset>page->length-state->rdx)continue;
    input=page->data+offset;
    break;
 }
 if(!input)return 0;
 mxb_crc_guest next={
    state->rip,state->rax,state->rbx,state->rcx,
    state->rdx,original_r14,state->zf,state->sf,state->cf
 };
 if(!mxb_original_crc_step(&next,input,state->rcx,state->rdx))
    return 0;
 uint32_t executed=(uint32_t)(state->rdx*17U);
 state->rip=next.rip;state->rax=next.rax;state->rbx=next.rbx;
 state->rcx=next.rcx;state->rdx=next.rdx;
 state->zf=next.zf;state->sf=next.sf;state->cf=next.cf;
 state->instructions+=executed;
 return 1;
}
#endif
