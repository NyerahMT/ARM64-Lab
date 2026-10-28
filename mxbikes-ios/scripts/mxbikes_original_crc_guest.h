#ifndef MXB_ORIGINAL_CRC_GUEST_H
#define MXB_ORIGINAL_CRC_GUEST_H
#include <stdint.h>
#include <stddef.h>

#define MXB_CRC_LOOP_VA UINT64_C(0x140130670)
#define MXB_CRC_EXIT_VA UINT64_C(0x1401306a9)
#define MXB_CRC_MAX_CHUNK UINT64_C(1000)

typedef struct {
 uint64_t rip,rax,rbx,rcx,rdx,r14;
 uint8_t zf,sf,cf;
} mxb_crc_guest;

static inline int mxb_original_crc_step(mxb_crc_guest *g,
             const uint8_t *memory,uint64_t start,uint64_t bytes) {
 if(!g||!memory||g->rip!=MXB_CRC_LOOP_VA||
    g->rdx==0U||g->rdx>MXB_CRC_MAX_CHUNK||
    (g->r14&UINT64_C(65535))!=UINT64_C(255)||
    g->rcx<start)return 0;
 uint64_t offset=g->rcx-start;
 if(offset>=bytes||g->rdx>bytes-offset||
    g->rcx>UINT64_MAX-g->rdx)return 0;
 uint16_t bx=(uint16_t)g->rbx;
 uint16_t ax=0U;
 for(uint64_t i=0U;i<g->rdx;i++) {
   bx=(uint16_t)((uint16_t)(bx<<8U)|(bx>>8U));
   bx=(uint16_t)(bx^(uint16_t)memory[offset+i]);
   ax=(uint16_t)((bx>>4U)&15U);
   bx=(uint16_t)(bx^ax);
   ax=(uint16_t)(bx<<12U);
   bx=(uint16_t)(bx^ax);
   ax=(uint16_t)((bx&255U)<<5U);
   bx=(uint16_t)(bx^ax);
 }
 uint64_t next_rcx=g->rcx+g->rdx;
 g->rbx=(g->rbx&UINT64_C(0xffffffffffff0000))|(uint64_t)bx;
 g->rax=(uint64_t)ax;
 g->rcx=next_rcx;
 g->rdx=0U;
 g->zf=1U;g->sf=0U;g->cf=0U;
 g->rip=MXB_CRC_EXIT_VA;
 return 1;
}
#endif
