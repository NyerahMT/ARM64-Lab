#ifndef MX_CFG_NATIVE_MODULE_H
#define MX_CFG_NATIVE_MODULE_H
#include "mx_cfg_vm.h"

/* Shared register layout for generated CFG workers and their caller.
 * Original addresses are guest virtual addresses, not native pointers. */
struct cpu {
 uint64_t rax,rbx,rcx,rdx,r8,r9,rdi,rsi,r10,r11,rbp,rsp,rip,r12,r13,r14,r15;
 uint8_t cf,zf,sf,of,pf;
 uint64_t xmm[16][2];
};
typedef struct cpu mx_cfg_native_cpu;

enum {
 MX_CFG_NATIVE_OK=0,
 MX_CFG_NATIVE_UNREGISTERED=20,
 MX_CFG_NATIVE_INVALID_STATE=21
};

/* Preflight an entire vector range before a write; no partial transfers. */
static inline int mx_cfg_vector_transfer(mx_cfg_memory*m,uint64_t address,uint64_t*words,uint32_t size,int write){
 if(!m||!m->regions||!words||(size!=4U&&size!=8U&&size!=16U)||m->count>16U)return 0;
 for(uint32_t i=0;i<m->count;i++){
  mx_cfg_region*r=&m->regions[i];
  if(!r->data||address<r->base||size>r->length)continue;
  uint64_t off=address-r->base;
  if(off>r->length-size)continue;
  volatile uint8_t*guest=(volatile uint8_t*)r->data;
  uint8_t*host=(uint8_t*)words;
  for(uint32_t j=0;j<size;j++){if(write)guest[off+j]=host[j];else host[j]=guest[off+j];}
  return 1;
 }
 return 0;
}

/* Dispatch exact translated guest entry only. A worker error may leave guest
 * memory changed; caller must stop, not retry from a presumed clean state.
 * Module generation and integration must supply the correct original revision
 * and matching guest image/static data. */
int mx_cfg_native_dispatch(mx_cfg_native_cpu *state,mx_cfg_memory *memory);
unsigned mx_cfg_native_count(void);
#endif
