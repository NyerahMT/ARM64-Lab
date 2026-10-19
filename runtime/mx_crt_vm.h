#ifndef MX_CRT_VM_H
#define MX_CRT_VM_H
#include "mx_cfg_vm.h"
#include "mx_import_registry.h"
typedef struct {uint64_t rax,rbx,rcx,rdi,r11,rsp,rip,visited,resume_pc; uint32_t pending_import,instructions,imports; uint8_t zf,fault;} mx_crt_state;
enum { MX_CRT_RETURNED=1, MX_CRT_PAUSED_IMPORT=2, MX_CRT_INVALID=-1, MX_CRT_MEMORY_FAULT=-2 };
static inline uint64_t mx_crt_read(mx_crt_state *s,mx_cfg_memory *m,uint64_t a,uint32_t size) {
    uint64_t v=0;
    if(!mx_cfg_transfer(m,a,&v,size,0))s->fault=1;
    return v;
}
static inline int mx_crt_write(mx_crt_state *s,mx_cfg_memory *m,uint64_t a,uint32_t size,uint64_t v) {
    if(!mx_cfg_transfer(m,a,&v,size,1)) {s->fault=1;return 0;}
    return 1;
}
#endif
