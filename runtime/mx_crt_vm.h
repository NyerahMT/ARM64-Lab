#ifndef MX_CRT_VM_H
#define MX_CRT_VM_H
#include "mx_cfg_vm.h"
#include "mx_import_registry.h"
typedef struct {uint64_t rax,rbx,rcx,rdi,r11,rsp,rip,visited,resume_pc; uint32_t pending_import,instructions,imports; uint8_t zf,fault;} mx_crt_state;
#endif
