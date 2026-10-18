"""Strict AOT lifter for one original Win64 indexed-array accumulation-loop pattern.

Recognizes a specific 14-instruction region with a back edge, indexed memory
read-modify-write, signed compare and Win64 saved-register epilogue. Rejects
any instruction, offset, branch, or register-layout variation. Original code
is never embedded in this public module.
"""
from capstone import Cs,CS_ARCH_X86,CS_MODE_64

class UnsupportedIndexedLoop(ValueError):
    pass

OPS=[
    ("mov", "rax, qword ptr [rbx + 0x100]"),
    ("movsxd", "rcx, edx"),
    ("inc", "edx"),
    ("add", "dword ptr [rax + rcx*4], r12d"),
    ("cmp", "edx, dword ptr [rbx + 8]"),
    ("jl", None),
    ("xor", "eax, eax"),
    ("mov", "r12, qword ptr [rsp + 0x58]"),
    ("add", "rsp, 0x28"),
    ("pop", "r13"),
    ("pop", "rdi"),
    ("pop", "rbp"),
    ("pop", "rbx"),
    ("ret", ""),
]


def lift_indexed_loop(original:bytes,rva:int,max_iterations:int=128):
    if not isinstance(original,bytes) or len(original)>128 or len(original)<20:
        raise UnsupportedIndexedLoop("Unexpected original Win64 region size")
    if not 1<=max_iterations<=4096:
        raise UnsupportedIndexedLoop("Unsafe loop bound")
    md=Cs(CS_ARCH_X86,CS_MODE_64)
    md.detail=True
    ins=list(md.disasm(original,rva))
    if len(ins)!=len(OPS) or sum(i.size for i in ins)!=len(original):
        raise UnsupportedIndexedLoop("Incomplete or incompatible original loop disassembly")
    for n,(i,(mnemonic,operands)) in enumerate(zip(ins,OPS)):
        if i.mnemonic!=mnemonic or (operands is not None and i.op_str!=operands):
            raise UnsupportedIndexedLoop(f"Unexpected instruction pattern at {n}: {i.mnemonic} {i.op_str}")
    if ins[5].op_str!=hex(rva):
        raise UnsupportedIndexedLoop("Conditional back-edge is not at region start")
    code=r'''#include <stdint.h>
#include "mx_cfg_vm.h"
/* Exact verified indexed-accumulator region with a bounded loop. */
int lifted_indexed_loop(mx_cfg_state *s,mx_cfg_memory *mem) {
 if(!s || !mem) return -1;
 uint32_t iterations=0;
L_head:
 if(++iterations>ITERATION_CAP) return -2;
 /* mov rax,[rbx+0x100] */
 {
  uint64_t ptr=0;
  if(!mx_cfg_transfer(mem,s->rbx+UINT64_C(256),&ptr,8,0)) return -3;
  s->rax=ptr;
 }
 /* movsxd rcx,edx; inc edx (32-bit zero-extension) */
 s->rcx=(uint64_t)(int64_t)(int32_t)(uint32_t)s->rdx;
 {
  const uint32_t original=(uint32_t)s->rdx;
  const uint32_t result=original+1U;
  s->rdx=(uint64_t)result;
  /* INC preserves CF; ZF/SF/OF updated until following CMP. */
  s->zf=(uint8_t)(result==0U);
  s->sf=(uint8_t)((result&UINT32_C(0x80000000))!=0);
  s->of=(uint8_t)(original==UINT32_C(0x7fffffff));
 }
 /* ADD dword ptr [rax+rcx*4],r12d */
 {
  const uint64_t dest=s->rax+s->rcx*UINT64_C(4);
  uint32_t value=0;
  if(!mx_cfg_transfer(mem,dest,&value,4,0)) return -3;
  const uint32_t b=(uint32_t)s->r12;
  const uint32_t result=value+b;
  if(!mx_cfg_transfer(mem,dest,(void *)&result,4,1)) return -3;
  s->cf=(uint8_t)(result<value);
  s->of=(uint8_t)((((~(value^b))&(value^result))&UINT32_C(0x80000000))!=0);
  s->sf=(uint8_t)((result&UINT32_C(0x80000000))!=0);
  s->zf=(uint8_t)(result==0);
 }
 /* CMP edx,dword ptr [rbx+8]; JL L_head (signed). */
 {
  uint32_t limit=0;
  if(!mx_cfg_transfer(mem,s->rbx+UINT64_C(8),&limit,4,0)) return -3;
  const uint32_t a=(uint32_t)s->rdx;
  const uint32_t result=a-limit;
  s->cf=(uint8_t)(a<limit);
  s->of=(uint8_t)((((a^limit)&(a^result))&UINT32_C(0x80000000))!=0);
  s->sf=(uint8_t)((result&UINT32_C(0x80000000))!=0);
  s->zf=(uint8_t)(result==0);
  if(s->sf!=s->of)goto L_head;
 }
 /* xor eax,eax */
 s->rax=0;
 s->zf=1; s->sf=0; s->cf=0; s->of=0;
 /* Win64 epilogue; the region itself starts after the original prologue. */
 if(!mx_cfg_transfer(mem,s->rsp+UINT64_C(88),&s->r12,8,0))return -3;
 s->rsp+=UINT64_C(40);
 if(!mx_cfg_transfer(mem,s->rsp,&s->r13,8,0))return -3;
 s->rsp+=8;
 if(!mx_cfg_transfer(mem,s->rsp,&s->rdi,8,0))return -3;
 s->rsp+=8;
 if(!mx_cfg_transfer(mem,s->rsp,&s->rbp,8,0))return -3;
 s->rsp+=8;
 if(!mx_cfg_transfer(mem,s->rsp,&s->rbx,8,0))return -3;
 s->rsp+=8;
 if(!mx_cfg_transfer(mem,s->rsp,&s->rip,8,0))return -3;
 s->rsp+=8;
 return 1;
}
'''.replace("ITERATION_CAP",str(max_iterations)+"U")
    return code,{
        "begin_rva":hex(rva),"decoded_instruction_count":len(ins),
        "back_edges":1,"memory_array_stride":4,"array_pointer_field_offset":256,
        "loop_limit_field_offset":8,"max_iterations":max_iterations,
        "note":"Specific unwind-backed original code region, not source-level whole-function recovery."
    }
