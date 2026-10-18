"""Strictly decode and link a pair of x64 functions into one native C runtime.

Synthetic control sequence:
  caller: sub rsp,0x28; call rel32 callee; add rsp,0x28; ret
  callee: mov eax,ecx; add eax,imm8; ret

Every x64 opcode and direct branch destination must match. A real call
pushes the guest return address and invokes the generated callee function;
no stubbed callee or synthetic success is used. This intentionally does not
support arbitrary x64 functions, indirect calls or recursive call graphs.
"""
from capstone import Cs,CS_ARCH_X86,CS_MODE_64
from capstone.x86 import X86_OP_IMM


class UnsupportedLinkedCall(ValueError):
    pass


def translate_linked_pair(caller:bytes,caller_rva:int,callee:bytes,callee_rva:int):
    md=Cs(CS_ARCH_X86,CS_MODE_64);md.detail=True
    first=list(md.disasm(caller,caller_rva))
    second=list(md.disasm(callee,callee_rva))
    if not 0<len(caller)<=64 or not 0<len(callee)<=64:
        raise UnsupportedLinkedCall("Invalid function lengths")
    if len(first)!=4 or sum(i.size for i in first)!=len(caller):
        raise UnsupportedLinkedCall("Caller is not a complete four-instruction wrapper")
    if len(second)!=3 or sum(i.size for i in second)!=len(callee):
        raise UnsupportedLinkedCall("Callee is not a complete integer helper")
    expected_caller=[("sub","rsp, 0x28"),("call",None),("add","rsp, 0x28"),("ret","")]
    expected_callee=[("mov","eax, ecx"),("add",None),("ret","")]
    for i,(expected_op,expected_args) in zip(first,expected_caller):
        if i.mnemonic!=expected_op or (expected_args is not None and i.op_str!=expected_args):
            raise UnsupportedLinkedCall("Unsupported caller ABI or operation")
    for i,(expected_op,expected_args) in zip(second,expected_callee):
        if i.mnemonic!=expected_op or (expected_args is not None and i.op_str!=expected_args):
            raise UnsupportedLinkedCall("Unsupported callee ABI or operation")
    op=first[1]
    if len(op.operands)!=1 or op.operands[0].type!=X86_OP_IMM or op.operands[0].imm!=callee_rva:
        raise UnsupportedLinkedCall("Direct call does not target the supplied callee")
    addition=second[1]
    if len(addition.operands)!=2 or addition.op_str.split(", ")[0]!="eax" or addition.operands[1].type!=X86_OP_IMM:
        raise UnsupportedLinkedCall("Callee must perform ADD EAX,immediate")
    addend=int(addition.operands[1].imm)&0xffffffff
    return_rva=op.address+op.size
    source=r'''#include <stdint.h>
#include "mx_cfg_vm.h"
/* Genuine linked native guest callee; not an injected RET stub. */
static int lifted_callee(mx_cfg_state *s,mx_cfg_memory *mem) {
 if(!s || !mem)return -1;
 /* MOV EAX,ECX zero-extends its destination. */
 s->rax=(uint32_t)s->rcx;
 /* ADD EAX,IMM32 carries ZF/SF/CF/OF semantics. */
 {
   const uint32_t a=(uint32_t)s->rax;
   const uint32_t b=UINT32_C(ADDEND);
   const uint32_t sum=a+b;
   s->rax=sum;
   s->cf=(uint8_t)(sum<a);
   s->of=(uint8_t)((((~(a^b))&(a^sum))&UINT32_C(0x80000000))!=0);
   s->sf=(uint8_t)((sum&UINT32_C(0x80000000))!=0);
   s->zf=(uint8_t)(sum==0);
 }
 /* Actual guest RET from the nested function. */
 if(!mx_cfg_transfer(mem,s->rsp,&s->rip,8,0))return -4;
 s->rsp+=8;
 return 1;
}
int lifted_caller(mx_cfg_state *s,mx_cfg_memory *mem) {
 if(!s || !mem)return -1;
 const uint64_t original_rsp=s->rsp;
 if(original_rsp%16!=8 || original_rsp<48)return -5;
 s->rsp-=40;
 /* True Win64 CALL: pushes a guest return address, then invokes callee. */
 s->rsp-=8;
 {
   uint64_t nested_return=UINT64_C(RETURN_RVA);
   if(!mx_cfg_transfer(mem,s->rsp,&nested_return,8,1))return -3;
 }
 s->rip=UINT64_C(CALLEE_RVA);
 int callee_status=lifted_callee(s,mem);
 if(callee_status!=1)return callee_status;
 if(s->rip!=UINT64_C(RETURN_RVA) || s->rsp!=original_rsp-40)return -6;
 /* ADD RSP,0x28 is an arithmetic x64 instruction and sets flags. */
 {
  const uint64_t a=s->rsp;
  const uint64_t b=UINT64_C(40);
  const uint64_t sum=a+b;
  s->rsp=sum;
  s->cf=(uint8_t)(sum<a);
  s->of=(uint8_t)((((~(a^b))&(a^sum))&UINT64_C(9223372036854775808))!=0);
  s->sf=(uint8_t)((sum>>63)!=0);
  s->zf=(uint8_t)(sum==0);
 }
 if(!mx_cfg_transfer(mem,s->rsp,&s->rip,8,0))return -4;
 s->rsp+=8;
 return 1;
}
'''.replace("UINT32_C(ADDEND)","UINT32_C("+str(addend)+")").replace(
    "UINT64_C(RETURN_RVA)","UINT64_C("+str(return_rva)+")").replace(
    "UINT64_C(CALLEE_RVA)","UINT64_C("+str(callee_rva)+")")
    return source,{
      "caller_rva":hex(caller_rva),"callee_rva":hex(callee_rva),
      "nested_call_return_rva":hex(return_rva),"callee_addend":addend,
      "original_decoded_instructions":len(first)+len(second),
      "actual_linked_callee_emitted":True,
      "scope":"Restricted synthetic two-function Win64 call pattern only"
    }


def synthetic_pair():
    caller_rva,callee_rva=0x1000,0x1100
    caller=(b"\x48\x83\xec\x28"
            +b"\xe8"+(callee_rva-(caller_rva+9)).to_bytes(4,"little",signed=True)
            +b"\x48\x83\xc4\x28\xc3")
    callee=b"\x89\xc8\x83\xc0\x05\xc3"
    return caller_rva,caller,callee_rva,callee
