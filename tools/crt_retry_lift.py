"""Bounded CRT compare-exchange retry CFG with one deterministic Sleep boundary.

Validates original x64 instruction forms before emitting C. Only the guest
single-thread scheduler/retry behavior is modeled. Sleep is a required injected
callback, not a Windows implementation; no actual time passes.
"""
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
from capstone.x86 import X86_OP_REG, X86_OP_IMM, X86_OP_MEM
from .crt_cfg_lift import UnsupportedCRT, _addr

def lift_crt_retry(retry:bytes,branch:bytes,retry_rva:int,branch_rva:int,
                   iat:dict,image_base:int=0x140000000):
    md=Cs(CS_ARCH_X86,CS_MODE_64)
    md.detail=True
    if not isinstance(retry,bytes) or not isinstance(branch,bytes):
        raise UnsupportedCRT("Original CFG segments must be immutable bytes")
    if not (8<=len(retry)<=24 and 18<=len(branch)<=64):
        raise UnsupportedCRT("Unbounded retry/branch intervals")
    rs=list(md.disasm(retry,retry_rva))
    bs=list(md.disasm(branch,branch_rva))
    if len(rs)!=2 or len(bs)!=8 or sum(x.size for x in rs)!=len(retry) or sum(x.size for x in bs)!=len(branch):
        raise UnsupportedCRT("Incorrect original retry/branch boundaries")
    if retry_rva+len(retry)!=branch_rva:
        raise UnsupportedCRT("Noncontiguous original CAS to branch")
    if [x.mnemonic for x in rs]!=["xor","lock cmpxchg"]:
        raise UnsupportedCRT("Unexpected original retry operation")
    if [x.mnemonic for x in bs]!=["je","cmp","jne","mov","jmp","mov","call","jmp"]:
        raise UnsupportedCRT("Unexpected original compare-and-wait CFG")
    xor,cas=rs
    je,cmp,jne,esi,jmp,ecx,call,back=bs
    def reg(i,o,name,size):
        return o.type==X86_OP_REG and i.reg_name(o.reg)==name and o.size==size
    def immediate(i,o,value):
        return o.type==X86_OP_IMM and o.imm==value
    if not (len(xor.operands)==2 and all(reg(xor,o,"eax",4) for o in xor.operands)):
        raise UnsupportedCRT("Retry must zero EAX")
    if not (len(cas.operands)==2 and cas.operands[0].type==X86_OP_MEM and
            cas.operands[0].size==8 and reg(cas,cas.operands[1],"rdi",8) and
            0xf0 in cas.prefix and
            cas.reg_name(cas.operands[0].mem.base)=="rip"):
        raise UnsupportedCRT("Retry must be original RIP-relative LOCK CMPXCHG64")
    target=_addr(cas,cas.operands[0],image_base)
    done_rva=branch_rva+len(branch)
    mov_sleep_rva=ecx.address
    if not (immediate(je,je.operands[0],done_rva) and
            len(cmp.operands)==2 and reg(cmp,cmp.operands[0],"rax",8) and
            reg(cmp,cmp.operands[1],"rdi",8) and
            immediate(jne,jne.operands[0],mov_sleep_rva) and
            len(esi.operands)==2 and reg(esi,esi.operands[0],"esi",4) and
            immediate(esi,esi.operands[1],1) and
            immediate(jmp,jmp.operands[0],done_rva) and
            len(ecx.operands)==2 and reg(ecx,ecx.operands[0],"ecx",4) and
            immediate(ecx,ecx.operands[1],1000) and
            len(call.operands)==1 and call.operands[0].type==X86_OP_MEM and
            call.reg_name(call.operands[0].mem.base)=="rip" and
            immediate(back,back.operands[0],retry_rva)):
        raise UnsupportedCRT("Unexpected original branch targets or Win64 Sleep arguments")
    slot=call.address+call.size+call.operands[0].mem.disp
    if iat.get(slot)!=("kernel32.dll","Sleep"):
        raise UnsupportedCRT("Callsite must resolve to validated Kernel32 Sleep")
    def step(bit):
        return (f' if(++s->instructions>128U)return MX_CRT_INVALID;\n'
                f' s->visited|=UINT64_C({1<<bit});\n')
    c=['#include <stdint.h>\n#include "mx_crt_primitives.h"\n',
       'typedef int (*mx_crt_sleep_callback)(void*,uint32_t);\n',
       'int lifted_crt_lock_retry(mx_crt_state *s,mx_cfg_memory *m,\n',
       '        mx_crt_sleep_callback sleep_call,void *context,int exclusive){\n',
       f' if(!s||!m||s->fault||s->rip!=UINT64_C({image_base+branch_rva}))return MX_CRT_INVALID;\n',
       ' if(!exclusive)return MX_CRT_INVALID;\n',
       ' goto JE_DECISION;\n',
       'RETRY:\n',
       step(0),' s->rax=0;s->zf=1;\n',
       step(1),
       f' if(!mx_crt_cmpxchg64_single_thread(s,m,{target},s->rdi,exclusive))return MX_CRT_MEMORY_FAULT;\n',
       'JE_DECISION:\n',
       step(2),
       ' if(s->zf)goto COMPLETE;\n',
       step(3),
       ' s->zf=(s->rax==s->rdi);\n',
       step(4),
       ' if(!s->zf)goto WAIT_AND_RETRY;\n',
       step(5),' s->rsi=1U;\n',
       step(6),' goto COMPLETE;\n',
       'WAIT_AND_RETRY:\n',
       step(7),' s->rcx=1000U;\n',
       step(8),
       ' if(!sleep_call || (s->rsp&15U))return MX_CRT_INVALID;\n',
       f' if(!mx_crt_write(s,m,s->rsp-8U,8,UINT64_C({image_base+call.address+call.size})))return MX_CRT_MEMORY_FAULT;\n',
       ' if(!sleep_call(context,1000U))return MX_CRT_INVALID;\n',
       ' s->imports++;s->import_trace=s->import_trace*8U+1U;\n',
       step(9),' goto RETRY;\n',
       'COMPLETE:\n',
       f' s->rip=UINT64_C({image_base+done_rva});\n',
       ' return MX_CRT_BRANCH_BOUNDARY;\n}\n']
    return "".join(c),{
        "retry_rva":hex(retry_rva),"branch_rva":hex(branch_rva),
        "stop_before_rva":hex(done_rva),"validated_sleep_iat_slot":hex(slot),
        "static_instruction_count":10,"retry_cap":128,
        "sleep_is_injected":True,"concurrent_lock_semantics":False
    }
