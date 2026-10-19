"""Strict CRT post-initialization lock-release CFG boundary.

Validates eleven original x64 instructions and emits single-thread guest code
for state!=1 release/recursive branches. Stops before any direct CRT callee.
"""
from capstone import Cs,CS_ARCH_X86,CS_MODE_64
from capstone.x86 import X86_OP_REG,X86_OP_IMM,X86_OP_MEM
from .crt_cfg_lift import UnsupportedCRT

MNEMONICS=("mov","cmp","jne","lea","lea","call","mov",
           "test","jne","xor","xchg")

def lift_crt_common_release(code:bytes,start:int,image_base:int=0x140000000):
    if not isinstance(code,bytes) or not 32<=len(code)<=110:
        raise UnsupportedCRT("Unbounded CRT lock-release interval")
    md=Cs(CS_ARCH_X86,CS_MODE_64);md.detail=True
    ins=list(md.disasm(code,start))
    if len(ins)!=11 or sum(x.size for x in ins)!=len(code):
        raise UnsupportedCRT("Incomplete eleven-instruction release CFG")
    if tuple(x.mnemonic for x in ins)!=MNEMONICS:
        raise UnsupportedCRT("Unexpected original CRT release opcode sequence")
    def reg(i,o,name,size):
        return o.type==X86_OP_REG and o.size==size and i.reg_name(o.reg)==name
    def imm(o,val):
        return o.type==X86_OP_IMM and o.imm==val
    def rip(i,o,size):
        return (o.type==X86_OP_MEM and o.size==size and not o.mem.segment
                and not o.mem.index and i.reg_name(o.mem.base)=="rip")
    def guest(i,o):
        target=image_base+i.address+i.size+o.mem.disp
        if not image_base<=target<image_base+0x10000000:
            raise UnsupportedCRT("Guest address outside image mapping")
        return target
    a,b,j1,d,e,call,write,check,j2,zero,exchange=ins
    if not (len(a.operands)==2 and reg(a,a.operands[0],"eax",4)
            and rip(a,a.operands[1],4)):
        raise UnsupportedCRT("Expected 32-bit original CRT state read")
    state=guest(a,a.operands[1])
    if not (len(b.operands)==2 and reg(b,b.operands[0],"eax",4)
            and imm(b.operands[1],1)):
        raise UnsupportedCRT("Expected state==1 compare")
    if not (len(j1.operands)==1 and imm(j1.operands[0],check.address)):
        raise UnsupportedCRT("Expected skip-direct-call edge")
    arguments=[]
    for i,name in ((d,"rdx"),(e,"rcx")):
        if not (len(i.operands)==2 and reg(i,i.operands[0],name,8)
                and rip(i,i.operands[1],8)):
            raise UnsupportedCRT("Unrecognized CRT callback table pointer")
        arguments.append(guest(i,i.operands[1]))
    if not (len(call.operands)==1 and call.operands[0].type==X86_OP_IMM):
        raise UnsupportedCRT("Expected original external CRT direct call")
    target=call.operands[0].imm
    if not 0<=target<0x10000000 or start<=target<start+len(code):
        raise UnsupportedCRT("Original call target is unbounded or internal")
    if not (len(write.operands)==2 and rip(write,write.operands[0],4)
            and guest(write,write.operands[0])==state
            and imm(write.operands[1],2)):
        raise UnsupportedCRT("Expected state=2 store after unexecuted CRT call")
    if not (len(check.operands)==2 and
            all(reg(check,o,"esi",4) for o in check.operands)):
        raise UnsupportedCRT("Expected test ESI, ESI")
    end=start+len(code)
    if not (len(j2.operands)==1 and imm(j2.operands[0],end)):
        raise UnsupportedCRT("Expected recursive-owner skip of XCHG")
    if not (len(zero.operands)==2 and
            all(reg(zero,o,"eax",4) for o in zero.operands)):
        raise UnsupportedCRT("Expected XOR EAX, EAX before release")
    if not (len(exchange.operands)==2 and rip(exchange,exchange.operands[0],8)
            and reg(exchange,exchange.operands[1],"rax",8)):
        raise UnsupportedCRT("Expected original implicit-lock XCHG64")
    owner=guest(exchange,exchange.operands[0])
    if owner==state:
        raise UnsupportedCRT("Lock owner and global CRT state cannot alias")
    def step(n):
        return f' s->visited|=UINT64_C({1<<n});s->instructions++;\\n'
    C=[
        '#include <stdint.h>\\n#include "mx_crt_primitives.h"\\n',
        'int lifted_crt_common_release(mx_crt_state*s,mx_cfg_memory*m,uint64_t*rdx,int exclusive){\\n',
        f' if(!s||!m||!rdx||s->fault||s->rip!=UINT64_C({image_base+start})||s->instructions)return MX_CRT_INVALID;\\n',
        step(0),f' s->rax=mx_crt_read(s,m,UINT64_C({state}),4);\\n',
        ' if(s->fault)return MX_CRT_MEMORY_FAULT;\\n',
        step(1),' s->zf=(s->rax==1U);\\n',
        step(2),' if(s->zf){\\n',
        step(3),f' *rdx=UINT64_C({arguments[0]});\\n',
        step(4),f' s->rcx=UINT64_C({arguments[1]});\\n',
        f' s->rip=UINT64_C({image_base+call.address});return 5;\\n',
        ' }\\n',
        step(7),' s->zf=((uint32_t)s->rsi==0U);\\n',
        step(8),' if(!s->zf){\\n',
        f' s->rip=UINT64_C({image_base+end});return MX_CRT_BRANCH_BOUNDARY;\\n',
        ' }\\n',
        step(9),' s->rax=0;s->zf=1;\\n',
        step(10),f' if(!mx_crt_xchg64_single_thread(s,m,UINT64_C({owner}),exclusive))return MX_CRT_MEMORY_FAULT;\\n',
        f' s->rip=UINT64_C({image_base+end});return MX_CRT_BRANCH_BOUNDARY;\\n',
        '}\\n'
    ]
    meta={
        "decoded_original_instructions":11,
        "state_global_va":hex(state),"lock_owner_global_va":hex(owner),
        "direct_call_site_rva":hex(call.address),
        "direct_call_target_rva":hex(target),
        "release_join_rva":hex(end),
        "paths":["state_one_direct_call_boundary","recursive_owner_no_release","nonrecursive_owner_release"],
        "direct_call_executed":False,
        "concurrent_exchange_supported":False
    }
    return "".join(C).replace("\\\\n","\\n"),meta
