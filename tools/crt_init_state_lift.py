"""Strict state-machine frontier lift for a bounded x64 CRT initialization block.

Three paths: already initializing, uninitialized (must invoke a direct CRT
callee), and other nonzero state. Both CALLs are STOP boundaries, not simulated
returns. Disassembles and validates all eighteen instructions before emitting C.
"""
from capstone import Cs,CS_ARCH_X86,CS_MODE_64
from capstone.x86 import X86_OP_REG,X86_OP_IMM,X86_OP_MEM
from .crt_cfg_lift import UnsupportedCRT

SHAPE=("mov","cmp","jne","lea","call","jmp","mov","test","jne",
       "mov","lea","lea","call","test","je","mov","jmp","mov")

def lift_crt_init_state(code:bytes,start:int,image_base:int=0x140000000):
    if not isinstance(code,bytes) or not 45<=len(code)<=160:
        raise UnsupportedCRT("Bounded state machine requires 45..160 original bytes")
    md=Cs(CS_ARCH_X86,CS_MODE_64);md.detail=True
    inst=list(md.disasm(code,start))
    if len(inst)!=18 or sum(i.size for i in inst)!=len(code):
        raise UnsupportedCRT("Expected complete eighteen-instruction original state frontier")
    if tuple(i.mnemonic for i in inst)!=SHAPE:
        raise UnsupportedCRT("Unexpected CRT initialization instruction family/order")
    def isreg(i,o,name,size):
        return o.type==X86_OP_REG and i.reg_name(o.reg)==name and o.size==size
    def isimm(o,num):
        return o.type==X86_OP_IMM and o.imm==num
    def ripmem(i,o,size):
        return (o.type==X86_OP_MEM and o.size==size and
                not o.mem.segment and not o.mem.index and
                i.reg_name(o.mem.base)=="rip")
    def mem_address(i,o):
        if not ripmem(i,o,o.size):
            raise UnsupportedCRT("Expected bounded RIP-relative address")
        target=image_base+i.address+i.size+o.mem.disp
        if target<image_base or target>=image_base+0x10000000:
            raise UnsupportedCRT("Guest address escaped bounded image interval")
        return target
    def direct(i):
        if len(i.operands)!=1 or i.operands[0].type!=X86_OP_IMM:
            raise UnsupportedCRT("Required original immediate direct call")
        target=i.operands[0].imm
        if start<=target<start+len(code):
            raise UnsupportedCRT("Direct callees must be external to this frontier")
        if not 0<=target<0x10000000:
            raise UnsupportedCRT("Direct callee outside supported image")
        return target
    first=inst[0]
    if not (len(first.operands)==2 and isreg(first,first.operands[0],"eax",4)
            and ripmem(first,first.operands[1],4)):
        raise UnsupportedCRT("Initial state must load 32-bit guest global")
    state=mem_address(first,first.operands[1])
    cmp=inst[1]
    if not (len(cmp.operands)==2 and isreg(cmp,cmp.operands[0],"eax",4)
            and isimm(cmp.operands[1],1)):
        raise UnsupportedCRT("Expected initial comparison against state 1")
    if not isimm(inst[2].operands[0],inst[6].address):
        raise UnsupportedCRT("State 1 fallthrough must branch to other state")
    lea=inst[3]
    if not (len(lea.operands)==2 and isreg(lea,lea.operands[0],"ecx",4)
            and lea.operands[1].type==X86_OP_MEM and
            lea.reg_name(lea.operands[1].mem.base)=="rax" and
            not lea.operands[1].mem.index and not lea.operands[1].mem.segment and
            lea.operands[1].mem.disp==30):
        raise UnsupportedCRT("Expected direct CRT callee argument from state")
    first_call=direct(inst[4])
    end=start+len(code)
    if not isimm(inst[5].operands[0],end):
        raise UnsupportedCRT("Expected join target after first direct CRT callee")
    nextload=inst[6]
    if not (len(nextload.operands)==2 and isreg(nextload,nextload.operands[0],"eax",4)
            and ripmem(nextload,nextload.operands[1],4)
            and mem_address(nextload,nextload.operands[1])==state):
        raise UnsupportedCRT("Expected same CRT global on second state read")
    test=inst[7]
    if not (len(test.operands)==2 and
            all(isreg(test,o,"eax",4) for o in test.operands)):
        raise UnsupportedCRT("Expected zero test of 32-bit state")
    if not isimm(inst[8].operands[0],inst[17].address):
        raise UnsupportedCRT("Expected alternate-state jump target")
    put=inst[9]
    if not (len(put.operands)==2 and ripmem(put,put.operands[0],4)
            and mem_address(put,put.operands[0])==state
            and isimm(put.operands[1],1)):
        raise UnsupportedCRT("Expected write state=1 before CRT initializer")
    addrs=[]
    for idx,name in ((10,"rdx"),(11,"rcx")):
        i=inst[idx]
        if not (len(i.operands)==2 and isreg(i,i.operands[0],name,8)
                and ripmem(i,i.operands[1],8)):
            raise UnsupportedCRT("Expected RIP-relative CRT callback array pointer")
        addrs.append(mem_address(i,i.operands[1]))
    second_call=direct(inst[12])
    tailtest=inst[13]
    if not (len(tailtest.operands)==2 and
            all(isreg(tailtest,o,"eax",4) for o in tailtest.operands)):
        raise UnsupportedCRT("Expected return-value test after the second direct call")
    if not isimm(inst[14].operands[0],end):
        raise UnsupportedCRT("Expected successful initialization join edge")
    bad=inst[15]
    if not (len(bad.operands)==2 and isreg(bad,bad.operands[0],"eax",4)
            and isimm(bad.operands[1],255)):
        raise UnsupportedCRT("Expected error return code")
    if not (len(inst[16].operands)==1 and inst[16].operands[0].type==X86_OP_IMM
            and inst[16].operands[0].imm>=end):
        raise UnsupportedCRT("Unexpected error path destination")
    alternate=inst[17]
    if not (len(alternate.operands)==2 and ripmem(alternate,alternate.operands[0],4)
            and isimm(alternate.operands[1],1)):
        raise UnsupportedCRT("Expected alternate-init flag write")
    alternate_addr=mem_address(alternate,alternate.operands[0])
    if alternate_addr==state:
        raise UnsupportedCRT("Alternate-init flag may not alias state")
    def mark(n):
        return f' s->visited |= UINT64_C({1<<n}); s->instructions++;\\n'
    generated=[
        '#include <stdint.h>\\n#include "mx_crt_vm.h"\\n',
        '/* 5: original direct CALL is unexecuted, 4: joined next block */\\n',
        'int lifted_crt_init_state(mx_crt_state *s,mx_cfg_memory *m,uint64_t *rdx){\\n',
        f' if(!s||!m||!rdx||s->fault||s->rip!=UINT64_C({image_base+start})||s->instructions)return MX_CRT_INVALID;\\n',
        mark(0),f' s->rax=mx_crt_read(s,m,UINT64_C({state}),4);\\n',
        ' if(s->fault)return MX_CRT_MEMORY_FAULT;\\n',
        mark(1),' s->zf=(s->rax==1U);\\n',
        mark(2),' if(s->zf){\\n',
        mark(3),' s->rcx=(uint32_t)(s->rax+UINT64_C(30));\\n',
        f' s->rip=UINT64_C({image_base+inst[4].address}); return 5;\\n',
        ' }\\n',
        mark(6),f' s->rax=mx_crt_read(s,m,UINT64_C({state}),4);\\n',
        ' if(s->fault)return MX_CRT_MEMORY_FAULT;\\n',
        mark(7),' s->zf=(s->rax==0U);\\n',
        mark(8),' if(!s->zf){\\n',
        mark(17),f' if(!mx_crt_write(s,m,UINT64_C({alternate_addr}),4,1U))return MX_CRT_MEMORY_FAULT;\\n',
        f' s->rip=UINT64_C({image_base+end});return MX_CRT_BRANCH_BOUNDARY;\\n',
        ' }\\n',
        mark(9),f' if(!mx_crt_write(s,m,UINT64_C({state}),4,1U))return MX_CRT_MEMORY_FAULT;\\n',
        mark(10),f' *rdx=UINT64_C({addrs[0]});\\n',
        mark(11),f' s->rcx=UINT64_C({addrs[1]});\\n',
        f' s->rip=UINT64_C({image_base+inst[12].address});return 5;\\n',
        '}\\n'
    ]
    # Calls are reported as targets, never executed or marked visited.
    meta={
        "decoded_original_instructions":18,
        "state_global_va":hex(state),"alternate_flag_va":hex(alternate_addr),
        "direct_call_targets_rva":[hex(first_call),hex(second_call)],
        "direct_call_sites_rva":[hex(inst[4].address),hex(inst[12].address)],
        "join_rva":hex(end),
        "supported_paths":["state_1_call_boundary","state_0_call_boundary","other_nonzero_join"],
        "direct_calls_executed":False
    }
    return "".join(generated).replace("\\\\n","\\n"),meta
