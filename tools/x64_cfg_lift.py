"""Restricted multi-basic-block x64 guest-state AOT lifter.

Supported: mov reg,[reg+positive disp], mov [reg+disp],reg,
test reg,reg; je/jne relative internal labels; add rsp,imm; ret.
Requires exact full decode, verified branch destinations and one ret.
Explicit guest memory ranges prevent illegal addresses.
This is NOT a general x64 decompiler, function ABI or emulator.
"""
import json
from capstone import Cs,CS_ARCH_X86,CS_MODE_64,CS_GRP_JUMP
from capstone.x86 import X86_OP_REG,X86_OP_MEM,X86_OP_IMM

class UnsupportedCFG(ValueError):
    pass

REGS={"rax":("rax",64),"eax":("rax",32),"rcx":("rcx",64),"ecx":("rcx",32),
      "rdx":("rdx",64),"edx":("rdx",32),"rsp":("rsp",64)}

def _reg(inst,operand):
    if operand.type!=X86_OP_REG:raise UnsupportedCFG("Expected integer register")
    name=inst.reg_name(operand.reg)
    if name not in REGS:raise UnsupportedCFG("Unmodeled general-purpose register "+name)
    return REGS[name]

def _mem(inst,operand):
    if operand.type!=X86_OP_MEM:raise UnsupportedCFG("Expected guest memory")
    base=inst.reg_name(operand.mem.base)
    if base not in ("rcx","rdx","rsp") or operand.mem.index or operand.mem.segment:
        raise UnsupportedCFG("Only unindexed [rcx/rdx/rsp + disp] supported")
    if not (0<=operand.mem.disp<=1024):
        raise UnsupportedCFG("Unsupported guest displacement")
    if operand.size not in (4,8):raise UnsupportedCFG("Only 32/64-bit memory transfer supported")
    return f"s->{base} + {operand.mem.disp}ULL",operand.size

def translate_cfg(blob:bytes,start:int):
    if not isinstance(blob,bytes) or not 3<=len(blob)<=256:
        raise UnsupportedCFG("Original code span outside safety cap")
    md=Cs(CS_ARCH_X86,CS_MODE_64);md.detail=True
    instructions=list(md.disasm(blob,start))
    if not instructions or sum(i.size for i in instructions)!=len(blob):
        raise UnsupportedCFG("Full x64 instruction decoding required")
    addrs={i.address for i in instructions}
    if not instructions[-1].mnemonic=="ret" or sum(i.mnemonic=="ret" for i in instructions)!=1:
        raise UnsupportedCFG("Require exactly one terminal ret")
    branches=0
    for i in instructions:
        if i.mnemonic in ("je","jne"):
            if len(i.operands)!=1 or i.operands[0].type!=X86_OP_IMM or i.operands[0].imm not in addrs:
                raise UnsupportedCFG("Branch target outside decoded instruction starts")
            branches+=1
        elif i.group(CS_GRP_JUMP):
            raise UnsupportedCFG("Unimplemented x64 branch")
        if i.mnemonic not in ("mov","test","je","jne","add","ret"):
            raise UnsupportedCFG("Unimplemented x64 opcode: "+i.mnemonic)
    if not branches:raise UnsupportedCFG("No conditional branch to translate")
    body=['#include <stdint.h>\n#include "mx_cfg_vm.h"\n',
          'int lifted_cfg(mx_cfg_state *s,mx_cfg_memory *mem) {\n',
          ' if (!s || !mem) return -1;\n',
          ' uint32_t steps=0;\n',
          f' goto L_{start:x};\n']
    for inst in instructions:
        body += [f'L_{inst.address:x}:\n',
                 ' if (++steps>256U) return -2;\n']
        ops=inst.operands
        if inst.mnemonic=="mov":
            if len(ops)!=2:raise UnsupportedCFG("Unexpected MOV count")
            if ops[0].type==X86_OP_REG and ops[1].type==X86_OP_MEM:
                field,bits=_reg(inst,ops[0])
                addr,size=_mem(inst,ops[1])
                if bits!=size*8:raise UnsupportedCFG("Operand width mismatch")
                body += [f' {{ uint64_t v=0; if(!mx_cfg_transfer(mem,{addr},&v,{size},0)) return -3;\n',
                         f' s->{field}='+('(uint32_t)v' if bits==32 else 'v')+'; }\n']
            elif ops[0].type==X86_OP_MEM and ops[1].type==X86_OP_REG:
                addr,size=_mem(inst,ops[0])
                field,bits=_reg(inst,ops[1])
                if bits!=size*8:raise UnsupportedCFG("Store width mismatch")
                body += [f' {{ uint64_t v=s->{field}; if(!mx_cfg_transfer(mem,{addr},&v,{size},1)) return -3; }}\n']
            elif ops[0].type==X86_OP_REG and ops[1].type==X86_OP_IMM:
                field,bits=_reg(inst,ops[0])
                v=ops[1].imm & ((1<<bits)-1)
                body += [f' s->{field}=UINT64_C({v});\n']
            else:raise UnsupportedCFG("Unhandled MOV operand form")
        elif inst.mnemonic=="test":
            if len(ops)!=2 or any(o.type!=X86_OP_REG for o in ops):
                raise UnsupportedCFG("Only TEST register,register supported")
            lhs,lbits=_reg(inst,ops[0]);rhs,rbits=_reg(inst,ops[1])
            if lbits!=rbits:raise UnsupportedCFG("TEST width mismatch")
            suffix=" & UINT64_C(4294967295)" if lbits==32 else ""
            body += [f' s->zf= (((s->{lhs} & s->{rhs}){suffix}) == 0);\n']
        elif inst.mnemonic in ("je","jne"):
            target=inst.operands[0].imm
            condition="s->zf" if inst.mnemonic=="je" else "!s->zf"
            body += [f' if ({condition}) goto L_{target:x};\n']
        elif inst.mnemonic=="add":
            if len(ops)!=2 or ops[0].type!=X86_OP_REG or ops[1].type!=X86_OP_IMM:
                raise UnsupportedCFG("Only ADD RSP,immediate supported")
            field,bits=_reg(inst,ops[0])
            amount=ops[1].imm
            if field!="rsp" or bits!=64 or amount not in (8,16,24,32,40,48,64,80):
                raise UnsupportedCFG("Unexpected RSP adjustment")
            body += [f' s->rsp += {amount}ULL;\n']
        elif inst.mnemonic=="ret":
            if len(ops)!=0:raise UnsupportedCFG("Only near RET supported")
            body += [' { uint64_t retaddr=0;\n',
                     ' if(!mx_cfg_transfer(mem,s->rsp,&retaddr,8,0)) return -4;\n',
                     ' s->rip=retaddr; s->rsp+=8ULL; return 1; }\n']
    body+=[' return -5;\n}\n']
    return "".join(body),{"original_instruction_count":len(instructions),
                          "conditional_branches":branches,
                          "entry_rva":hex(start),
                          "note":"Restricted fully decoded region; does not establish source-level function boundary."}
