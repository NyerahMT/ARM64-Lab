"""Bounded x86-64 integer loop and condition-code AOT translator.

Handles a rigorously small subset: direct internal Jcc/JMP; MOV between
supported registers/immediates; 32/64-bit register arithmetic, CMP, TEST,
INC/DEC, XOR, RET. Models ZF, SF, CF and OF, zero-extension of 32-bit writes
and INC/DEC CF preservation. No x87/SSE, memory ALU, calls, or OS effects.
"""
from capstone import Cs,CS_ARCH_X86,CS_MODE_64,CS_GRP_JUMP
from capstone.x86 import X86_OP_REG,X86_OP_IMM


class UnsupportedLoop(ValueError):
    pass


REGS={
    "rax":("rax",64),"eax":("rax",32),
    "rcx":("rcx",64),"ecx":("rcx",32),
    "rdx":("rdx",64),"edx":("rdx",32),
}
CONDS={
    "je":"s->zf", "jne":"!s->zf",
    "jl":"(s->sf != s->of)", "jge":"(s->sf == s->of)",
    "jle":"(s->zf || s->sf != s->of)","jg":"(!s->zf && s->sf == s->of)",
    "jb":"s->cf", "jae":"!s->cf",
    "jbe":"(s->cf || s->zf)", "ja":"(!s->cf && !s->zf)",
    "js":"s->sf", "jns":"!s->sf",
}
ALIASES={"jz":"je","jnz":"jne","jc":"jb","jnc":"jae"}


def _register(inst, op):
    if op.type!=X86_OP_REG:
        raise UnsupportedLoop("Expected supported general-purpose register")
    name=inst.reg_name(op.reg)
    if name not in REGS:
        raise UnsupportedLoop(f"Unsupported x64 register {name}")
    return REGS[name]


def _rhs(inst, op, width):
    if op.type==X86_OP_REG:
        field,bits=_register(inst,op)
        if bits!=width:
            raise UnsupportedLoop("Mixed operand widths")
        return f"s->{field}"
    if op.type==X86_OP_IMM:
        # Capstone sign-extends encoded immediate operands as x64 does.
        imm=int(op.imm)&((1<<width)-1)
        return f"UINT64_C({imm})"
    raise UnsupportedLoop("Memory ALU and indirect operands not yet translated")


def translate_integer_loop(code:bytes, start_rva:int, max_steps:int=1024):
    if not isinstance(code,bytes) or not 3<=len(code)<=256:
        raise UnsupportedLoop("Code length must be 3..256 bytes")
    if not 1<=max_steps<=65536:
        raise UnsupportedLoop("Unbounded loop instruction budget")
    md=Cs(CS_ARCH_X86,CS_MODE_64)
    md.detail=True
    inst=list(md.disasm(code,start_rva))
    if not inst or sum(x.size for x in inst)!=len(code) or len(inst)>64:
        raise UnsupportedLoop("Incomplete or excessive instruction decoding")
    if sum(i.mnemonic=="ret" for i in inst)!=1 or inst[-1].mnemonic!="ret":
        raise UnsupportedLoop("Require one terminal near RET")
    addresses={i.address for i in inst}
    branches=[]
    for i in inst:
        mnemonic=ALIASES.get(i.mnemonic,i.mnemonic)
        if mnemonic in CONDS or mnemonic=="jmp":
            if len(i.operands)!=1 or i.operands[0].type!=X86_OP_IMM or i.operands[0].imm not in addresses:
                raise UnsupportedLoop("Branch target is not an internal instruction boundary")
            branches.append((i.address,i.operands[0].imm))
        elif i.group(CS_GRP_JUMP):
            raise UnsupportedLoop("Unsupported conditional or indirect jump")
        if mnemonic not in {"mov","add","sub","cmp","test","inc","dec","xor","ret","jmp",*CONDS}:
            raise UnsupportedLoop("Unsupported instruction "+i.mnemonic)
    if not branches:
        raise UnsupportedLoop("No branches in proposed loop/CFG code")
    if not any(target<=address for address,target in branches):
        raise UnsupportedLoop("No backward edge: use the non-loop translator")
    src=[
        '#include <stdint.h>\n#include "mx_cfg_vm.h"\n',
        'int lifted_integer_loop(mx_cfg_state *s,mx_cfg_memory *mem) {\n',
        ' if(!s || !mem) return -1;\n',
        ' uint32_t steps=0;\n',
        ' uint8_t flags_ready=0;\n',
        f' goto L_{start_rva:x};\n'
    ]
    targets={start_rva}|{target for _,target in branches}
    for i in inst:
        if i.address in targets:
            src.append(f"L_{i.address:x}:\n")
        src.append(f" if(++steps>{max_steps}U) return -2;\n")
        m=ALIASES.get(i.mnemonic,i.mnemonic)
        ops=i.operands
        if m=="mov":
            if len(ops)!=2:
                raise UnsupportedLoop("Wrong MOV operand count")
            dest,bits=_register(i,ops[0])
            val=_rhs(i,ops[1],bits)
            mask="UINT64_C(4294967295)" if bits==32 else "UINT64_MAX"
            src.append(f" s->{dest}=({val}) & {mask};\n")
        elif m in ("add","sub","cmp","test","xor","inc","dec"):
            if len(ops)!=(1 if m in ("inc","dec") else 2):
                raise UnsupportedLoop("Wrong ALU operand count")
            dest,bits=_register(i,ops[0])
            other="UINT64_C(1)" if m in ("inc","dec") else _rhs(i,ops[1],bits)
            mask="UINT64_C(4294967295)" if bits==32 else "UINT64_MAX"
            sign="UINT64_C(2147483648)" if bits==32 else "UINT64_C(9223372036854775808)"
            src.append(" {\n")
            src.append(f"  const uint64_t a=s->{dest} & {mask};\n")
            src.append(f"  const uint64_t b=({other}) & {mask};\n")
            if m in ("add","inc"):
                src.append(f"  const uint64_t result=(a+b)&{mask};\n")
                if m=="add":
                    if bits==64:
                        src.append("  s->cf=(uint8_t)(result<a);\n")
                    else:
                        src.append(f"  s->cf=(uint8_t)((a+b)>{mask});\n")
                src.append(f"  s->of=(uint8_t)((((~(a^b))&(a^result))&{sign})!=0);\n")
            elif m in ("sub","dec","cmp"):
                src.append(f"  const uint64_t result=(a-b)&{mask};\n")
                if m in ("sub","cmp"):
                    src.append("  s->cf=(uint8_t)(a<b);\n")
                src.append(f"  s->of=(uint8_t)((((a^b)&(a^result))&{sign})!=0);\n")
            else:
                operator="&" if m=="test" else "^"
                src.append(f"  const uint64_t result=(a{operator}b)&{mask};\n")
                src.append("  s->cf=0; s->of=0;\n")
            src.append(f"  s->zf=(uint8_t)(result==0); s->sf=(uint8_t)((result&{sign})!=0);\n")
            src.append("  flags_ready=1;\n")
            if m not in ("test","cmp"):
                src.append(f"  s->{dest}=result;\n")
            src.append(" }\n")
        elif m in CONDS:
            dest=ops[0].imm
            src.append(f" if(!flags_ready) return -6;\n if({CONDS[m]}) goto L_{dest:x};\n")
        elif m=="jmp":
            src.append(f" goto L_{ops[0].imm:x};\n")
        elif m=="ret":
            if len(ops):
                raise UnsupportedLoop("Only near RET without immediate")
            src += [
                " { uint64_t retaddr=0;\n",
                " if(!mx_cfg_transfer(mem,s->rsp,&retaddr,8,0)) return -4;\n",
                " s->rip=retaddr; s->rsp+=8ULL; return 1; }\n"
            ]
    src.append(" return -5;\n}\n")
    return "".join(src),{
        "entry_rva":hex(start_rva),
        "instructions":len(inst),
        "branches":len(branches),
        "back_edges":sum(target<=address for address,target in branches),
        "max_execution_steps":max_steps,
        "model":"AOT integer condition-code interpreter with explicit bounded guest state",
        "scope":"Limited instruction subset, not arbitrary executable or native iOS code"
    }
