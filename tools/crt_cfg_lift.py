"""Strict bounded x64 CRT control-flow to portable C translation.

Converts verified original instruction forms into resumable guest-state C.
Windows calls pause for explicit typed native dispatch; they are never
silently treated as RET. Not a general PE loader, decompiler or iOS port.
"""
from capstone import Cs, CS_ARCH_X86, CS_MODE_64, CS_GRP_JUMP
from capstone.x86 import X86_OP_REG, X86_OP_IMM, X86_OP_MEM
from .startup_gate import static_cfg_blocks

class UnsupportedCRT(ValueError):
    pass

REGS={"rax":"rax","eax":"rax","rbx":"rbx","rcx":"rcx","rdi":"rdi",
      "r11":"r11","r11d":"r11","rsp":"rsp"}
ALLOWED={"GetSystemTimeAsFileTime","GetCurrentThreadId",
         "GetCurrentProcessId","GetTickCount","QueryPerformanceCounter"}

def _addr(ins, op, base):
    if op.type!=X86_OP_MEM or op.mem.index or op.mem.segment:
        raise UnsupportedCRT("Unrecognized guest memory address")
    reg=ins.reg_name(op.mem.base)
    if reg=="rip":
        return f"UINT64_C({base+ins.address+ins.size+op.mem.disp})"
    if reg=="rsp":
        return f"(s->rsp + UINT64_C({op.mem.disp & 0xffffffffffffffff}))"
    raise UnsupportedCRT("Only RIP-relative globals and RSP stack supported")

def _get(ins,op,base):
    if op.type==X86_OP_REG:
        name=ins.reg_name(op.reg)
        if name not in REGS or op.size not in (4,8):
            raise UnsupportedCRT("Unsupported source register: "+name)
        field="s->"+REGS[name]
        return f"((uint32_t){field})" if op.size==4 else field
    if op.type==X86_OP_IMM:
        return f"UINT64_C({op.imm & 0xffffffffffffffff})"
    if op.type==X86_OP_MEM and op.size in (4,8):
        return f"mx_crt_read(s,m,{_addr(ins,op,base)},{op.size})"
    raise UnsupportedCRT("Unsupported source operand")

def _put(ins,op,value,base):
    if op.type==X86_OP_REG:
        name=ins.reg_name(op.reg)
        if name not in REGS or op.size not in (4,8):
            raise UnsupportedCRT("Unsupported destination register: "+name)
        expr=f"((uint32_t)({value}))" if op.size==4 else f"({value})"
        return f"s->{REGS[name]}={expr};"
    if op.type==X86_OP_MEM and op.size in (4,8):
        return f"if(!mx_crt_write(s,m,{_addr(ins,op,base)},{op.size},({value})))return MX_CRT_MEMORY_FAULT;"
    raise UnsupportedCRT("Unsupported destination operand")

def translate_crt_cfg(code:bytes,start:int,iat:dict,image_base:int=0x140000000):
    """Emit a resumable instruction-to-C CFG, validating every edge and import.

    Returned status: 1 guest RET, 2 pending imported CALL, negative error.
    Only measured RAX/RBX/RCX/RDI/R11/RSP and ZF are modeled.
    """
    if not isinstance(code,bytes) or not 3<=len(code)<=768:
        raise UnsupportedCRT("Unbounded function code")
    md=Cs(CS_ARCH_X86,CS_MODE_64);md.detail=True
    instructions=list(md.disasm(code,start))
    if not instructions or sum(i.size for i in instructions)!=len(code):
        raise UnsupportedCRT("Incomplete original x64 disassembly")
    if len(instructions)>63 or sum(i.mnemonic=="ret" for i in instructions)!=1:
        raise UnsupportedCRT("Require at most 63 instructions, exactly one RET")
    cfg=static_cfg_blocks(instructions)
    targets={i.address for i in instructions}
    imports=[]
    for ins in instructions:
        if ins.group(CS_GRP_JUMP):
            if ins.mnemonic not in ("je","jmp") or len(ins.operands)!=1 or ins.operands[0].type!=X86_OP_IMM or ins.operands[0].imm not in targets:
                raise UnsupportedCRT("Unsupported jump or branch target")
        if ins.mnemonic=="call":
            if len(ins.operands)!=1 or ins.operands[0].type!=X86_OP_MEM:
                raise UnsupportedCRT("Only RIP-relative IAT CALL supported")
            address=_addr(ins,ins.operands[0],0)
            slot=ins.address+ins.size+ins.operands[0].mem.disp
            if not address or slot not in iat:
                raise UnsupportedCRT("Unverified imported call site")
            dll,name=iat[slot]
            if dll.lower()!="kernel32.dll" or name not in ALLOWED:
                raise UnsupportedCRT("Unsupported runtime import")
            imports.append((ins.address,ins.address+ins.size,dll,name))
    if len(imports)>7 or len(set(x[0] for x in imports))!=len(imports):
        raise UnsupportedCRT("Unbounded imported-call sites")
    if len(set(name for _,_,_,name in imports))!=len(imports):
        raise UnsupportedCRT("Duplicate API call mapping")
    starts={start}|{cont for _,cont,_,_ in imports}
    lines=['#include <stdint.h>\n#include "mx_crt_vm.h"\n',
           'int lifted_crt_run(mx_crt_state *s,mx_cfg_memory *m) {\n',
           ' if(!s||!m)return MX_CRT_INVALID;\n',
           ' if(s->pending_import)return MX_CRT_PAUSED_IMPORT;\n',
           ' switch(s->rip) {\n']
    for address in sorted(starts):
        if address not in targets:
            raise UnsupportedCRT("Import continuation not instruction aligned")
        lines.append(f' case UINT64_C({image_base+address}): goto I_{address:x};\n')
    lines+=[' default:return MX_CRT_INVALID;\n }\n']
    callnum={address:i+1 for i,(address,_,_,_) in enumerate(imports)}
    labels=starts | {i.operands[0].imm for i in instructions if i.mnemonic in ('je','jmp')}
    for index,ins in enumerate(instructions):
        mnem=ins.mnemonic;ops=ins.operands
        if ins.address in labels: lines.append(f'I_{ins.address:x}:\n')
        lines.append(f' if(++s->instructions>128U){{ return MX_CRT_INVALID; }}\n s->visited |= UINT64_C({1<<index});\n')
        if mnem in ("mov","movabs"):
            if len(ops)!=2:raise UnsupportedCRT("Bad MOV operands")
            lines.append(' '+_put(ins,ops[0],_get(ins,ops[1],image_base),image_base)+'\n')
        elif mnem=="lea":
            if len(ops)!=2 or ops[0].type!=X86_OP_REG or ops[1].type!=X86_OP_MEM:
                raise UnsupportedCRT("Bad LEA operands")
            lines.append(' '+_put(ins,ops[0],_addr(ins,ops[1],image_base),image_base)+'\n')
        elif mnem in ("sub","add","xor","and"):
            if len(ops)!=2 or ops[0].size not in (4,8):
                raise UnsupportedCRT("Unmodeled integer arithmetic")
            a=_get(ins,ops[0],image_base);b=_get(ins,ops[1],image_base)
            op={"sub":"-","add":"+","xor":"^","and":"&"}[mnem]
            mask="UINT64_C(4294967295)" if ops[0].size==4 else "UINT64_MAX"
            lines.append(' {uint64_t x='+a+';uint64_t y='+b+';uint64_t z=(x'+op+'y)&'+mask+';\n')
            lines.append(' '+_put(ins,ops[0],"z",image_base)+' s->zf=(z==0); }\n')
        elif mnem=="not":
            if len(ops)!=1:raise UnsupportedCRT("Bad NOT operands")
            lines.append(' '+_put(ins,ops[0],f"(~({_get(ins,ops[0],image_base)}))",image_base)+'\n')
        elif mnem=="cmp":
            if len(ops)!=2 or ops[0].size!=ops[1].size:
                raise UnsupportedCRT("CMP widths differ")
            lines.append(f' s->zf=({_get(ins,ops[0],image_base)}=={_get(ins,ops[1],image_base)});\n')
        elif mnem=="cmove":
            if len(ops)!=2:raise UnsupportedCRT("Bad CMOVE")
            lines.append(' if(s->zf){'+_put(ins,ops[0],_get(ins,ops[1],image_base),image_base)+'}\n')
        elif mnem in ("je","jmp"):
            dest=ops[0].imm
            lines.append(f' {"if(s->zf)" if mnem=="je" else ""}goto I_{dest:x};\n')
        elif mnem=="push":
            if len(ops)!=1 or ops[0].size!=8:raise UnsupportedCRT("Bad PUSH")
            value=_get(ins,ops[0],image_base)
            lines.append(f' s->rsp-=8U; if(!mx_crt_write(s,m,s->rsp,8,{value}))return MX_CRT_MEMORY_FAULT;\n')
        elif mnem=="pop":
            if len(ops)!=1 or ops[0].size!=8:raise UnsupportedCRT("Bad POP")
            lines.append(' {uint64_t v=mx_crt_read(s,m,s->rsp,8); s->rsp+=8U;')
            lines.append(_put(ins,ops[0],"v",image_base)+'}\n')
        elif mnem=="call":
            if ins.address not in callnum:raise UnsupportedCRT("Unmatched IAT call")
            n=callnum[ins.address]
            lines.append(' if((s->rsp&15ULL)!=0)return MX_CRT_INVALID;\n')
            lines.append(f' if(!mx_crt_write(s,m,s->rsp-8U,8,UINT64_C({image_base+ins.address+ins.size})))return MX_CRT_MEMORY_FAULT;\n')
            lines.append(f' s->pending_import={n}U;s->resume_pc=UINT64_C({image_base+ins.address+ins.size});')
            lines.append(f' s->rip=UINT64_C({image_base+ins.address});return MX_CRT_PAUSED_IMPORT;\n')
        elif mnem=="ret":
            if ops:raise UnsupportedCRT("Unsupported RET immediate")
            lines.append(' s->rip=mx_crt_read(s,m,s->rsp,8);s->rsp+=8U;')
            lines.append(' return s->fault ? MX_CRT_MEMORY_FAULT : MX_CRT_RETURNED;\n')
        else:
            raise UnsupportedCRT("Unsupported original opcode "+mnem)
        lines.append(' if(s->fault)return MX_CRT_MEMORY_FAULT;\n')
    lines+=[' return MX_CRT_INVALID;\n}\n']
    lines+=['int lifted_crt_resume_import(mx_crt_state *s,const mx_import_runtime *rt) {\n',
            ' if(!s||!rt||!s->pending_import)return MX_CRT_INVALID;\n',
            ' const char *dll=0,*name=0;switch(s->pending_import){\n']
    for idx,(address,after,dll,name) in enumerate(imports,1):
        lines.append(f' case {idx}:dll="{dll}";name="{name}";break;\n')
    lines+=[' default:return MX_CRT_INVALID;\n }\n',
            ' mx_win64_call call={0}; call.rcx=s->rcx;call.rax=s->rax;call.rsp=s->rsp-8U;\n',
            ' int result=mx_dispatch_supported_win64_import(rt,dll,name,&call);\n',
            ' if(result!=1)return result==0 ? -4 : -5;\n',
            ' s->rax=call.rax;s->import_trace=s->import_trace*8U+s->pending_import;\n',
            ' s->imports++;s->pending_import=0;s->rip=s->resume_pc;return 1;\n}\n']
    metadata={"decoded_instructions":len(instructions),"blocks":cfg["block_count"],
              "direct_edges":cfg["direct_edges"],
              "imports":[{"rva":hex(a),"iat_symbol":name} for a,_,_,name in imports],
              "scope":"Restricted original CRT guest-state CFG, not entire engine"}
    return "".join(lines),metadata
