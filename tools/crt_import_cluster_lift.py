"""Restricted x64 CRT import-cluster to native C/ARM64 compiler frontend.

Supports only explicitly verified small Win64 function bodies consisting of
register/guest-memory moves, LEA, one equality branch family, balanced stack
setup/epilogue, and imports into six opt-in CRT services. Each imported call
is a *callback boundary*, never a fabricated Windows result. An unknown
mnemonic, symbol, indirect target, incomplete CFG or oversized function fails.

The source of any real commercial input and its generated native derivative
MUST remain private. This public module and its synthetic tests contain no
original game instruction bytes.
"""
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
from capstone.x86 import X86_OP_REG, X86_OP_IMM, X86_OP_MEM

class UnsupportedCluster(ValueError):
    pass

UINT64 = (1 << 64) - 1
REGS = {
    "rax": ("rax", 8), "eax": ("rax", 4),
    "rbx": ("rbx", 8), "ebx": ("rbx", 4),
    "rcx": ("rcx", 8), "ecx": ("rcx", 4),
    "rdx": ("rdx", 8), "edx": ("rdx", 4),
    "r8": ("r8", 8), "r8d": ("r8", 4),
    "rdi": ("rdi", 8), "edi": ("rdi", 4),
    "rsi": ("rsi", 8), "esi": ("rsi", 4),
    "r11": ("r11", 8), "r11d": ("r11", 4),
    "rsp": ("rsp", 8),
}
SERVICES = {
    "_encode_pointer": "MX_CRT_SERVICE_ENCODE_POINTER",
    "_decode_pointer": "MX_CRT_SERVICE_DECODE_POINTER",
    "_onexit": "MX_CRT_SERVICE_ONEXIT",
    "__dllonexit": "MX_CRT_SERVICE_DLLONEXIT",
    "_lock": "MX_CRT_SERVICE_LOCK",
    "_unlock": "MX_CRT_SERVICE_UNLOCK",
}

def _reg(ins, operand):
    if operand.type != X86_OP_REG:
        raise UnsupportedCluster("Expected integer register")
    name = ins.reg_name(operand.reg)
    if name not in REGS or operand.size != REGS[name][1]:
        raise UnsupportedCluster("Unmodeled register width: " + name)
    return REGS[name]

def _address(ins, operand, image_base):
    if operand.type != X86_OP_MEM or operand.mem.segment or operand.mem.index:
        raise UnsupportedCluster("Guest memory indexing/segment not supported")
    reg = ins.reg_name(operand.mem.base)
    displacement = operand.mem.disp
    if reg == "rip":
        va = image_base + ins.address + ins.size + displacement
        if not image_base <= va < image_base + 0x10000000:
            raise UnsupportedCluster("RIP-relative guest address outside image")
        return f"UINT64_C({va})"
    if reg == "rsp":
        return f"(s->rsp + UINT64_C({displacement & UINT64}))"
    raise UnsupportedCluster("Only RIP-relative image or RSP stack addresses")

def _get(ins, operand, image_base):
    if operand.type == X86_OP_REG:
        field, size = _reg(ins, operand)
        return f"((uint32_t)s->{field})" if size == 4 else f"s->{field}"
    if operand.type == X86_OP_IMM:
        return f"UINT64_C({operand.imm & UINT64})"
    if operand.type == X86_OP_MEM and operand.size in (4, 8):
        return f"mx_crt_cluster_read(s,m,{_address(ins,operand,image_base)},{operand.size})"
    raise UnsupportedCluster("Unsupported source operand")

def _put(ins, operand, value, image_base):
    if operand.type == X86_OP_REG:
        field, size = _reg(ins, operand)
        rhs = f"((uint32_t)({value}))" if size == 4 else f"({value})"
        return f"s->{field} = {rhs};"
    if operand.type == X86_OP_MEM and operand.size in (4, 8):
        return (f"if (!mx_crt_cluster_write(s,m,"
                f"{_address(ins,operand,image_base)},{operand.size},({value})))"
                f" return MX_CRT_CLUSTER_MEMORY_FAULT;")
    raise UnsupportedCluster("Unsupported destination operand")

def _import(ins, iat, thunks, decoder):
    if len(ins.operands) != 1:
        raise UnsupportedCluster("Imported CALL requires one target")
    op=ins.operands[0]
    if op.type == X86_OP_MEM and ins.reg_name(op.mem.base) == "rip" and not op.mem.index:
        slot=ins.address+ins.size+op.mem.disp
        kind="rip_indirect"
    elif op.type == X86_OP_IMM:
        thunk_rva=op.imm
        if thunk_rva not in thunks:
            raise UnsupportedCluster("Direct call target lacks verified import thunk")
        thunk_blob=thunks[thunk_rva]
        if not isinstance(thunk_blob,bytes) or len(thunk_blob)!=6:
            raise UnsupportedCluster("Indirect import thunk must be six raw bytes")
        thunk=list(decoder.disasm(thunk_blob,thunk_rva))
        if (len(thunk)!=1 or thunk[0].size!=6 or
            thunk[0].mnemonic!="jmp" or len(thunk[0].operands)!=1):
            raise UnsupportedCluster("Malformed imported JMP thunk")
        target=thunk[0].operands[0]
        if (target.type!=X86_OP_MEM or
            thunk[0].reg_name(target.mem.base)!="rip" or
            target.mem.index or target.mem.segment):
            raise UnsupportedCluster("Unverified thunk destination form")
        slot=thunk_rva+thunk[0].size+target.mem.disp
        kind="direct_via_jmp_thunk"
    else:
        raise UnsupportedCluster("Computed call target cannot be resolved safely")
    if slot not in iat:
        raise UnsupportedCluster("Import IAT slot not identified")
    dll,name=iat[slot]
    if not isinstance(dll,str) or not isinstance(name,str):
        raise UnsupportedCluster("Malformed DLL symbol")
    if dll.lower()!="msvcr90.dll" or name.lower() not in SERVICES:
        raise UnsupportedCluster("Imported API has no CRT service contract")
    return slot,name.lower(),kind

def lift_crt_import_cluster(code:bytes,start:int,iat:dict,thunks:dict,
                            image_base:int=0x140000000):
    """Emit standalone freestanding C for a bounded, verified x64 function.

    Returns generated C source and structural metadata. Import callbacks are
    injected at execution time. Caller keeps all real generated C private.
    Both the original x64 reference and native AArch64 must still run and
    be compared; compilation alone is not a verified translation.
    """
    if (not isinstance(code,bytes) or not 8<=len(code)<=768 or
        not isinstance(start,int) or not 0<=start<0x10000000 or
        not isinstance(iat,dict) or not isinstance(thunks,dict) or
        len(iat)>512 or len(thunks)>32):
        raise UnsupportedCluster("Invalid or oversized CRT cluster input")
    decoder=Cs(CS_ARCH_X86,CS_MODE_64)
    decoder.detail=True
    insns=list(decoder.disasm(code,start))
    if (not insns or sum(i.size for i in insns)!=len(code) or
        not 1<=len(insns)<=63 or
        sum(i.mnemonic=="ret" for i in insns)!=1 or
        insns[-1].mnemonic!="ret"):
        raise UnsupportedCluster("Incomplete bounded x64 function or terminal RET")
    addrs={i.address for i in insns}
    edges=[]
    imports=[]
    for ins in insns:
        ops=ins.operands
        mn=ins.mnemonic
        if mn in ("je","jne","jmp"):
            if (len(ops)!=1 or ops[0].type!=X86_OP_IMM or
                ops[0].imm not in addrs):
                raise UnsupportedCluster("Branch leaves bounded original CFG")
            edges.append((ins.address,ops[0].imm))
        elif mn=="call":
            slot,name,kind=_import(ins,iat,thunks,decoder)
            imports.append({"rva":hex(ins.address),"iat_slot":hex(slot),
                            "symbol":name,"kind":kind,
                            "service":SERVICES[name]})
        elif mn not in ("mov","lea","cmp","push","pop","add","sub","nop","ret"):
            raise UnsupportedCluster("Unsupported x64 instruction: "+mn)
        if mn in ("mov","lea","cmp","add","sub"):
            if len(ops)!=2:
                raise UnsupportedCluster("Unexpected two-operand shape: "+mn)
        if mn in ("push","pop") and (len(ops)!=1 or ops[0].type!=X86_OP_REG or
                                   ops[0].size!=8):
            raise UnsupportedCluster("Stack operation requires 64-bit register")
        if mn in ("add","sub") and not (
            ops[0].type==X86_OP_REG and ins.reg_name(ops[0].reg)=="rsp" and
            ops[1].type==X86_OP_IMM and 0<ops[1].imm<=256
        ):
            raise UnsupportedCluster("Only constant Win64 RSP adjustment supported")
    if not imports or len(imports)>16:
        raise UnsupportedCluster("One to sixteen explicit CRT import callsites required")
    lines=[
        '#include <stdint.h>\n#include "mx_crt_cluster_guest.h"\n',
        'int lifted_crt_import_cluster(mx_crt_cluster_state *s,',
        ' mx_cfg_memory *m,mx_crt_cluster_import_fn callback,void *ctx) {\n',
        f' if(!s||!m||!callback||s->fault||s->rip!=UINT64_C({image_base+start}))',
        ' return MX_CRT_CLUSTER_INVALID;\n',
        f' goto I_{start:x};\n'
    ]
    labels={start}|{target for _,target in edges}
    for index, ins in enumerate(insns):
        mn=ins.mnemonic;ops=ins.operands
        if ins.address in labels:
            lines.append(f'I_{ins.address:x}:\n')
        lines.append(' if(++s->instructions>192U)return MX_CRT_CLUSTER_INVALID;\n')
        lines.append(f' s->visited|=UINT64_C({1<<index});\n')
        if mn=="mov":
            if (ops[0].size!=ops[1].size and ops[1].type!=X86_OP_IMM):
                raise UnsupportedCluster("MOV operand width mismatch")
            lines.append(' '+_put(ins,ops[0],_get(ins,ops[1],image_base),image_base)+'\n')
        elif mn=="lea":
            if (ops[0].type!=X86_OP_REG or ops[1].type!=X86_OP_MEM or
                ops[0].size!=8):
                raise UnsupportedCluster("LEA requires 64-bit register destination")
            lines.append(' '+_put(ins,ops[0],_address(ins,ops[1],image_base),image_base)+'\n')
        elif mn=="cmp":
            if (ops[0].type!=X86_OP_REG or ops[0].size not in (4,8)):
                raise UnsupportedCluster("CMP limited to register operands")
            if ops[1].type!=X86_OP_IMM and ops[1].size!=ops[0].size:
                raise UnsupportedCluster("CMP operand width mismatch")
            bits=ops[0].size*8
            mask=f' & UINT64_C({(1<<bits)-1})' if bits==32 else ''
            lines.append(f' s->zf=((({_get(ins,ops[0],image_base)}){mask})'
                         f'==(({_get(ins,ops[1],image_base)}){mask}));\n')
        elif mn in ("je","jne","jmp"):
            target=ops[0].imm
            condition=('if(s->zf)' if mn=="je" else
                       'if(!s->zf)' if mn=="jne" else '')
            lines.append(f' {condition}goto I_{target:x};\n')
        elif mn=="push":
            if ins.reg_name(ops[0].reg)=="rsp":
                raise UnsupportedCluster("PUSH RSP needs pre-decrement snapshot")
            lines.append(' if(s->rsp<8U)return MX_CRT_CLUSTER_MEMORY_FAULT;\\n')
            lines.append(f' s->rsp-=8U; if(!mx_crt_cluster_write(s,m,s->rsp,8,{_get(ins,ops[0],image_base)}))return MX_CRT_CLUSTER_MEMORY_FAULT;\\n')
        elif mn=="pop":
            field,size=_reg(ins,ops[0])
            lines.append(' {uint64_t v=mx_crt_cluster_read(s,m,s->rsp,8);\n')
            lines.append(' if(s->fault)return MX_CRT_CLUSTER_MEMORY_FAULT;\n')
            lines.append(f' s->{field}=v;s->rsp+=8U;}}\n')
        elif mn in ("add","sub"):
            immediate=ops[1].imm
            op="+" if mn=="add" else "-"
            if mn=="sub":
                lines.append(f' if(s->rsp<UINT64_C({immediate}))return MX_CRT_CLUSTER_MEMORY_FAULT;\\n')
            else:
                lines.append(f' if(s->rsp>UINT64_MAX-UINT64_C({immediate}))return MX_CRT_CLUSTER_MEMORY_FAULT;\\n')
            lines.append(f' s->rsp=s->rsp{op}UINT64_C({immediate});')
            lines.append(' s->zf=(s->rsp==0);\\n')
        elif mn=="nop":
            pass
        elif mn=="call":
            entry=imports.pop(0)
            lines.extend([
                ' if(s->rsp<8U||(s->rsp&15U)!=0U)return MX_CRT_CLUSTER_INVALID;\n',
                f' {{uint64_t pc=UINT64_C({image_base+ins.address+ins.size});\n',
                ' if(!mx_crt_cluster_write(s,m,s->rsp-8U,8,pc))',
                ' return MX_CRT_CLUSTER_MEMORY_FAULT;\n',
                f' if(!callback(ctx,{entry["service"]},s,m,s->rsp-8U))',
                ' return MX_CRT_CLUSTER_IMPORT_UNSUPPORTED;\n',
                ' s->imports++;}\n',
            ])
        elif mn=="ret":
            lines.extend([
                ' s->rip=mx_crt_cluster_read(s,m,s->rsp,8);\n',
                ' if(s->fault)return MX_CRT_CLUSTER_MEMORY_FAULT;\n',
                ' s->rsp+=8U;return MX_CRT_CLUSTER_RETURNED;\n'
            ])
        lines.append(' if(s->fault)return MX_CRT_CLUSTER_MEMORY_FAULT;\n')
    lines.append(' return MX_CRT_CLUSTER_INVALID;\n}\n')
    metadata={
        "bounded_function_rva":hex(start),
        "decoded_instructions":len(insns),
        "original_code_bytes":len(code),
        "verified_internal_branches":len(edges),
        "import_calls":sum(x.mnemonic=="call" for x in insns),
        "unique_import_services":sorted({
            _import(x,iat,thunks,decoder)[1] for x in insns
            if x.mnemonic=="call"}),
        "native_code_generated":True,
        "real_imports_executed":False,
        "original_x64_vs_arm64_verified":False,
        "scope":"One bounded Win64 CRT dependency cluster, not engine startup",
    }
    return "".join(lines),metadata

