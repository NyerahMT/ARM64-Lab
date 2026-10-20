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
    "rax": ("rax",8), "eax": ("rax",4), "ax": ("rax",2), "al": ("rax",1),
    "rbx": ("rbx",8), "ebx": ("rbx",4), "bx": ("rbx",2), "bl": ("rbx",1),
    "rcx": ("rcx",8), "ecx": ("rcx",4), "cx": ("rcx",2), "cl": ("rcx",1),
    "rdx": ("rdx",8), "edx": ("rdx",4), "dx": ("rdx",2), "dl": ("rdx",1),
    "r8": ("r8",8), "r8d": ("r8",4), "r8w": ("r8",2), "r8b": ("r8",1),
    "r9": ("r9",8), "r9d": ("r9",4), "r9w": ("r9",2), "r9b": ("r9",1),
    "rdi": ("rdi",8), "edi": ("rdi",4), "di": ("rdi",2), "dil": ("rdi",1),
    "rsi": ("rsi",8), "esi": ("rsi",4), "si": ("rsi",2), "sil": ("rsi",1),
    "r11": ("r11",8), "r11d": ("r11",4), "r11w": ("r11",2), "r11b": ("r11",1),
    "rsp": ("rsp",8),
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
    if reg in {"rax","rbx","rcx","rdx","r8","r9","rdi","rsi","r11"}:
        return f"(s->{reg} + UINT64_C({displacement & UINT64}))"
    raise UnsupportedCluster("Unmodeled guest memory base register")

def _get(ins, operand, image_base):
    if operand.type == X86_OP_REG:
        field,size = _reg(ins,operand)
        if size == 8:
            return f"s->{field}"
        return f"((uint{8*size}_t)s->{field})"
    if operand.type == X86_OP_IMM:
        return f"UINT64_C({operand.imm & UINT64})"
    if operand.type == X86_OP_MEM and operand.size in (1,2,4,8):
        return f"mx_crt_cluster_read(s,m,{_address(ins,operand,image_base)},{operand.size})"
    raise UnsupportedCluster("Unsupported source operand")

def _put(ins, operand, value, image_base):
    if operand.type == X86_OP_REG:
        field,size = _reg(ins,operand)
        if size == 8:
            return f"s->{field}=({value});"
        if size == 4:
            return f"s->{field}=((uint32_t)({value}));"
        mask=(1<<(size*8))-1
        return (f"s->{field}=(s->{field}&~UINT64_C({mask}))|"
                f"(((uint64_t)({value}))&UINT64_C({mask}));")
    if operand.type == X86_OP_MEM and operand.size in (1,2,4,8):
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
        if mn in ("je","jne","jns","js","jbe","jb","ja","jmp"):
            if (len(ops)!=1 or ops[0].type!=X86_OP_IMM or
                ops[0].imm not in addrs):
                raise UnsupportedCluster("Branch leaves bounded original CFG")
            edges.append((ins.address,ops[0].imm))
        elif mn=="call":
            slot,name,kind=_import(ins,iat,thunks,decoder)
            imports.append({"rva":hex(ins.address),"iat_slot":hex(slot),
                            "symbol":name,"kind":kind,
                            "service":SERVICES[name]})
        elif mn not in ("mov","movzx","movsxd","lea","cmp","test","setne",
                         "xor","or","push","pop","add","sub","nop","ret"):
            raise UnsupportedCluster("Unsupported x64 instruction: "+mn)
        if mn in ("mov","movzx","movsxd","lea","cmp","test","xor","or","add","sub"):
            if len(ops)!=2:
                raise UnsupportedCluster("Unexpected two-operand shape: "+mn)
        if mn=="setne" and len(ops)!=1:
            raise UnsupportedCluster("SETNE requires one byte destination")
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
        elif mn in ("movzx","movsxd"):
            dst,src=ops
            if dst.type!=X86_OP_REG:
                raise UnsupportedCluster("Integer extension needs register destination")
            if mn=="movzx":
                if dst.size not in (4,8) or src.size not in (1,2):
                    raise UnsupportedCluster("MOVZX supports 8/16 to 32/64 bits")
                value=_get(ins,src,image_base)
            else:
                if dst.size!=8 or src.size!=4:
                    raise UnsupportedCluster("MOVSXD supports sign extension 32 to 64")
                value=f"((uint64_t)(int64_t)(int32_t)({_get(ins,src,image_base)}))"
            lines.append(' '+_put(ins,dst,value,image_base)+'\n')
        elif mn=="lea":
            if (ops[0].type!=X86_OP_REG or ops[1].type!=X86_OP_MEM or
                ops[0].size!=8):
                raise UnsupportedCluster("LEA requires 64-bit register destination")
            lines.append(' '+_put(ins,ops[0],_address(ins,ops[1],image_base),image_base)+'\n')
        elif mn in ("cmp","test"):
            if (ops[0].type not in (X86_OP_REG,X86_OP_MEM) or
                    ops[0].size not in (1,2,4,8)):
                raise UnsupportedCluster("Flag operation requires 8/16/32/64-bit operand")
            if ops[1].type!=X86_OP_IMM and ops[1].size!=ops[0].size:
                raise UnsupportedCluster("Flag operand widths differ")
            bits=8*ops[0].size
            mask=(1<<bits)-1
            left=_get(ins,ops[0],image_base)
            right=_get(ins,ops[1],image_base)
            lines.append(f' {{uint64_t lhs=({left})&UINT64_C({mask});\n')
            lines.append(f' uint64_t rhs=({right})&UINT64_C({mask});\n')
            operation='lhs-rhs' if mn=="cmp" else 'lhs&rhs'
            lines.append(f' uint64_t flags_result=({operation})&UINT64_C({mask});\n')
            lines.append(' s->zf=(flags_result==0U);\n')
            lines.append(f' s->sf=(flags_result&UINT64_C({1<<(bits-1)}))!=0U;\n')
            lines.append(' s->cf=(lhs<rhs);\n' if mn=="cmp" else ' s->cf=0U;\n')
            lines.append(' }\n')
        elif mn=="setne":
            if ops[0].size!=1:
                raise UnsupportedCluster("SETNE only writes a byte")
            lines.append(' '+_put(ins,ops[0],'(s->zf==0U)',image_base)+'\n')
        elif mn in ("xor","or"):
            lhs,rhs=ops
            if lhs.type!=X86_OP_REG or lhs.size not in (1,2,4,8):
                raise UnsupportedCluster("Bitwise destination must be a register")
            if rhs.type!=X86_OP_IMM and rhs.size!=lhs.size:
                raise UnsupportedCluster("Bitwise operands have different widths")
            bits=lhs.size*8
            mask=(1<<bits)-1
            operator='^' if mn=="xor" else '|'
            lines.append(f' {{uint64_t value=(({_get(ins,lhs,image_base)}){operator}({_get(ins,rhs,image_base)}))&UINT64_C({mask});\n')
            lines.append(' '+_put(ins,lhs,'value',image_base)+'\n')
            lines.append(' s->zf=(value==0U);\n')
            lines.append(f' s->sf=(value&UINT64_C({1<<(bits-1)}))!=0U;\n')
            lines.append(' s->cf=0U;}\n')
        elif mn in ("je","jne","jns","js","jbe","jb","ja","jmp"):
            target=ops[0].imm
            condition={
                "je":"if(s->zf)","jne":"if(!s->zf)",
                "jns":"if(!s->sf)","js":"if(s->sf)",
                "jbe":"if(s->cf||s->zf)","jb":"if(s->cf)",
                "ja":"if(!s->cf&&!s->zf)","jmp":""
            }[mn]
            lines.append(f' {condition}goto I_{target:x};\n')
        elif mn=="push":
            if ins.reg_name(ops[0].reg)=="rsp":
                raise UnsupportedCluster("PUSH RSP needs pre-decrement snapshot")
            lines.append(' if(s->rsp<8U)return MX_CRT_CLUSTER_MEMORY_FAULT;\n')
            lines.append(f' s->rsp-=8U; if(!mx_crt_cluster_write(s,m,s->rsp,8,{_get(ins,ops[0],image_base)}))return MX_CRT_CLUSTER_MEMORY_FAULT;\n')
        elif mn=="pop":
            field,size=_reg(ins,ops[0])
            lines.append(' {uint64_t v=mx_crt_cluster_read(s,m,s->rsp,8);\n')
            lines.append(' if(s->fault)return MX_CRT_CLUSTER_MEMORY_FAULT;\n')
            lines.append(f' s->{field}=v;s->rsp+=8U;}}\n')
        elif mn in ("add","sub"):
            immediate=ops[1].imm
            op="+" if mn=="add" else "-"
            if mn=="sub":
                lines.append(f' if(s->rsp<UINT64_C({immediate}))return MX_CRT_CLUSTER_MEMORY_FAULT;\n')
            else:
                lines.append(f' if(s->rsp>UINT64_MAX-UINT64_C({immediate}))return MX_CRT_CLUSTER_MEMORY_FAULT;\n')
            lines.append(f' s->rsp=s->rsp{op}UINT64_C({immediate});')
            lines.append(' s->zf=(s->rsp==0);s->sf=((s->rsp>>63U)&1U);s->cf=0U;\n')
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

