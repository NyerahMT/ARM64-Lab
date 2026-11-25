"""Legacy SSE data movement and bitwise XOR for the bounded CFG translator.

All sixteen XMM registers are represented as two little-endian 64-bit lanes.
No floating arithmetic, exception flags, AVX/VEX semantics, or guest calls.
All memory operations use checked guest ranges, never host pointers.
"""
from capstone.x86 import X86_OP_MEM,X86_OP_REG
import mxbikes_cfg_extended_regs as regs
import mxbikes_native_prefix_wave as prefix

PACKED={"movaps","movups","movapd","movupd","movdqa","movdqu"}
ALIGNED={"movaps","movapd","movdqa"}
SCALAR={"movss":4,"movsd":8}
XOR={"xorps","xorpd","pxor"}
BASES=regs.GP|{"rsp","rbp"}
HEAP_BASES=BASES-{"rsp","rbp"}

def xmm(ins,op):
    if op.type!=X86_OP_REG or op.size!=16:
        return None
    n=ins.reg_name(op.reg)
    if n.startswith("xmm") and n[3:].isdigit() and int(n[3:])<16:
        return int(n[3:])
    return None

def memory(ins,op):
    if op.type!=X86_OP_MEM or op.size not in (4,8,16):
        return None
    m=op.mem
    if m.index or m.segment or 0x67 in ins.prefix:
        return None
    base=ins.reg_name(m.base)
    if base=="rip":
        address=ins.address+ins.size+m.disp
        if not 0<=address<=prefix.MASK-op.size+1:return None
        return base,address,op.size
    if base in BASES and abs(m.disp)<= (16384 if base in ("rsp","rbp") else 1024):
        return base,m.disp,op.size
    return None

def references(ins):
    if ins.mnemonic not in PACKED|set(SCALAR) or len(ins.operands)!=2:
        return []
    a,b=ins.operands
    m=memory(ins,b)
    return [(m[1],m[2])] if xmm(ins,a) is not None and m and m[0]=="rip" else []

def memory_bases(ins):
    if ins.mnemonic not in PACKED|set(SCALAR):return set()
    return {m[0] for op in ins.operands if (m:=memory(ins,op)) and m[0] in HEAP_BASES}

def address(m):
    base,disp,width=m
    if base=="rip":return f"UINT64_C({disp})"
    return f"(s.{base}+UINT64_C({disp&prefix.MASK}))"

def emit(ins):
    name=ins.mnemonic
    if name not in PACKED|set(SCALAR)|XOR or len(ins.operands)!=2:
        return None
    dst,src=ins.operands
    d,s=xmm(ins,dst),xmm(ins,src)
    if name in XOR:
        if d is None or s is None:return None
        return f"s.xmm[{d}][0]^=s.xmm[{s}][0];s.xmm[{d}][1]^=s.xmm[{s}][1];"
    width=16 if name in PACKED else SCALAR[name]
    mask=(1<<(8*width))-1 if width<16 else None
    if d is not None and s is not None:
        if width==16:
            return f"s.xmm[{d}][0]=s.xmm[{s}][0];s.xmm[{d}][1]=s.xmm[{s}][1];"
        return f"s.xmm[{d}][0]=(s.xmm[{d}][0]&~UINT64_C({mask}))|(s.xmm[{s}][0]&UINT64_C({mask}));"
    read,write=memory(ins,src),memory(ins,dst)
    if d is not None and read and read[2]==width:
        addr=address(read)
        align=f"if((a&15U)!=0U)return 11;" if name in ALIGNED else ""
        return (f"{{uint64_t a={addr};uint64_t v[2]={{0U,0U}};{align}"
                f"if(!mx_cfg_vector_transfer(&mem,a,v,{width}U,0))return 11;"
                f"s.xmm[{d}][0]=v[0];s.xmm[{d}][1]=v[1];}}")
    if s is not None and write and write[0]!="rip" and write[2]==width:
        addr=address(write)
        align=f"if((a&15U)!=0U)return 11;" if name in ALIGNED else ""
        return (f"{{uint64_t a={addr};{align}"
                f"if(!mx_cfg_vector_transfer(&mem,a,s.xmm[{s}],{width}U,1))return 11;}}")
    return None
