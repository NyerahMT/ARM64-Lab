#!/usr/bin/env python3
"""Recognize one complete bounded register/LEA/zero setup instruction before CALL.

A registered prefix is a bounded native instruction slice, NOT a translated
caller or an assertion that the surrounding original CFG has been executed.
"""
from __future__ import annotations
from capstone.x86 import X86_OP_REG, X86_OP_MEM, X86_OP_IMM

REG64={"rax":"rax","rbx":"rbx","rcx":"rcx","rdx":"rdx",
       "r8":"r8","r9":"r9","rdi":"rdi","rsi":"rsi","r11":"r11"}
REG32={"eax":"rax","ebx":"rbx","ecx":"rcx","edx":"rdx",
       "r8d":"r8","r9d":"r9","edi":"rdi","esi":"rsi","r11d":"r11"}


def decode_mov_prefix(ins):
    """Capstone-confirmed exact x86-64 ModRM register-to-register MOV only."""
    data=bytes(ins.bytes)
    if ins.mnemonic!="mov" or len(ins.operands)!=2:
        return None
    ops=ins.operands
    if any(op.type!=X86_OP_REG for op in ops):
        return None
    width=ops[0].size
    if width!=ops[1].size or width not in (4,8):
        return None
    regs=REG64 if width==8 else REG32
    dest=regs.get(ins.reg_name(ops[0].reg))
    src=regs.get(ins.reg_name(ops[1].reg))
    if dest is None or src is None:
        return None
    at=0
    if len(data)==3 and 0x40<=data[0]<=0x4f:
        at=1
        if bool(data[0]&8)!=(width==8):
            return None
    elif len(data)!=2 or width!=4:
        return None
    if data[at] not in (0x89,0x8b) or data[at+1]<0xc0:
        return None
    return {"kind":"register_mov", "src":src, "dst":dest,
            "bits":width*8, "bytes":len(data), "address":ins.address}



SOURCE_REGS={**REG64,"rsp":"rsp"}


def decode_lea_prefix(ins):
    """LEA computes a guest effective address; it never reads guest memory."""
    data=bytes(ins.bytes)
    if (ins.mnemonic!="lea" or len(ins.operands)!=2 or
        ins.operands[0].type!=X86_OP_REG or
        ins.operands[1].type!=X86_OP_MEM):
        return None
    width=ins.operands[0].size
    if width!=8 or not 3<=len(data)<=8:
        return None
    # Exclude 32-bit/address-size overrides, RIP-relative references, indexes
    # and implicit segment addressing; no guest memory access is performed.
    if not 0x48<=data[0]<=0x4f or data[1]!=0x8d:
        return None
    mem=ins.operands[1].mem
    if mem.index or mem.segment or mem.scale not in (0,1):
        return None
    dst=REG64.get(ins.reg_name(ins.operands[0].reg))
    src=SOURCE_REGS.get(ins.reg_name(mem.base))
    disp=int(mem.disp)
    if dst is None or src is None or not -(1<<31)<=disp<(1<<31):
        return None
    return {"kind":"effective_address","src":src,"dst":dst,"bits":64,
            "disp":disp,"address":ins.address,"bytes":len(data)}


def decode_zero_prefix(ins):
    data=bytes(ins.bytes)
    if ins.mnemonic!="xor" or len(ins.operands)!=2:
        return None
    left,right=ins.operands
    if left.type!=X86_OP_REG or right.type!=X86_OP_REG or left.reg!=right.reg:
        return None
    if left.size not in (4,8):
        return None
    at=0
    if len(data)==3 and 0x40<=data[0]<=0x4f:
        at=1
        if bool(data[0]&8)!=(left.size==8):
            return None
    elif len(data)!=2 or left.size!=4:
        return None
    if data[at] not in (0x31,0x33) or data[at+1]<0xc0:
        return None
    regs=REG64 if left.size==8 else REG32
    dst=regs.get(ins.reg_name(left.reg))
    if dst is None:
        return None
    return {"kind":"zero_register","dst":dst,"bits":left.size*8,
            "address":ins.address,"bytes":len(data)}


def decode_imm_prefix(ins):
    data=bytes(ins.bytes)
    if ins.mnemonic not in ("mov","movabs") or len(ins.operands)!=2:
        return None
    dst,src=ins.operands
    if dst.type!=X86_OP_REG or src.type!=X86_OP_IMM or dst.size not in (4,8):
        return None
    at=0
    if len(data)==10 and 0x48<=data[0]<=0x4f and data[0]&8:
        at=1
    elif len(data)!=5 or dst.size!=4:
        return None
    if not 0xb8<=data[at]<=0xbf:
        return None
    regs=REG64 if dst.size==8 else REG32
    destination=regs.get(ins.reg_name(dst.reg))
    if destination is None:
        return None
    literal=int(src.imm)&((1<<(dst.size*8))-1)
    return {"kind":"immediate_register","dst":destination,"bits":dst.size*8,
            "value":literal,"address":ins.address,"bytes":len(data)}



# Only stack argument/shadow-space reads that fit our initialized bounded test
# window are allowed. No arbitrary host memory, pointer dereference, or writes.
MAX_STACK_READ_END=128


def decode_stack_load_prefix(ins):
    data=bytes(ins.bytes)
    if ins.mnemonic!="mov" or len(ins.operands)!=2:
        return None
    dst,src=ins.operands
    if (dst.type!=X86_OP_REG or src.type!=X86_OP_MEM or
        dst.size not in (4,8) or src.size!=dst.size):
        return None
    mem=src.mem
    if (ins.reg_name(mem.base)!="rsp" or mem.index or mem.segment or
        mem.scale not in (0,1)):
        return None
    offset=int(mem.disp)
    if offset<0 or offset+dst.size>MAX_STACK_READ_END:
        return None
    at=0
    if len(data)>=3 and 0x40<=data[0]<=0x4f:
        at=1
        if bool(data[0]&8)!=(dst.size==8):
            return None
    elif dst.size!=4:
        return None
    if len(data)>9 or len(data)<at+3 or data[at]!=0x8b:
        return None
    dst_name=(REG64 if dst.size==8 else REG32).get(ins.reg_name(dst.reg))
    if dst_name is None:
        return None
    return {"kind":"stack_argument_load","dst":dst_name,"bits":dst.size*8,
            "offset":offset,"address":ins.address,"bytes":len(data)}



GUEST_HEAP_REGS=frozenset(REG64)
MAX_GUEST_DISPLACEMENT=128


def decode_guest_heap_load_prefix(ins):
    """One bounded guest-pointer read, not arbitrary production pointer access."""
    data=bytes(ins.bytes)
    if ins.mnemonic!="mov" or len(ins.operands)!=2:
        return None
    dst,src=ins.operands
    if (dst.type!=X86_OP_REG or src.type!=X86_OP_MEM or
        dst.size not in (4,8) or src.size!=dst.size):
        return None
    mem=src.mem
    base=ins.reg_name(mem.base)
    if (base not in GUEST_HEAP_REGS or mem.index or mem.segment or
        mem.scale not in (0,1) or
        not -MAX_GUEST_DISPLACEMENT<=int(mem.disp)<=MAX_GUEST_DISPLACEMENT):
        return None
    at=0
    if len(data)>=3 and 0x40<=data[0]<=0x4f:
        at=1
        if bool(data[0]&8)!=(dst.size==8):
            return None
    elif dst.size!=4:
        return None
    if len(data)<at+2 or len(data)>9 or data[at]!=0x8b:
        return None
    destination=(REG64 if dst.size==8 else REG32).get(ins.reg_name(dst.reg))
    if destination is None:
        return None
    return {"kind":"guest_heap_load","src":base,"dst":destination,
            "bits":dst.size*8,"disp":int(mem.disp),
            "address":ins.address,"bytes":len(data)}



def decode_guest_indexed_load_prefix(ins):
    """A bounded x64 MOV reg,[base+index*scale+disp] using seeded guest pages.

    Require an exact ModRM/SIB encoding and permitted guest registers. Indexed
    source addresses are guest virtual addresses, never native host pointers.
    """
    data=bytes(ins.bytes)
    if (ins.mnemonic!="mov" or len(ins.operands)!=2 or
        ins.operands[0].type!=X86_OP_REG or
        ins.operands[1].type!=X86_OP_MEM):
        return None
    dst,src=ins.operands
    if dst.size not in (4,8) or src.size!=dst.size:
        return None
    mem=src.mem
    base=ins.reg_name(mem.base) if mem.base else ""
    index=ins.reg_name(mem.index) if mem.index else ""
    if (base not in GUEST_HEAP_REGS or index not in GUEST_HEAP_REGS or
        base==index or mem.segment or mem.scale not in (1,2,4,8) or
        not -MAX_GUEST_DISPLACEMENT<=int(mem.disp)<=MAX_GUEST_DISPLACEMENT):
        return None
    at=0
    if len(data)>=4 and 0x40<=data[0]<=0x4f:
        at=1
        if bool(data[0]&8)!=(dst.size==8):
            return None
    elif dst.size!=4:
        return None
    if len(data)<at+3 or data[at]!=0x8b:
        return None
    modrm=data[at+1]
    mode=modrm>>6
    if mode==3 or (modrm&7)!=4:
        return None
    sib=data[at+2]
    if (1<<(sib>>6))!=mem.scale:
        return None
    # A SIB base=5,mod=0 encodes a no-base disp32 addressing form.
    if mode==0 and (sib&7)==5:
        return None
    encoded_disp_size={0:0,1:1,2:4}[mode]
    if len(data)!=at+3+encoded_disp_size:
        return None
    if encoded_disp_size:
        actual_disp=int.from_bytes(data[-encoded_disp_size:],"little",signed=True)
    else:
        actual_disp=0
    if actual_disp!=int(mem.disp):
        return None
    destination=(REG64 if dst.size==8 else REG32).get(ins.reg_name(dst.reg))
    if destination is None:
        return None
    return {"kind":"guest_heap_indexed_load","src":base,"index":index,
            "scale":int(mem.scale),"dst":destination,"bits":dst.size*8,
            "disp":int(mem.disp),"address":ins.address,"bytes":len(data)}




def decode_guest_heap_store_prefix(ins):
    """Exact register-to-guest-pointer MOV store, bounded to a seeded page."""
    data=bytes(ins.bytes)
    if (ins.mnemonic!="mov" or len(ins.operands)!=2 or
        ins.operands[0].type!=X86_OP_MEM or
        ins.operands[1].type!=X86_OP_REG):
        return None
    dest,src=ins.operands
    if dest.size not in (4,8) or dest.size!=src.size:
        return None
    mem=dest.mem
    base=ins.reg_name(mem.base) if mem.base else ""
    if (base not in GUEST_HEAP_REGS or mem.index or mem.segment or
        mem.scale not in (0,1) or
        not -MAX_GUEST_DISPLACEMENT<=int(mem.disp)<=MAX_GUEST_DISPLACEMENT):
        return None
    at=0
    if len(data)>=3 and 0x40<=data[0]<=0x4f:
        at=1
        if bool(data[0]&8)!=(dest.size==8):
            return None
    elif dest.size!=4:
        return None
    if len(data)<at+2 or data[at]!=0x89:
        return None
    modrm=data[at+1]
    mode=modrm>>6
    if mode==3 or (modrm&7)==4:
        return None
    disp_size={0:0,1:1,2:4}[mode]
    if len(data)!=at+2+disp_size:
        return None
    disp=int.from_bytes(data[-disp_size:],"little",signed=True) if disp_size else 0
    if disp!=int(mem.disp):
        return None
    value_reg=(REG64 if src.size==8 else REG32).get(ins.reg_name(src.reg))
    if value_reg is None:
        return None
    return {"kind":"guest_heap_store","src":base,"value_reg":value_reg,
            "bits":dest.size*8,"disp":int(mem.disp),
            "address":ins.address,"bytes":len(data)}




# This is a *fixture* relationship, not a reconstruction of the parent
# function's real frame-pointer value or its Win64 prologue. The reference
# emulator seeds RBP = entry RSP + 64 and initializes RSP..RSP+1023.
FRAME_ANCHOR_FROM_RSP=64
MAX_FRAME_READ_END=1024

def decode_frame_pointer_load_prefix(ins):
    """Exact 32/64-bit MOV reg,[rbp+disp], confined to seeded guest stack."""
    data=bytes(ins.bytes)
    if ins.mnemonic!="mov" or len(ins.operands)!=2:
        return None
    dst,src=ins.operands
    if (dst.type!=X86_OP_REG or src.type!=X86_OP_MEM or
        dst.size not in (4,8) or src.size!=dst.size):
        return None
    mem=src.mem
    if (ins.reg_name(mem.base)!="rbp" or mem.index or mem.segment or
        mem.scale not in (0,1)):
        return None
    disp=int(mem.disp)
    stack_offset=FRAME_ANCHOR_FROM_RSP+disp
    if not 0<=stack_offset or stack_offset+dst.size>MAX_FRAME_READ_END:
        return None
    at=0
    if len(data)>=4 and 0x40<=data[0]<=0x4f:
        at=1
        if bool(data[0]&8)!=(dst.size==8):
            return None
    elif dst.size!=4:
        return None
    if len(data)<at+3 or data[at]!=0x8b:
        return None
    modrm=data[at+1]
    if (modrm&7)!=5 or modrm>>6 not in (1,2):
        return None
    size=1 if modrm>>6==1 else 4
    if len(data)!=at+2+size:
        return None
    encoded=int.from_bytes(data[-size:],"little",signed=True)
    if disp!=encoded:
        return None
    destination=(REG64 if dst.size==8 else REG32).get(ins.reg_name(dst.reg))
    if destination is None:
        return None
    return {"kind":"frame_pointer_load","dst":destination,"bits":dst.size*8,
            "frame_disp":disp,"stack_offset":stack_offset,
            "address":ins.address,"bytes":len(data)}


def emit_native_prefix(prefix):
    if prefix is None:
        return ""
    kind=prefix.get("kind")
    width=prefix.get("bits")
    dst=prefix.get("dst")
    if width not in (32,64) or (kind!="guest_heap_store" and dst not in REG64):
        raise ValueError("Unsafe native original-callsite destination register")
    cast="(uint32_t)" if width==32 else ""
    if kind=="register_mov":
        src=prefix.get("src")
        if src not in REG64:
            raise ValueError("Unsafe native register operand")
        return f's.{dst}={cast}s.{src};'
    if kind=="effective_address":
        src=prefix.get("src")
        disp=prefix.get("disp")
        if width!=64 or src not in SOURCE_REGS or not isinstance(disp,int):
            raise ValueError("Unsafe native LEA operand")
        return f's.{dst}=s.{src}+UINT64_C({disp&((1<<64)-1)});'
    if kind=="stack_argument_load":
        offset=prefix.get("offset")
        if not isinstance(offset,int) or offset<0 or offset+width//8>MAX_STACK_READ_END:
            raise ValueError("Unsafe guest stack argument offset")
        reader="uint32_t" if width==32 else "uint64_t"
        return (f"do{{{reader} guest_read_value=0;"
                f"if(!mx_cfg_transfer(&memory,s.rsp+UINT64_C({offset}),"
                f"&guest_read_value,{width//8}U,0))return 8;"
                f"s.{dst}=(uint64_t)guest_read_value;}}while(0);")
    if kind=="frame_pointer_load":
        off=prefix.get("stack_offset")
        displacement=prefix.get("frame_disp")
        if (not isinstance(off,int) or not isinstance(displacement,int)
            or off!=FRAME_ANCHOR_FROM_RSP+displacement
            or off<0 or off+width//8>MAX_FRAME_READ_END):
            raise ValueError("Unverified guest frame-pointer load")
        reader="uint32_t" if width==32 else "uint64_t"
        return (f"do{{{reader} frame_value=0;"
                f"if(!mx_cfg_transfer(&memory,s.rsp+UINT64_C({off}),"
                f"&frame_value,{width//8}U,0))return 8;"
                f"s.{dst}=(uint64_t)frame_value;}}while(0);")
    if kind=="guest_heap_load":
        src=prefix.get("src")
        disp=prefix.get("disp")
        if (src not in GUEST_HEAP_REGS or not isinstance(disp,int) or
            not -MAX_GUEST_DISPLACEMENT<=disp<=MAX_GUEST_DISPLACEMENT):
            raise ValueError("Unsafe bounded original guest-pointer read")
        reader="uint32_t" if width==32 else "uint64_t"
        return (f"do{{{reader} guest_heap_value=0;"
                f"if(!mx_cfg_transfer(&memory,s.{src}+UINT64_C({disp&((1<<64)-1)}),"
                f"&guest_heap_value,{width//8}U,0))return 8;"
                f"s.{dst}=(uint64_t)guest_heap_value;}}while(0);")
    if kind=="guest_heap_store":
        base=prefix.get("src")
        reg=prefix.get("value_reg")
        disp=prefix.get("disp")
        if (base not in GUEST_HEAP_REGS or reg not in REG64 or
            not isinstance(disp,int) or
            not -MAX_GUEST_DISPLACEMENT<=disp<=MAX_GUEST_DISPLACEMENT):
            raise ValueError("Unsafe original guest memory store")
        cast="(uint32_t)" if width==32 else ""
        return (f"do{{uint64_t guest_store_addr=s.{base}+"
                f"UINT64_C({disp&((1<<64)-1)});"
                f"uint64_t guest_store_value={cast}s.{reg};"
                f"if(!mx_cfg_transfer(&memory,guest_store_addr,"
                f"&guest_store_value,{width//8}U,1))return 8;}}while(0);")
    if kind=="guest_heap_indexed_load":
        src=prefix.get("src")
        index=prefix.get("index")
        scale=prefix.get("scale")
        disp=prefix.get("disp")
        if (src not in GUEST_HEAP_REGS or index not in GUEST_HEAP_REGS or
            src==index or scale not in (1,2,4,8) or
            not isinstance(disp,int) or
            not -MAX_GUEST_DISPLACEMENT<=disp<=MAX_GUEST_DISPLACEMENT):
            raise ValueError("Unsafe indexed original guest memory read")
        reader="uint32_t" if width==32 else "uint64_t"
        return (f"do{{{reader} guest_indexed_value=0;"
                f"uint64_t guest_indexed_address=s.{src}+"
                f"s.{index}*UINT64_C({scale})+"
                f"UINT64_C({disp&((1<<64)-1)});"
                f"if(!mx_cfg_transfer(&memory,guest_indexed_address,"
                f"&guest_indexed_value,{width//8}U,0))return 8;"
                f"s.{dst}=(uint64_t)guest_indexed_value;}}while(0);")
    if kind=="zero_register":
        return f's.{dst}=0U;s.cf=0U;s.zf=1U;s.sf=0U;'
    if kind=="immediate_register":
        value=prefix.get("value")
        if not isinstance(value,int) or not 0<=value<(1<<width):
            raise ValueError("Unsafe native MOV immediate")
        return f's.{dst}=UINT64_C({value});'
    raise ValueError("Unsupported callsite native setup instruction")


def select_prefix(insns, call_index):
    if not isinstance(call_index,int) or not 0<call_index<len(insns):
        return None
    prior=insns[call_index-1]
    call=insns[call_index]
    if prior.address+prior.size!=call.address:
        return None
    return (decode_mov_prefix(prior) or decode_lea_prefix(prior) or
            decode_zero_prefix(prior) or decode_imm_prefix(prior) or
            decode_stack_load_prefix(prior) or decode_frame_pointer_load_prefix(prior) or
            decode_guest_heap_load_prefix(prior) or
            decode_guest_indexed_load_prefix(prior) or
            decode_guest_heap_store_prefix(prior))


MAX_PREFIX_INSTRUCTIONS=4
MAX_PREFIX_BYTES=32


def select_prefix_chain(insns, call_index):
    """Extract a complete contiguous bounded argument-setup slice.

    Stop at the first unsupported instruction, an instruction gap, or the
    budget. A selected prefix proves only the testable original execution
    slice, not a full parent function or the safety of external entry edges.
    """
    if not isinstance(call_index,int) or not 0<call_index<len(insns):
        return []
    selected=[]
    right_address=insns[call_index].address
    total_bytes=0
    for at in range(call_index-1,max(-1,call_index-1-MAX_PREFIX_INSTRUCTIONS),-1):
        inst=insns[at]
        if inst.address+inst.size!=right_address:
            break
        opcode=(decode_mov_prefix(inst) or decode_lea_prefix(inst) or
                decode_zero_prefix(inst) or decode_imm_prefix(inst) or
                decode_stack_load_prefix(inst) or decode_frame_pointer_load_prefix(inst) or
                decode_guest_heap_load_prefix(inst) or
                decode_guest_indexed_load_prefix(inst) or
                decode_guest_heap_store_prefix(inst))
        if opcode is None or total_bytes+inst.size>MAX_PREFIX_BYTES:
            break
        selected.append(opcode)
        total_bytes+=inst.size
        right_address=inst.address
    selected.reverse()
    return selected
