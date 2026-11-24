#!/usr/bin/env python3
"""Bounded CFG lifter: explicit guest PC, call stack, conditional paths and loops.

Supported local CPU operations only. No entitlement decisions, external imports,
indirect calls, guest code writes, or arbitrary host pointers. A private owned
binary is never copied to public outputs.
"""
from __future__ import annotations
import argparse, hashlib, json, struct, sys
from pathlib import Path
from capstone import Cs, CS_ARCH_X86, CS_MODE_64, CS_OP_REG, CS_OP_IMM, CS_OP_MEM
from unicorn import Uc, UC_ARCH_X86, UC_MODE_64, UC_HOOK_CODE
from unicorn import x86_const as x
from mxbikes_native_slice_lift import (
    MASK,PAGE,STACK,RSP,REGS,REG_INDEX,UC_REG,CMP_FLAGS,RUNTIME,u,
    initial,hash_page,compile_native,owned_input,SHA,
)

# Use the production-style persistent guest memory instead of a private array
# embedded in each generated fixture. Flag operations remain shared with the
# previously verified slice lifter.
MEMORY_RUNTIME=r"""
#include <stdint.h>
#include "mxb_guest_memory.h"
#include "mxb_guest_crt.h"
#include "mxb_native_exec.h"
#include "mxb_pe_guest_image.h"
typedef MXBGuestState State;
static uint64_t load(State*s,uint64_t addr,unsigned size){
 uint8_t bytes[8];uint64_t v=0;
 if(!mxb_guest_read(&s->memory,addr,bytes,size)){s->fault=1;return 0;}
 for(unsigned i=0;i<size;i++)v|=(uint64_t)bytes[i]<<(8u*i);
 return v;
}
static void store(State*s,uint64_t addr,uint64_t v,unsigned size){
 uint8_t bytes[8];
 for(unsigned i=0;i<size;i++)bytes[i]=(uint8_t)(v>>(8u*i));
 if(!mxb_guest_write(&s->memory,addr,bytes,size))s->fault=1;
}
"""
MEMORY_RUNTIME+="#define PAGE 4096u\n"+RUNTIME[RUNTIME.index("static uint64_t common_flags"):]
MEMORY_RUNTIME+=r"""
#ifdef MXB_FREESTANDING_TEST
void *memcpy(void *dst,const void *src,unsigned long n){
 volatile unsigned char*d=dst;const volatile unsigned char*s=src;
 for(unsigned long i=0;i<n;i++)d[i]=s[i];
 return dst;
}
#endif
"""
RUNTIME_SOURCES=("mxb_guest_memory.c","mxb_guest_crt.c","mxb_pe_guest_image.c","mxb_native_dispatch.c")
MAX_STATIC=512
MAX_DYNAMIC=8192
HEAP_ARENA = 0x740000000
TRACE_INIT=0xcbf29ce484222325
TRACE_PRIME=0x100000001b3

# Canonical Capstone condition names; x86 uses CF/PF/ZF/SF/OF.
CONDS={
 "je":"z","jne":"!z","jb":"c","jae":"!c","jbe":"(c||z)","ja":"(!c&&!z)",
 "js":"sign","jns":"!sign","jo":"o","jno":"!o","jp":"p","jnp":"!p",
 "jl":"(sign!=o)","jge":"(sign==o)","jle":"(z||sign!=o)","jg":"(!z&&sign==o)",
}
EXTRA=r"""
static uint64_t add_flags(State*s,uint64_t a,uint64_t b,unsigned width){
 uint64_t mask=UINT64_MAX>>(64u-width);
 a&=mask;b&=mask;uint64_t v=(a+b)&mask;
 s->flags=(s->flags&~UINT64_C(0x8d5))|common_flags(v,width)|
   (v<a?1u:0u)|((a^b^v)&0x10u)|(((~(a^b)&(a^v))>>(width-1u))&1u?0x800u:0u);
 return v;
}
static uint64_t logic_flags(State*s,uint64_t v,unsigned width){
 v&=UINT64_MAX>>(64u-width);
 s->flags=(s->flags&~UINT64_C(0x8c5))|common_flags(v,width);return v;
}
"""
def decode_cfg(windows,entry,stop,imports=None,iat=None,alternate_stops=(),disk_imports=None,gs_base=None,register_calls=None,additional_entries=(),dynamic_limit=8192):
    if not 1<=dynamic_limit<=8000000:raise ValueError('Invalid native dynamic budget')
    imports=imports or {};iat=iat or {};import_returns={a:set() for a in imports}
    frontiers={stop,*alternate_stops}
    decoder=Cs(CS_ARCH_X86,CS_MODE_64);decoder.detail=True
    nodes={}; pages=set(); pending=[entry,*additional_entries]; ranges=[(a,a+len(b)) for a,b in windows]
    def in_code(pc):return any(a<=pc<b for a,b in ranges)
    def reg(ins,op):
        name=ins.reg_name(op.reg)
        if name not in REG_INDEX:raise ValueError("Unsupported register "+name)
        idx,width=REG_INDEX[name]
        if op.size*8!=width:raise ValueError("Register width mismatch")
        return idx,width
    def xmm(ins,op):
        if op.type!=CS_OP_REG:raise ValueError("Expected XMM register")
        name=ins.reg_name(op.reg)
        if not name.startswith("xmm") or not name[3:].isdigit() or not 0<=int(name[3:])<16:
            raise ValueError("Unsupported vector register "+name)
        return int(name[3:])
    def addr(ins,op):
        m=op.mem
        if (gs_base is not None and ins.reg_name(m.segment)=="gs" and not m.index
                and not m.base and m.disp==0x30 and ins.mnemonic=="mov" and op.size==8):
            return u(gs_base+m.disp)
        if m.segment or (not m.base and not m.index):raise ValueError("Unsupported memory addressing")
        base=ins.reg_name(m.base) if m.base else None
        index=ins.reg_name(m.index) if m.index else None
        if base=="rip":
            if index:raise ValueError("Invalid RIP index")
            a=(ins.address+ins.size+m.disp)&MASK
            if ins.mnemonic!="lea":
                if a%PAGE+op.size>PAGE:raise ValueError("Cross-page static data")
                pages.add(a&~(PAGE-1))
            return u(a)
        if base is not None and base not in REGS:raise ValueError("Invalid base register")
        if index is not None and (index not in REGS or m.scale not in (1,2,4,8)):
            raise ValueError("Invalid index register")
        terms=[u(m.disp)]
        if base is not None:terms.append(f"s->r[{REGS.index(base)}]")
        if index is not None:terms.append(f"s->r[{REGS.index(index)}]*{m.scale}u")
        return "("+"+".join(terms)+")"
    # Legacy 8/16-bit register aliases preserve the other bits of the GPR.
    partial={}
    for i,name in enumerate(("ax","cx","dx","bx","sp","bp","si","di",*(f"r{i}w" for i in range(8,16)))):
        partial[name]=(i,16,0)
    for i,name in enumerate(("al","cl","dl","bl","spl","bpl","sil","dil",*(f"r{i}b" for i in range(8,16)))):
        partial[name]=(i,8,0)
    for i,name in enumerate(("ah","ch","dh","bh")):partial[name]=(i,8,8)
    def read(ins,op):
        if op.type==CS_OP_REG and ins.reg_name(op.reg) in partial:
            i,width,shift=partial[ins.reg_name(op.reg)]
            if op.size*8!=width:raise ValueError("Partial register width mismatch")
            return f"((s->r[{i}]>>{shift}u)&{u((1<<width)-1)})"
        if op.type==CS_OP_REG:
            i,w=reg(ins,op);return "(s->r[%d]&%s)"%(i,u((1<<w)-1))
        if op.type==CS_OP_IMM:return u(op.imm)
        if op.type==CS_OP_MEM and op.size in (1,2,4,8):return "load(s,%s,%du)"%(addr(ins,op),op.size)
        raise ValueError("Unsupported source operand")
    def write(ins,op,v):
        if op.type==CS_OP_REG and ins.reg_name(op.reg) in partial:
            i,width,shift=partial[ins.reg_name(op.reg)]
            if op.size*8!=width:raise ValueError("Partial register width mismatch")
            mask=(1<<width)-1
            return f"s->r[{i}]=(s->r[{i}]&{u(~(mask<<shift))})|((({v})&{u(mask)})<<{shift}u);"
        if op.type==CS_OP_REG:
            i,w=reg(ins,op);return "s->r[%d]=(%s)&%s;"%(i,v,u((1<<w)-1))
        if op.type==CS_OP_MEM and op.size in (1,2,4,8):return "store(s,%s,%s,%du);"%(addr(ins,op),v,op.size)
        raise ValueError("Unsupported destination operand")
    while pending:
        pc=pending.pop()
        if pc in frontiers or pc in nodes or pc in imports:continue
        if len(nodes)>=MAX_STATIC:raise ValueError("Static budget exhausted")
        found=[(base,buf) for base,buf in windows if base<=pc<base+len(buf)]
        if len(found)!=1:raise ValueError("Unapproved direct target "+hex(pc))
        base,buf=found[0]
        ins=next(decoder.disasm(buf[pc-base:],pc,count=1),None)
        if ins is None:raise ValueError("Decode failed at "+hex(pc))
        if any(a<pc<b or pc<a<pc+ins.size for a,(_,b) in nodes.items()):
            raise ValueError("Overlapping instruction boundaries")
        op=ins.operands;mn=ins.mnemonic;nxt=pc+ins.size
        edges=[nxt];next_pc=u(nxt);stmt=""
        if mn=="xorps" and len(op)==2 and all(o.type==CS_OP_REG for o in op):
            dst,src=xmm(ins,op[0]),xmm(ins,op[1])
            stmt=f"s->xmm[{dst}][0]^=s->xmm[{src}][0];s->xmm[{dst}][1]^=s->xmm[{src}][1];"
        elif mn=="movss" and len(op)==2:
            if op[0].type==CS_OP_MEM and op[0].size==4 and op[1].type==CS_OP_REG:
                src=xmm(ins,op[1]);stmt=write(ins,op[0],f"s->xmm[{src}][0]&UINT64_C(0xffffffff)")
            elif op[0].type==CS_OP_REG and op[1].type==CS_OP_MEM and op[1].size==4:
                dst=xmm(ins,op[0]);address=addr(ins,op[1])
                stmt=(f"{{uint64_t v=load(s,{address},4);if(s->fault)return MXB_NATIVE_MEMORY_FAULT;"
                      f"s->xmm[{dst}][0]=v;s->xmm[{dst}][1]=0;}}")
            elif op[0].type==op[1].type==CS_OP_REG:
                dst,src=xmm(ins,op[0]),xmm(ins,op[1])
                stmt=f"s->xmm[{dst}][0]=(s->xmm[{dst}][0]&UINT64_C(0xffffffff00000000))|(s->xmm[{src}][0]&UINT64_C(0xffffffff));"
            else:raise ValueError("Unsupported scalar SSE move at "+hex(pc))
        elif mn=="not" and len(op)==1 and op[0].type==CS_OP_REG:
            stmt=write(ins,op[0],"~"+read(ins,op[0]))
        elif mn in ("repne scasb","repnz scasb") and len(op)==2:
            # One bounded string instruction; preserve direction, final
            # arithmetic flags and the remaining original count.
            stmt=("{unsigned budget=65536u;while(s->r[1]){"
                  "if(!budget--)return MXB_NATIVE_BUDGET;"
                  "uint64_t value=load(s,s->r[7],1);if(s->fault)return MXB_NATIVE_MEMORY_FAULT;"
                  "(void)sub_flags(s,s->r[0]&255u,value,8u);"
                  "s->r[7]+=(s->flags&0x400u)?UINT64_MAX:1u;s->r[1]--;"
                  "if(s->flags&0x40u)break;}}")
        elif mn=="imul" and len(op)==3 and op[0].type==CS_OP_REG and op[0].size in (4,8) and op[2].type==CS_OP_IMM:
            width=op[0].size*8
            signed_type=f"int{width}_t"
            a=read(ins,op[1]);b=read(ins,op[2])
            stmt=("{__int128 product=(__int128)("+signed_type+")("+a+")*("+signed_type+")("+b+");"
                  f"uint64_t result=(uint64_t)product&{u((1<<width)-1)};"
                  f"unsigned overflow=product!=(__int128)({signed_type})result;"
                  +write(ins,op[0],"result")+"s->flags=(s->flags&~UINT64_C(0x801))|(overflow?0x801u:0u);}")
        elif mn=="cdqe" and not op:
            stmt="s->r[0]=(uint64_t)(int64_t)(int32_t)s->r[0];"
        elif mn in ("mov","movabs") and len(op)==2:
            stmt=write(ins,op[0],read(ins,op[1]))
        elif mn in ("movsx","movsxd","movzx") and len(op)==2 and op[0].type==CS_OP_REG:
            _,width=reg(ins,op[0]);src_width=op[1].size*8
            if src_width not in (8,16,32) or src_width>=width:raise ValueError("Invalid extending move width")
            value=read(ins,op[1]);mask=u((1<<src_width)-1)
            if mn=="movzx":value="(%s&%s)"%(value,mask)
            else:
                sign=u(1<<(src_width-1))
                value="(((%s&%s)^%s)-%s)"%(value,mask,sign,sign)
            stmt=write(ins,op[0],value)
        elif mn=="lea" and len(op)==2 and op[0].type==CS_OP_REG and op[1].type==CS_OP_MEM:
            stmt=write(ins,op[0],addr(ins,op[1]))
        elif mn in ("rol","ror","shl","shr") and len(op)==2 and op[0].type==CS_OP_REG and op[0].size in (1,2,4,8) and op[1].type==CS_OP_IMM:
            width=op[0].size*8
            mask=u((1<<width)-1)
            count=op[1].imm&(63 if width==64 else 31)
            rotate=mn in ("rol","ror")
            if rotate:count%=width
            if count:
                if count>=width:raise ValueError("Unsupported shift count at "+hex(pc))
                if mn=="rol":
                    expr=f"((v<<{count}u)|(v>>{width-count}u))&{mask}"
                    carry="(result&1u)"
                    overflow=f"((result>>{width-1})^carry)"
                elif mn=="ror":
                    expr=f"((v>>{count}u)|(v<<{width-count}u))&{mask}"
                    carry=f"(result>>{width-1})"
                    overflow=f"((result>>{width-1})^((result>>{width-2})&1u))"
                elif mn=="shl":
                    expr=f"(v<<{count}u)&{mask}"
                    carry=f"((v>>{width-count})&1u)"
                    overflow=f"((result>>{width-1})^carry)"
                else:
                    expr=f"v>>{count}u"
                    carry=f"((v>>{count-1})&1u)"
                    overflow=f"(v>>{width-1})"
                stmt=("{uint64_t v="+read(ins,op[0])+",result="+expr+",carry="+carry+";"
                      +write(ins,op[0],"result")
                      +("" if rotate else f"s->flags=(s->flags&~UINT64_C(0xc4))|common_flags(result,{width}u);")
                      +"s->flags=(s->flags&~UINT64_C(1))|carry;"
                      +(f"s->flags=(s->flags&~UINT64_C(0x800))|(({overflow})<<11);" if count==1 else "")+"}")
        elif mn in ("inc","dec") and len(op)==1 and op[0].type==CS_OP_MEM and op[0].size in (4,8):
            n=op[0].size;address=addr(ins,op[0]);operation="add" if mn=="inc" else "sub"
            stmt=(f"{{uint64_t ea={address};"
                  f"if(!mxb_guest_check(&s->memory,ea,{n},MXB_MEM_READ|MXB_MEM_WRITE))"
                  "{s->fault=1;return MXB_NATIVE_MEMORY_FAULT;}"
                  f"uint64_t v=load(s,ea,{n}),carry=s->flags&1u;"
                  f"v={operation}_flags(s,v,1,{n*8}u);"
                  "s->flags=(s->flags&~UINT64_C(1))|carry;"
                  f"store(s,ea,v,{n});}}")
        elif mn in ("add","sub") and len(op)==2 and op[0].type==CS_OP_MEM and op[0].size in (4,8) and op[1].type in (CS_OP_IMM,CS_OP_REG):
            n=op[0].size;address=addr(ins,op[0]);operand=read(ins,op[1])
            stmt=(f"{{uint64_t ea={address};"
                  f"if(!mxb_guest_check(&s->memory,ea,{n},MXB_MEM_READ|MXB_MEM_WRITE))"
                  "{s->fault=1;return MXB_NATIVE_MEMORY_FAULT;}"
                  f"uint64_t v=load(s,ea,{n});v={mn}_flags(s,v,{operand},{n*8}u);"
                  f"store(s,ea,v,{n});}}")
        elif mn in ("and","or") and len(op)==2 and op[0].type==CS_OP_MEM and op[0].size==4 and op[1].type==CS_OP_IMM:
            address=addr(ins,op[0]);operator="&" if mn=="and" else "|"
            stmt=(f"{{uint64_t ea={address};"
                  "if(!mxb_guest_check(&s->memory,ea,4,MXB_MEM_READ|MXB_MEM_WRITE))"
                  "{s->fault=1;return MXB_NATIVE_MEMORY_FAULT;}"
                  f"uint64_t v=load(s,ea,4);store(s,ea,logic_flags(s,v{operator}{u(op[1].imm)},32),4);}}")
        elif mn in ("xor","sub","add","and","or") and len(op)==2 and op[0].type==CS_OP_REG:
            width=op[0].size*8;a=read(ins,op[0]);b=read(ins,op[1])
            v=("%s_flags(s,%s,%s,%du)"%(mn,a,b,width) if mn in ("xor","sub","add")
               else "logic_flags(s,%s%s%s,%du)"%(a,"&" if mn=="and" else "|",b,width))
            stmt=write(ins,op[0],v)
        elif mn in ("neg","dec","inc") and len(op)==1 and op[0].type==CS_OP_REG and op[0].size in (4,8):
            width=op[0].size*8
            source=read(ins,op[0])
            if mn=="neg":stmt=write(ins,op[0],f"sub_flags(s,0,{source},{width}u)")
            else:
                operation="add" if mn=="inc" else "sub"
                stmt="{uint64_t carry=s->flags&1u;"+write(ins,op[0],f"{operation}_flags(s,{source},1,{width}u)")+"s->flags=(s->flags&~UINT64_C(1))|carry;}"
        elif mn=="sbb" and len(op)==2 and op[0].type==op[1].type==CS_OP_REG and op[0].reg==op[1].reg and op[0].size in (4,8):
            # x - x - CF has the same result and arithmetic flags as 0 - CF.
            stmt=write(ins,op[0],f"sub_flags(s,0,s->flags&1u,{op[0].size*8}u)")
        elif mn=="cmp" and len(op)==2 and op[0].type==CS_OP_MEM and op[0].size==2 and op[1].type==CS_OP_REG and ins.reg_name(op[1].reg)=="ax":
            stmt="(void)sub_flags(s,%s,s->r[0],16u);"%read(ins,op[0])
        elif mn=="setne" and len(op)==1 and op[0].type==CS_OP_REG and ins.reg_name(op[0].reg)=="al":
            stmt="s->r[0]=(s->r[0]&~UINT64_C(255))|((s->flags&0x40u)==0);"
        elif mn.startswith("set") and "j"+mn[3:] in CONDS and len(op)==1 and op[0].size==1:
            cond=CONDS["j"+mn[3:]]
            stmt=("{unsigned c=(s->flags&1)!=0,p=(s->flags&4)!=0,z=(s->flags&0x40)!=0,sign=(s->flags&0x80)!=0,o=(s->flags&0x800)!=0;"
                  "(void)c;(void)p;(void)z;(void)sign;(void)o;"+write(ins,op[0],f"({cond})?1u:0u")+"}")
        elif mn.startswith("cmov") and "j"+mn[4:] in CONDS and len(op)==2 and op[0].type==CS_OP_REG and op[0].size in (4,8):
            cond=CONDS["j"+mn[4:]];width=op[0].size*8
            stmt=("{unsigned c=(s->flags&1)!=0,p=(s->flags&4)!=0,z=(s->flags&0x40)!=0,sign=(s->flags&0x80)!=0,o=(s->flags&0x800)!=0;"
                  "(void)c;(void)p;(void)z;(void)sign;(void)o;"
                  f"uint64_t v={read(ins,op[1])};if(s->fault)return MXB_NATIVE_MEMORY_FAULT;"
                  +write(ins,op[0],f"({cond})?v:{read(ins,op[0])}")+"}")
        elif mn=="xchg" and len(op)==2 and op[0].type==CS_OP_MEM and op[1].type==CS_OP_REG and op[0].size==op[1].size and op[0].size in (4,8):
            n=op[0].size;address=addr(ins,op[0])
            # Guest runtime is single-threaded; the implicit locked operation
            # checks the complete writable span before changing either operand.
            stmt=(f"{{uint64_t ea={address};"
                  f"if(!mxb_guest_check(&s->memory,ea,{n},MXB_MEM_READ|MXB_MEM_WRITE))"
                  "{s->fault=1;return MXB_NATIVE_MEMORY_FAULT;}"
                  f"uint64_t old=load(s,ea,{n}),value={read(ins,op[1])};"
                  f"store(s,ea,value,{n});if(s->fault)return MXB_NATIVE_MEMORY_FAULT;"
                  +write(ins,op[1],"old")+"}")
        elif mn in ("cmp","test") and len(op)==2 and op[0].size in (1,2,4,8):
            width=op[0].size*8;a=read(ins,op[0]);b=read(ins,op[1])
            if mn=="cmp":stmt="(void)sub_flags(s,%s,%s,%du);"%(a,b,width)
            elif width in (8,16):stmt="(void)logic_flags(s,(%s&%s)&%s,%du);"%(a,b,u((1<<width)-1),width)
            else:stmt="(void)logic_flags(s,%s&%s,%du);"%(a,b,width)
        elif mn=="push" and len(op)==1 and op[0].type==CS_OP_REG and op[0].size==8:
            stmt="{uint64_t value=%s;s->r[4]-=8u;store(s,s->r[4],value,8u);}"%read(ins,op[0])
        elif mn=="pop" and len(op)==1 and op[0].type==CS_OP_REG and op[0].size==8 and reg(ins,op[0])[0]!=4:
            stmt=write(ins,op[0],"load(s,s->r[4],8u)")+"s->r[4]+=8u;"
        elif mn=="call" and len(op)==1 and op[0].type in (CS_OP_REG,CS_OP_MEM) and pc in (register_calls or {}):
            target=register_calls[pc]
            if op[0].size!=8:raise ValueError("Indirect target must be Win64 pointer")
            stmt=(f"{{uint64_t target={read(ins,op[0])};"
                  "if(s->fault)return MXB_NATIVE_MEMORY_FAULT;"
                  f"if(target!={u(target)})return MXB_NATIVE_UNKNOWN_PC;"
                  f"if(s->r[4]<8u||!mxb_guest_check(&s->memory,s->r[4]-8u,8,MXB_MEM_WRITE))"
                  "{s->fault=1;return MXB_NATIVE_MEMORY_FAULT;}"
                  f"s->r[4]-=8u;store(s,s->r[4],{u(nxt)},8u);}}")
            next_pc=u(target);edges=[target,nxt]
        elif mn=="call" and len(op)==1 and op[0].type==CS_OP_IMM:
            target=op[0].imm
            stmt="s->r[4]-=8u;store(s,s->r[4],%s,8u);"%u(nxt)
            next_pc=u(target);edges=[target]
            if in_code(nxt) or nxt in frontiers:edges.append(nxt)
            if target in imports:import_returns[target].add(nxt)
        elif mn in ("ret","repz ret","rep ret") and not op:
            stmt="next=load(s,s->r[4],8u);s->r[4]+=8u;"
            next_pc="next";edges=[]
        elif mn=="jmp" and len(op)==1 and op[0].type==CS_OP_IMM:
            edges=[op[0].imm];next_pc=u(op[0].imm)
        elif mn=="jmp" and len(op)==1 and op[0].type==CS_OP_MEM:
            mem=op[0].mem
            if ins.reg_name(mem.base)!="rip" or mem.index or mem.segment or op[0].size!=8:
                raise ValueError("Unsupported indirect jump")
            slot=pc+ins.size+mem.disp
            if slot not in iat or iat[slot][0] not in imports:
                raise ValueError("Unapproved IAT slot")
            target,continuation=iat[slot]
            pages.add(slot&~(PAGE-1));import_returns[target].update(continuation if isinstance(continuation,(tuple,list)) else (continuation,))
            slot_value=target if disk_imports is None else disk_imports[slot]
            stmt="next=load(s,%s,8u);if(s->fault||next!=%s)return 97;"%(u(slot),u(slot_value))
            if disk_imports is not None:stmt+="next=%s;"%u(target)
            edges=[target];next_pc="next"
        elif mn in CONDS and len(op)==1 and op[0].type==CS_OP_IMM:
            edges=[nxt,op[0].imm]
            stmt="{unsigned c=(s->flags&1)!=0,p=(s->flags&4)!=0,z=(s->flags&0x40)!=0,sign=(s->flags&0x80)!=0,o=(s->flags&0x800)!=0;(void)c;(void)p;(void)z;(void)sign;(void)o;next=(%s)?%s:%s;}"%(CONDS[mn],u(op[0].imm),u(nxt))
            next_pc="next"
        elif mn=="nop":pass  # multi-byte NOP addressing operands are not dereferenced
        else:raise ValueError("Unsupported CFG instruction "+mn+" "+ins.op_str+" at "+hex(pc))
        nodes[pc]=(stmt+"if(s->fault)return 90;pc="+next_pc+";break;",nxt)
        pending.extend(edges)
    # Import slots are explicit host-approved semantic boundaries. No native
    # function pointer can be obtained from a guest register.
    for target,name in imports.items():
        continuations=sorted(import_returns[target])
        if not continuations:continue
        if name not in ("memset","memcpy","memmove","malloc","free","strcpy","strrchr","fopen","fseek","ftell","fread","fclose"):raise ValueError("Unsupported native import")
        guard="||".join("next=="+u(a) for a in continuations)
        stmt=("next=load(s,s->r[4],8u);if(s->fault||!(%s))return 97;"
              'if(mxb_guest_crt_call(s,"MSVCR90.dll","%s",next)!=MXB_CRT_OK)return 98;'
              "pc=next;break;")%(guard,name)
        nodes[target]=(stmt,target+1)
    cases=["case "+u(pc)+":{"+stmt+"}" for pc,(stmt,_) in sorted(nodes.items())]
    c="""typedef MXBNativeCursor Cursor;
static Cursor lifted_begin(void){
 Cursor c={ENTRY,UINT64_C(0xcbf29ce484222325),0};return c;
}
/* Pause only at original instruction boundaries. Caller-owned CPU and cursor
 * remain live across budgeted invocations; never reset register or stack state. */
static int lifted_resume(State*s,Cursor*c,unsigned quota){
 uint64_t pc=c->pc;
 while(pc!=STOP){
  if(c->steps>=DYNAMIC_LIMIT)return MXB_NATIVE_BUDGET;
  if(!quota){c->pc=pc;return MXB_NATIVE_YIELD;}
  quota--;c->steps++;c->trace=(c->trace^pc)*UINT64_C(0x100000001b3);
  c->pc=pc;
  uint64_t next=0;(void)next;
  switch(pc){CASES default:return MXB_NATIVE_UNKNOWN_PC;}
  c->pc=pc;
 }
 return 0;
}
""".replace("ENTRY",u(entry)).replace("STOP",u(stop)+"".join("&&pc!="+u(a) for a in alternate_stops)).replace("CASES","\n".join(cases)).replace("DYNAMIC_LIMIT",str(dynamic_limit)+"u")
    return c,sorted(pages),set(nodes)

def synthetic_input():
    base=0x10000000
    # test ecx,ecx; jle stop; xor eax,eax; call helper; stop
    a=bytes.fromhex("85c9 7e07 31c0 e8f5000000")
    # helper: push rbx; mov ebx,ecx; add eax,ebx; sub ebx,1;
    # jne loop; pop rbx; ret. Both forward branches and repeated back edges.
    b=bytes.fromhex("53 89cb 01d8 83eb01 75f9 5b c3")
    return [(base,a),(base+0x100,b)],base,base+len(a)

def reference(windows,entry,stop,pages,nodes,seed,synthetic,imports=None,iat=None,crt_case=None,image_pages=None,page_permissions=None,alternate_stops=(),patches=None,filename_case=False):
    imports=imports or {};iat=iat or {}
    regs,flags,data=initial(seed,pages)
    data.update(image_pages or {});page_permissions=page_permissions or {}
    if synthetic:regs[1]=[0,1,2,3,5,8,0xffffffff,0x80000000][seed-1]
    if crt_case and crt_case[0]!="heap-init":
        name,n=crt_case;heap=0x730000000
        regs[1]=heap+4094 if name=='memcpy' else heap+128
        regs[2]=heap+32 if name=='memcpy' else seed*19
        regs[8]=n
    for address,payload in (patches or {}).items():
        page=address&~(PAGE-1);off=address-page
        if off+len(payload)>PAGE:raise ValueError('Fixture patch crosses page')
        buf=bytearray(data[page]);buf[off:off+len(payload)]=payload;data[page]=bytes(buf)
    for slot,(target,_) in iat.items():
        page=slot&~(PAGE-1);off=slot-page
        buf=bytearray(data[page]);buf[off:off+8]=struct.pack('<Q',target);data[page]=bytes(buf)
    cpu=Uc(UC_ARCH_X86,UC_MODE_64);mapped=set()
    for a,blob in windows:
        for p in range(a&~(PAGE-1),(a+len(blob)+PAGE-1)&~(PAGE-1),PAGE):
            if p not in mapped:cpu.mem_map(p,PAGE);mapped.add(p)
        cpu.mem_write(a,blob)
    if mapped.intersection(pages):raise ValueError("Code/data overlap")
    for p in pages:
        cpu.mem_map(p,PAGE);cpu.mem_write(p,data[p])
        if p in page_permissions:cpu.mem_protect(p,PAGE,page_permissions[p])
    for r,v in zip(UC_REG,regs):cpu.reg_write(r,v)
    cpu.reg_write(x.UC_X86_REG_EFLAGS,flags)
    trace=[]; invalid=[]; import_events=[]
    def hook(uc,pc,size,ctx):
        if pc in alternate_stops:uc.emu_stop();return
        if pc not in nodes:invalid.append(pc);uc.emu_stop();return
        trace.append(pc)
        if pc in imports:
            # Independent Python reference for the synthetic CRT service.
            # The actual x64 RET instruction still executes in Unicorn.
            sp=uc.reg_read(x.UC_X86_REG_RSP)
            if sp%16!=8:raise ValueError("Reference Win64 ABI alignment")
            dst=uc.reg_read(x.UC_X86_REG_RCX);src=uc.reg_read(x.UC_X86_REG_RDX)
            name=imports[pc]
            if name in ("strcpy","strrchr"):
                address=src if name=="strcpy" else dst
                string=bytearray()
                while len(string)<65536:
                    string.extend(uc.mem_read(address+len(string),1))
                    if string[-1]==0:break
                else:raise ValueError("Unterminated reference string")
                if name=="strcpy":
                    uc.mem_write(dst,bytes(string));result=dst
                else:
                    index=string.rfind(bytes([src & 255]))
                    result=dst+index if index>=0 else 0
                uc.reg_write(x.UC_X86_REG_RAX,result)
            elif name=="malloc":
                # Scripted independent contract for the public sequence. The
                # second allocation fits the released first extent.
                expected_size = 9600 if crt_case else (32 if not import_events else 16)
                if dst != expected_size:raise ValueError("Unexpected allocation size")
                uc.reg_write(x.UC_X86_REG_RAX,HEAP_ARENA)
            elif name=="free":
                if dst != HEAP_ARENA:raise ValueError("Unexpected free pointer")
            else:
                n=uc.reg_read(x.UC_X86_REG_R8)
                if n>16384:raise ValueError("Reference CRT fixture size")
                if name=="memcpy" and n and abs(dst-src)<n:raise ValueError("Reference overlapping memcpy")
                payload=bytes([src&255])*n if name=="memset" else bytes(uc.mem_read(src,n))
                uc.mem_write(dst,payload);uc.reg_write(x.UC_X86_REG_RAX,dst)
            import_events.append(name)
    cpu.hook_add(UC_HOOK_CODE,hook)
    cpu.emu_start(entry,stop,count=MAX_DYNAMIC,timeout=2_000_000)
    final_pc=cpu.reg_read(x.UC_X86_REG_RIP)
    if invalid or final_pc not in {stop,*alternate_stops}:raise ValueError("Reference did not reach frontier")
    expected_imports = ["malloc","memset","free","malloc","memcpy","memset","memmove"]
    if filename_case:
        path=FILENAME_CASES[seed-1]
        last=max(path.rfind(b"/"),path.rfind(bytes([92])))
        colon=path.rfind(b":")
        expected=path[:last+1] if last>=0 else path[:colon+1]+bytes([92]) if colon>=0 else b""
        expected_imports=["strcpy"] if last>=0 else ["strcpy","strrchr"]
        if final_pc!=stop or cpu.reg_read(x.UC_X86_REG_RAX)!=FILENAME_GLOBAL or cpu.reg_read(x.UC_X86_REG_RSP)!=RSP:
            raise ValueError("Original filename helper return contract")
        if bytes(cpu.mem_read(FILENAME_GLOBAL,len(expected)+1))!=expected+b"\x00":
            raise ValueError("Original directory selection mismatch")
    if crt_case:
        expected_imports = ["malloc","memset"] if crt_case[0]=="heap-init" else [crt_case[0]]
    if imports and import_events!=expected_imports:raise ValueError("Reference import sequence")
    if crt_case and crt_case[0]=="heap-init":
        if bytes(cpu.mem_read(0x140585930,8))!=struct.pack("<Q",HEAP_ARENA):
            raise ValueError("Original initialization did not retain the allocated pointer")
        if bytes(cpu.mem_read(HEAP_ARENA,9600))!=bytes(9600):
            raise ValueError("Original initialization failed to clear its allocation")
    th=TRACE_INIT
    for pc in trace:th=((th^pc)*TRACE_PRIME)&MASK
    return regs,flags,[cpu.reg_read(r) for r in UC_REG],cpu.reg_read(x.UC_X86_REG_EFLAGS),[hash_page(cpu.mem_read(p,PAGE)) for p in pages],th,trace,final_pc

def owned_loop_input(path):
    from tools.pe_probe import PE
    if hashlib.sha256(path.read_bytes()).hexdigest()!=SHA:raise ValueError("Wrong owned executable")
    pe=PE(path);base=pe.u64(pe.opt+24)
    if base!=0x140000000:raise ValueError("Unexpected image base")
    # Original caller and two nested local calls, through the first complete
    # nested memory initialization loop. No later transformation is lifted.
    spans=((0x133f66,0x133f7b),(0x2a9ae0,0x2a9b0d),
           (0x2838f0,0x28394a),(0x285980,0x2859f3))
    windows=[(base+a,pe.read_rva(a,b-a)) for a,b in spans]
    # The code uses register-indirect reads/writes into these bounded pages.
    # Seed them with synthetic data; no original table contents are exported.
    extra=[base+rva for rva in (0x32e000,0x32f000,0x584000,0x585000)]
    return windows,base+spans[0][0],base+spans[-1][1],extra

def imports_input():
    base=0x10000000;heap=0x730000000
    targets={base+0x100:"memcpy",base+0x110:"memset",base+0x120:"memmove"}
    code=bytearray(bytes.fromhex("4883ec20"))
    targets.update({base+0x130:"malloc",base+0x140:"free"})
    def call(target):
        code.extend(b"\xe8"+struct.pack("<i",target-(base+len(code)+5)))
    code.extend(bytes.fromhex("b920000000"))  # mov ecx,32
    call(base+0x130)
    code.extend(bytes.fromhex("4889c1 ba5a000000 41b820000000"))  # memset(rax,0x5a,32)
    call(base+0x110)
    code.extend(bytes.fromhex("4889c1"))  # free(memset return)
    call(base+0x140)
    code.extend(bytes.fromhex("b910000000"))
    call(base+0x130)
    code.extend(bytes.fromhex("4889c3"))  # retain second pointer across calls
    for target,dst,src,n in (
        (base+0x100,heap+128,heap+16,40),
        (base+0x110,heap+4092,0xa7,8),
        (base+0x120,heap+132,heap+128,32),
    ):
        code+=b"\x48\xb9"+struct.pack("<Q",dst)
        code+=b"\x48\xba"+struct.pack("<Q",src)
        code+=b"\x41\xb8"+struct.pack("<I",n)
        code+=b"\xe8"+struct.pack("<i",target-(base+len(code)+5))
    code+=bytes.fromhex("4883c420")
    # Real x64 RET stubs. Synthetic CRT reference is independently modeled
    # in the Unicorn hook; no proprietary machine code is involved.
    windows=[(base,bytes(code))]+[(a,b"\xc3") for a in targets]
    return windows,base,base+len(code),[heap,heap+PAGE,HEAP_ARENA],targets

def owned_return_input(path):
    from tools.pe_probe import PE
    if hashlib.sha256(path.read_bytes()).hexdigest()!=SHA:raise ValueError("Wrong owned executable")
    pe=PE(path);base=pe.u64(pe.opt+24)
    if base!=0x140000000:raise ValueError("Unexpected image base")
    # Standalone actual local caller and complete leaf callee. This is
    # independently seeded, NOT a continuation across an unported function.
    spans=((0x28394a,0x283951),(0x2838e0,0x2838e7))
    return [(base+a,pe.read_rva(a,b-a)) for a,b in spans],base+0x28394a,base+0x283951

def owned_import_site(pe,base,slots,call_rva,kind,target):
    original_call=pe.read_rva(call_rva,5)
    if original_call[0]!=0xe8:raise ValueError("Expected original E8 CALL")
    ret=base+call_rva+5
    thunk=ret+struct.unpack_from("<i",original_call,1)[0]
    jump=pe.read_rva(thunk-base,6)
    if jump[:2]!=b"\xff\x25":raise ValueError("Expected original FF25 import thunk")
    slot=thunk+6+struct.unpack_from("<i",jump,2)[0]
    if slots.get(slot)!=("msvcr90.dll",kind):raise ValueError("Original import provenance mismatch")
    if slot%PAGE>PAGE-8:raise ValueError("Cross-page IAT slot")
    return [(thunk,jump),(target,b"\xc3")],slot,ret

def owned_crt_input(path,kind):
    from tools.pe_probe import PE
    from mxbikes_first_callee_emu import import_slots
    if hashlib.sha256(path.read_bytes()).hexdigest()!=SHA:raise ValueError("Wrong owned executable")
    pe=PE(path);base=pe.u64(pe.opt+24)
    if base!=0x140000000:raise ValueError("Unexpected image base")
    slots={base+r:(lib.lower(),symbol) for r,lib,symbol in import_slots(pe)}
    if kind=="heap-init":
        start,stop=0x28394a,0x283972
        windows=[(base+start,pe.read_rva(start,stop-start)),
                 (base+0x2838e0,pe.read_rva(0x2838e0,7))]
        imports={};iat={}
        for i,(site,name) in enumerate(((0x283956,"malloc"),(0x28396d,"memset"))):
            target=0x750000000+i*16
            pieces,slot,ret=owned_import_site(pe,base,slots,site,name,target)
            windows.extend(pieces);imports[target]=name;iat[slot]=(target,ret)
        pages=[HEAP_ARENA+i*PAGE for i in range(3)]
        return windows,base+start,base+stop,pages,imports,iat,(kind,9600)
    call_rva,n={"memcpy":(0x1599df,4),"memset":(0x15c1f2,296)}[kind]
    target=0x740000000
    pieces,slot,ret=owned_import_site(pe,base,slots,call_rva,kind,target)
    windows=[(base+call_rva,pe.read_rva(call_rva,5)),*pieces]
    return windows,base+call_rva,ret,[0x730000000,0x730001000],{target:kind},{slot:(target,ret)},(kind,n)

FILENAME_GLOBAL=0x1403968a0
FILENAME_CASES=(b"C:\\games\\mxbikes.exe",b"/tmp/mxbikes.exe",b"mixed\\dir/file.exe",
                b"mxbikes.exe",b"C:relative.exe",b"a:b:tail",b"",b"high"+bytes([128])+b"/dir/file.exe")
def owned_filename_input(path):
    from tools.pe_probe import PE
    if hashlib.sha256(path.read_bytes()).hexdigest()!=SHA:raise ValueError("Wrong owned executable")
    pe=PE(path);base=pe.u64(pe.opt+24)
    if base!=0x140000000:raise ValueError("Unexpected image base")
    from mxbikes_first_callee_emu import import_slots
    slots={base+r:(lib.lower(),symbol) for r,lib,symbol in import_slots(pe)}
    spans=((0x13675c,0x136769),(0x15b790,0x15b867))
    windows=[(base+a,pe.read_rva(a,b-a)) for a,b in spans]
    imports={};iat={}
    for i,(site,name) in enumerate(((0x15b7a5,"strcpy"),(0x15b827,"strrchr"))):
        target=0x750000000+i*16
        pieces,slot,ret=owned_import_site(pe,base,slots,site,name,target)
        windows.extend(pieces);imports[target]=name;iat[slot]=(target,ret)
    return windows,base+0x13675c,base+0x136769,[FILENAME_GLOBAL&~(PAGE-1)],imports,iat

def run(path=None,original_loop=False,imports_fixture=False,original_return=False,original_crt=None,original_image_data=False,split_modules=False,original_filename=False):
    if original_image_data and (not path or not original_loop):raise ValueError('Actual image data requires owned loop') 
    imports={};iat={};crt_case=None;alternate_stops=()
    if original_filename:
        if not path or original_loop or original_return or original_crt or imports_fixture or split_modules:raise ValueError('Owned filename fixture requires owned executable')
        windows,entry,stop,extra,imports,iat=owned_filename_input(path)
    elif original_crt:
        if not path or original_loop or original_return or imports_fixture:raise ValueError("Owned CRT fixture requires owned executable")
        windows,entry,stop,extra,imports,iat,crt_case=owned_crt_input(path,original_crt)
    elif imports_fixture:
        if path or original_loop or original_return:raise ValueError("Synthetic imports only")
        windows,entry,stop,extra,imports=imports_input()
    elif original_return:
        if not path or original_loop:raise ValueError("Original return requires owned executable")
        windows,entry,stop=owned_return_input(path);extra=[]
    elif original_loop:
        if not path:raise ValueError("Original loop requires owned executable")
        windows,entry,stop,extra=owned_loop_input(path)
    else:
        windows,entry,stop=owned_input(path) if path else synthetic_input()
        extra=[]
    code,static_pages,nodes=decode_cfg(windows,entry,stop,imports,iat,alternate_stops)
    if split_modules:
        if original_loop:split=0x140283945
        elif imports_fixture:split=stop-35  # final memmove setup, CALL and stack restoration
        else:raise ValueError("Split fixture requires owned loop or public CRT sequence")
        first,p1,n1=decode_cfg(windows,entry,split,imports,iat)
        second,p2,n2=decode_cfg(windows,split,stop,imports,iat)
        if n1&n2 or n1|n2!=nodes or sorted(set(p1+p2))!=static_pages:
            raise ValueError("Invalid translation unit partition")
        first=first.replace("lifted_begin","unit1_begin").replace("lifted_resume","unit1_resume")
        second=second.replace("lifted_begin","unit2_begin").replace("lifted_resume","unit2_resume")
        def arr(name,values):return "static const uint64_t %s[]={%s};"%(name,",".join(map(u,sorted(values))))
        registry=r"""
static const MXBNativeUnit units[]={
 {pcs1,sizeof(pcs1)/sizeof(pcs1[0]),unit1_resume},
 {pcs2,sizeof(pcs2)/sizeof(pcs2[0]),unit2_resume}
};
static const MXBNativeRegistry registry={units,2};
static Cursor lifted_begin(void){return unit1_begin();}
static int lifted_resume(State*s,Cursor*c,unsigned quota){
 return mxb_native_dispatch(&registry,s,c,quota,FINAL);
}
""".replace("FINAL",u(stop))
        code='#include "mxb_native_dispatch.h"\n'+first+second+arr("pcs1",n1)+arr("pcs2",n2)+registry
    pages=sorted(set(static_pages+[STACK]+extra))
    if len(pages)>16:raise ValueError("Data page budget")
    parts=[MEMORY_RUNTIME,EXTRA,code]
    native_pages={};reference_pages={};page_permissions={}
    if original_image_data:
        from mxbikes_pe_guest_owned_test import run as map_original_image
        native_pages,reference_pages,page_permissions=map_original_image(path,[p for p in pages if p!=STACK],False)
        # Private data is compiled only in temporary files. Never emit or log it.
        for i,p in enumerate(pages):
            if p in native_pages:
                parts.append("static const uint8_t image_page_%d[4096]={"%i)
                data=native_pages[p]
                for start in range(0,len(data),32):
                    parts.append(",".join(str(b) for b in data[start:start+32])+",")
                parts.append("};")
    parts.extend(["int smoke(void){","if(!mxb_guest_memory_smoke()||!mxb_guest_crt_smoke()||!mxb_pe_guest_smoke())return 95;"])
    lengths=[];covered=set();case_parts=[];endpoints=[];prefix_length=len(parts)
    for seed in range(1,9):
        case_start=len(parts)
        patches={RSP+0x140:FILENAME_CASES[seed-1]+bytes([0])} if original_filename else {}
        regs,flags,out,of,hashes,th,trace,endpoint=reference(windows,entry,stop,pages,nodes,seed,not path and not imports_fixture,imports,iat,crt_case,reference_pages,page_permissions,alternate_stops,patches,original_filename)
        endpoints.append(endpoint)
        lengths.append(len(trace));covered.update(trace)
        parts.append("{State s={0};uint8_t storage[%du*4096u];uint8_t *backing[sizeof(storage)/4096u];for(unsigned j=0;j<sizeof(storage)/4096u;j++)backing[j]=storage+j*4096u;Cursor cursor=lifted_begin();unsigned slices=0;"%len(pages))
        for i,v in enumerate(regs):parts.append("s.r[%d]=%s;"%(i,u(v)))
        parts.append("s.flags=%s;"%u(flags))
        for i,p in enumerate(pages):
            if p in native_pages:
                parts.append("__builtin_memcpy(backing[%d],image_page_%d,4096u);"%(i,i))
            else:parts.append("for(unsigned j=0;j<4096u;j++)backing[%d][j]=(uint8_t)(j*17u+%du+%s);"%(i,seed*31,u(p>>12)))
            for address,payload in patches.items():
                if address&~(PAGE-1)==p:
                    for k,b in enumerate(payload):parts.append('backing[%d][%d]=%du;'%(i,address-p+k,b))
            for slot,(target,_) in iat.items():
                if slot&~(PAGE-1)==p:
                    off=slot-p
                    for k,b in enumerate(struct.pack("<Q",target)):
                        parts.append("backing[%d][%d]=%du;"%(i,off+k,b))
            perm=1 if any(slot&~(PAGE-1)==p for slot in iat) else page_permissions.get(p,3)
            arena_size = 3*PAGE if original_crt=="heap-init" else PAGE if imports_fixture else 0
            if HEAP_ARENA<=p<HEAP_ARENA+arena_size:
                if p==HEAP_ARENA:
                    parts.append("if(!mxb_guest_heap_init(&s,%s,backing[%d],%du))return 96;"%(u(p),i,arena_size))
                continue
            parts.append("if(!mxb_guest_map(&s.memory,%s,backing[%d],4096u,%du))return 96;"%(u(p),i,perm))
        # Vary the pause interval, including very short boundaries inside calls.
        quota=1+seed*19
        parts.append("int rc;do{rc=lifted_resume(&s,&cursor,%du);slices++;if(slices>8193u)return 94;}while(rc==93);if(rc)return rc;"%quota)
        parts.append("if(cursor.pc!=%s||cursor.trace!=%s||cursor.steps!=%du)return 80;"%(u(endpoint),u(th),len(trace)))
        parts.append("if(slices!=%du)return 81;"%((len(trace)+quota-1)//quota))
        for i,v in enumerate(out):parts.append("if(s.r[%d]!=%s)return %d;"%(i,u(v),10+i))
        parts.append("if((s.flags&%s)!=%s)return 40;"%(u(CMP_FLAGS),u(of&CMP_FLAGS)))
        for i,h in enumerate(hashes):parts.append("if(hash_page(backing[%d])!=%s)return %d;"%(i,u(h),50+i))
        parts.append("}");case_parts.append(parts[case_start:])
    footer="return 0;}\n#ifdef HOST\nint main(void){return smoke();}\n#endif"
    parts.append(footer)
    if not path and not imports_fixture:
        # Bad decode targets must never compile into a purported native success.
        base=0x10000000
        rejected=[
            ([(base,bytes.fromhex("0f0b"))],base+2), # UD2
            ([(base,bytes.fromhex("eb7f"))],base+2), # unapproved jump
            ([(base,bytes.fromhex("ffe0"))],base+2), # indirect jmp
        ]
        for bad,frontier in rejected:
            try:decode_cfg(bad,base,frontier)
            except ValueError:pass
            else:raise ValueError("Unsupported instruction accepted")
        # An actual infinite guest loop must yield, then stop at the hard
        # cumulative instruction ceiling rather than spin forever.
        bad_code,_,_=decode_cfg([(base,bytes.fromhex("ebfe"))],base,base+2)
        negative=[MEMORY_RUNTIME,EXTRA,bad_code,
                  "int smoke(void){State s={0};Cursor c=lifted_begin();",
                  "if(lifted_resume(&s,&c,17u)!=93||c.steps!=17u)return 1;",
                  "if(lifted_resume(&s,&c,8192u)!=91||c.steps!=8192u){return 2;}",
                  "return 0;}",
                  "#ifdef HOST\nint main(void){return smoke();}\n#endif"]
        compile_native("\n".join(negative),RUNTIME_SOURCES)
    if original_filename and covered!=nodes:raise ValueError("Filename helper coverage incomplete")
    if original_loop and (min(lengths)<4000 or len(covered)!=len(nodes)):
        raise ValueError("Original loop coverage incomplete")
    if original_image_data:
        # Actual image-page seeds cost more instructions in the independent
        # AArch64 runner. Keep the existing hard ceiling per run, partition
        # the eight cases into two bounded four-case ELF executions.
        for start in range(0,len(case_parts),4):
            batch=parts[:prefix_length]+[line for case in case_parts[start:start+4] for line in case]+[footer]
            compile_native("\n".join(batch),RUNTIME_SOURCES,redact_diagnostics=True)
    else:compile_native("\n".join(parts),RUNTIME_SOURCES)
    print(json.dumps({"mode":"private_owned_original_filename" if original_filename else "private_owned_original_loop_actual_image_data" if original_image_data else "private_owned_original_crt_"+original_crt if original_crt else "public_synthetic_crt_calls" if imports_fixture else "private_owned_original_return" if original_return else "private_owned_original_loop" if original_loop else "private_owned_original_cfg" if path else "public_synthetic_cfg",
        "static_instructions":len(nodes)-len(imports),"modeled_import_nodes":len(imports),"original_iat_provenance":bool(iat),"covered_unique":len(covered),
        "dynamic_instructions_per_case":lengths,"cases":8,"complete_primary_returns":sum(e==stop for e in endpoints),"alternate_frontiers":sum(e!=stop for e in endpoints),
        "pc_trace_hash_and_length_matched":True,"resumable_instruction_batches":True,"persistent_guest_memory":True,"original_image_seed_pages":len(native_pages),"native_execution_batches":2 if original_image_data else 1,"independent_translation_units":2 if split_modules else 1,"registers":16,
        "bytes_hashed_per_case":len(pages)*PAGE,"host":"pass","arm64":"pass","ios_object":"pass",
        "original_game_booted":False},indent=2))

def emit_public_module(output):
    # Only the purpose-built synthetic program can be exported by this CLI.
    windows,entry,stop,_,imports=imports_input()
    code,_,_=decode_cfg(windows,entry,stop,imports)
    wrappers=r"""
MXBNativeCursor mxb_native_probe_begin(void){return lifted_begin();}
int mxb_native_probe_resume(MXBGuestState*s,MXBNativeCursor*c,unsigned quota){
 if(!s||!c||s->fault)return MXB_NATIVE_MEMORY_FAULT;
 return lifted_resume(s,c,quota);
}
"""
    output.write_text("/* Generated by mxbikes_native_cfg_lift.py --emit-module; synthetic only. */\n"+
                      MEMORY_RUNTIME+EXTRA+code+wrappers)

if __name__=="__main__":
    p=argparse.ArgumentParser();g=p.add_mutually_exclusive_group(required=True)
    g.add_argument("--source-only",action="store_true");g.add_argument("--owned-exe",type=Path)
    p.add_argument('--original-loop',action='store_true')
    p.add_argument('--imports-fixture',action='store_true')
    p.add_argument('--original-return',action='store_true')
    p.add_argument('--original-crt',choices=['memcpy','memset','heap-init'])
    p.add_argument('--original-image-data',action='store_true')
    p.add_argument('--split-modules',action='store_true')
    p.add_argument('--original-filename',action='store_true')
    p.add_argument('--emit-module',type=Path)
    args=p.parse_args()
    if args.emit_module:
        if not args.source_only or not args.imports_fixture or args.original_loop or args.original_return or args.original_crt or args.original_image_data or args.split_modules or args.original_filename:
            p.error('Only the public synthetic imports fixture can be emitted')
        emit_public_module(args.emit_module)
    else:run(args.owned_exe,args.original_loop,args.imports_fixture,args.original_return,args.original_crt,args.original_image_data,args.split_modules,args.original_filename)
