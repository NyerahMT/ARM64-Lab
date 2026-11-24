#!/usr/bin/env python3
"""Bounded CFG lifter: explicit guest PC, call stack, conditional paths and loops.

Supported local CPU operations only. No entitlement decisions, external imports,
indirect calls, guest code writes, or arbitrary host pointers. A private owned
binary is never copied to public outputs.
"""
from __future__ import annotations
import argparse, hashlib, json, sys
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
#ifndef HOST
void *memcpy(void *dst,const void *src,unsigned long n){
 volatile unsigned char*d=dst;const volatile unsigned char*s=src;
 for(unsigned long i=0;i<n;i++)d[i]=s[i];
 return dst;
}
#endif
"""
RUNTIME_SOURCES=("mxb_guest_memory.c",)
MAX_STATIC=512
MAX_DYNAMIC=8192
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
 uint64_t mask=width==32u?UINT64_C(0xffffffff):UINT64_MAX;
 a&=mask;b&=mask;uint64_t v=(a+b)&mask;
 s->flags=(s->flags&~UINT64_C(0x8d5))|common_flags(v,width)|
   (v<a?1u:0u)|((a^b^v)&0x10u)|(((~(a^b)&(a^v))>>(width-1u))&1u?0x800u:0u);
 return v;
}
static uint64_t logic_flags(State*s,uint64_t v,unsigned width){
 v&=width==32u?UINT64_C(0xffffffff):UINT64_MAX;
 s->flags=(s->flags&~UINT64_C(0x8c5))|common_flags(v,width);return v;
}
"""
def decode_cfg(windows,entry,stop):
    decoder=Cs(CS_ARCH_X86,CS_MODE_64);decoder.detail=True
    nodes={}; pages=set(); pending=[entry]; ranges=[(a,a+len(b)) for a,b in windows]
    def in_code(pc):return any(a<=pc<b for a,b in ranges)
    def reg(ins,op):
        name=ins.reg_name(op.reg)
        if name not in REG_INDEX:raise ValueError("Unsupported register "+name)
        idx,width=REG_INDEX[name]
        if op.size*8!=width:raise ValueError("Register width mismatch")
        return idx,width
    def addr(ins,op):
        m=op.mem
        if m.segment or m.index or not m.base:raise ValueError("Unsupported memory addressing")
        base=ins.reg_name(m.base)
        if base=="rip":
            a=(ins.address+ins.size+m.disp)&MASK
            if ins.mnemonic!="lea":
                if a%PAGE+op.size>PAGE:raise ValueError("Cross-page static data")
                pages.add(a&~(PAGE-1))
            return u(a)
        if base not in REGS:raise ValueError("Invalid base register")
        return "(s->r[%d]+%s)"%(REGS.index(base),u(m.disp))
    def read(ins,op):
        if op.type==CS_OP_REG:
            i,w=reg(ins,op);return "(s->r[%d]&%s)"%(i,u((1<<w)-1))
        if op.type==CS_OP_IMM:return u(op.imm)
        if op.type==CS_OP_MEM and op.size in (4,8):return "load(s,%s,%du)"%(addr(ins,op),op.size)
        raise ValueError("Unsupported source operand")
    def write(ins,op,v):
        if op.type==CS_OP_REG:
            i,w=reg(ins,op);return "s->r[%d]=(%s)&%s;"%(i,v,u((1<<w)-1))
        if op.type==CS_OP_MEM and op.size in (4,8):return "store(s,%s,%s,%du);"%(addr(ins,op),v,op.size)
        raise ValueError("Unsupported destination operand")
    while pending:
        pc=pending.pop()
        if pc==stop or pc in nodes:continue
        if len(nodes)>=MAX_STATIC:raise ValueError("Static budget exhausted")
        found=[(base,buf) for base,buf in windows if base<=pc<base+len(buf)]
        if len(found)!=1:raise ValueError("Unapproved direct target "+hex(pc))
        base,buf=found[0]
        ins=next(decoder.disasm(buf[pc-base:],pc,count=1),None)
        if ins is None:raise ValueError("Decode failed")
        if any(a<pc<b or pc<a<pc+ins.size for a,(_,b) in nodes.items()):
            raise ValueError("Overlapping instruction boundaries")
        op=ins.operands;mn=ins.mnemonic;nxt=pc+ins.size
        edges=[nxt];next_pc=u(nxt);stmt=""
        if mn=="mov" and len(op)==2:
            stmt=write(ins,op[0],read(ins,op[1]))
        elif mn=="lea" and len(op)==2 and op[0].type==CS_OP_REG and op[1].type==CS_OP_MEM:
            stmt=write(ins,op[0],addr(ins,op[1]))
        elif mn in ("xor","sub","add","and","or") and len(op)==2 and op[0].type==CS_OP_REG:
            _,width=reg(ins,op[0]);a=read(ins,op[0]);b=read(ins,op[1])
            v=("%s_flags(s,%s,%s,%du)"%(mn,a,b,width) if mn in ("xor","sub","add")
               else "logic_flags(s,%s%s%s,%du)"%(a,"&" if mn=="and" else "|",b,width))
            stmt=write(ins,op[0],v)
        elif mn in ("cmp","test") and len(op)==2 and op[0].size in (4,8):
            width=op[0].size*8;a=read(ins,op[0]);b=read(ins,op[1])
            stmt=("(void)sub_flags(s,%s,%s,%du);"%(a,b,width) if mn=="cmp"
                  else "(void)logic_flags(s,%s&%s,%du);"%(a,b,width))
        elif mn=="push" and len(op)==1 and op[0].type==CS_OP_REG and op[0].size==8:
            stmt="{uint64_t value=%s;s->r[4]-=8u;store(s,s->r[4],value,8u);}"%read(ins,op[0])
        elif mn=="pop" and len(op)==1 and op[0].type==CS_OP_REG and op[0].size==8 and reg(ins,op[0])[0]!=4:
            stmt=write(ins,op[0],"load(s,s->r[4],8u)")+"s->r[4]+=8u;"
        elif mn=="call" and len(op)==1 and op[0].type==CS_OP_IMM:
            target=op[0].imm
            stmt="s->r[4]-=8u;store(s,s->r[4],%s,8u);"%u(nxt)
            next_pc=u(target);edges=[target]
            if in_code(nxt) or nxt==stop:edges.append(nxt)
        elif mn=="ret" and not op:
            stmt="next=load(s,s->r[4],8u);s->r[4]+=8u;"
            next_pc="next";edges=[]
        elif mn=="jmp" and len(op)==1 and op[0].type==CS_OP_IMM:
            edges=[op[0].imm];next_pc=u(op[0].imm)
        elif mn in CONDS and len(op)==1 and op[0].type==CS_OP_IMM:
            edges=[nxt,op[0].imm]
            stmt="{unsigned c=(s->flags&1)!=0,p=(s->flags&4)!=0,z=(s->flags&0x40)!=0,sign=(s->flags&0x80)!=0,o=(s->flags&0x800)!=0;(void)c;(void)p;(void)z;(void)sign;(void)o;next=(%s)?%s:%s;}"%(CONDS[mn],u(op[0].imm),u(nxt))
            next_pc="next"
        elif mn=="nop":pass  # multi-byte NOP addressing operands are not dereferenced
        else:raise ValueError("Unsupported CFG instruction "+mn+" at "+hex(pc))
        nodes[pc]=(stmt+"if(s->fault)return 90;pc="+next_pc+";break;",nxt)
        pending.extend(edges)
    cases=["case "+u(pc)+":{"+stmt+"}" for pc,(stmt,_) in sorted(nodes.items())]
    c="""typedef struct {uint64_t pc,trace;unsigned steps;} Cursor;
static Cursor lifted_begin(void){
 Cursor c={ENTRY,UINT64_C(0xcbf29ce484222325),0};return c;
}
/* Pause only at original instruction boundaries. Caller-owned CPU and cursor
 * remain live across budgeted invocations; never reset register or stack state. */
static int lifted_resume(State*s,Cursor*c,unsigned quota){
 uint64_t pc=c->pc;
 while(pc!=STOP){
  if(c->steps>=8192u)return 91;
  if(!quota){c->pc=pc;return 93;}
  quota--;c->steps++;c->trace=(c->trace^pc)*UINT64_C(0x100000001b3);
  c->pc=pc;
  uint64_t next=0;(void)next;
  switch(pc){CASES default:return 92;}
  c->pc=pc;
 }
 return 0;
}
""".replace("ENTRY",u(entry)).replace("STOP",u(stop)).replace("CASES","\n".join(cases))
    return c,sorted(pages),set(nodes)

def synthetic_input():
    base=0x10000000
    # test ecx,ecx; jle stop; xor eax,eax; call helper; stop
    a=bytes.fromhex("85c9 7e07 31c0 e8f5000000")
    # helper: push rbx; mov ebx,ecx; add eax,ebx; sub ebx,1;
    # jne loop; pop rbx; ret. Both forward branches and repeated back edges.
    b=bytes.fromhex("53 89cb 01d8 83eb01 75f9 5b c3")
    return [(base,a),(base+0x100,b)],base,base+len(a)

def reference(windows,entry,stop,pages,nodes,seed,synthetic):
    regs,flags,data=initial(seed,pages)
    if synthetic:regs[1]=[0,1,2,3,5,8,0xffffffff,0x80000000][seed-1]
    cpu=Uc(UC_ARCH_X86,UC_MODE_64);mapped=set()
    for a,blob in windows:
        for p in range(a&~(PAGE-1),(a+len(blob)+PAGE-1)&~(PAGE-1),PAGE):
            if p not in mapped:cpu.mem_map(p,PAGE);mapped.add(p)
        cpu.mem_write(a,blob)
    if mapped.intersection(pages):raise ValueError("Code/data overlap")
    for p in pages:cpu.mem_map(p,PAGE);cpu.mem_write(p,data[p])
    for r,v in zip(UC_REG,regs):cpu.reg_write(r,v)
    cpu.reg_write(x.UC_X86_REG_EFLAGS,flags)
    trace=[]; invalid=[]
    def hook(uc,pc,size,ctx):
        if pc not in nodes:invalid.append(pc);uc.emu_stop();return
        trace.append(pc)
    cpu.hook_add(UC_HOOK_CODE,hook)
    cpu.emu_start(entry,stop,count=MAX_DYNAMIC,timeout=2_000_000)
    if invalid or cpu.reg_read(x.UC_X86_REG_RIP)!=stop:raise ValueError("Reference did not reach frontier")
    th=TRACE_INIT
    for pc in trace:th=((th^pc)*TRACE_PRIME)&MASK
    return regs,flags,[cpu.reg_read(r) for r in UC_REG],cpu.reg_read(x.UC_X86_REG_EFLAGS),[hash_page(cpu.mem_read(p,PAGE)) for p in pages],th,trace

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

def run(path=None,original_loop=False):
    if original_loop:
        if not path:raise ValueError("Original loop requires owned executable")
        windows,entry,stop,extra=owned_loop_input(path)
    else:
        windows,entry,stop=owned_input(path) if path else synthetic_input()
        extra=[]
    code,static_pages,nodes=decode_cfg(windows,entry,stop)
    pages=sorted(set(static_pages+[STACK]+extra))
    if len(pages)>16:raise ValueError("Data page budget")
    parts=[MEMORY_RUNTIME,EXTRA,code,"int smoke(void){","if(!mxb_guest_memory_smoke())return 95;"]
    lengths=[];covered=set()
    for seed in range(1,9):
        regs,flags,out,of,hashes,th,trace=reference(windows,entry,stop,pages,nodes,seed,not path)
        lengths.append(len(trace));covered.update(trace)
        parts.append("{State s={0};uint8_t backing[%du][4096];Cursor cursor=lifted_begin();unsigned slices=0;"%len(pages))
        for i,v in enumerate(regs):parts.append("s.r[%d]=%s;"%(i,u(v)))
        parts.append("s.flags=%s;"%u(flags))
        for i,p in enumerate(pages):
            parts.append("for(unsigned j=0;j<4096u;j++)backing[%d][j]=(uint8_t)(j*17u+%du+%s);"%(i,seed*31,u(p>>12)))
            parts.append("if(!mxb_guest_map(&s.memory,%s,backing[%d],4096u,3u))return 96;"%(u(p),i))
        # Vary the pause interval, including very short boundaries inside calls.
        quota=1+seed*19
        parts.append("int rc;do{rc=lifted_resume(&s,&cursor,%du);slices++;if(slices>8193u)return 94;}while(rc==93);if(rc)return rc;"%quota)
        parts.append("if(cursor.pc!=%s||cursor.trace!=%s||cursor.steps!=%du)return 80;"%(u(stop),u(th),len(trace)))
        parts.append("if(slices!=%du)return 81;"%((len(trace)+quota-1)//quota))
        for i,v in enumerate(out):parts.append("if(s.r[%d]!=%s)return %d;"%(i,u(v),10+i))
        parts.append("if((s.flags&%s)!=%s)return 40;"%(u(CMP_FLAGS),u(of&CMP_FLAGS)))
        for i,h in enumerate(hashes):parts.append("if(hash_page(backing[%d])!=%s)return %d;"%(i,u(h),50+i))
        parts.append("}")
    parts.append("return 0;}\n#ifdef HOST\nint main(void){return smoke();}\n#endif")
    if not path:
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
    if original_loop and (min(lengths)<4000 or len(covered)!=len(nodes)):
        raise ValueError("Original loop coverage incomplete")
    compile_native("\n".join(parts),RUNTIME_SOURCES)
    print(json.dumps({"mode":"private_owned_original_loop" if original_loop else "private_owned_original_cfg" if path else "public_synthetic_cfg",
        "static_instructions":len(nodes),"covered_unique":len(covered),
        "dynamic_instructions_per_case":lengths,"cases":8,
        "pc_trace_hash_and_length_matched":True,"resumable_instruction_batches":True,"persistent_guest_memory":True,"registers":16,
        "bytes_hashed_per_case":len(pages)*PAGE,"host":"pass","arm64":"pass","ios_object":"pass",
        "original_game_booted":False},indent=2))

if __name__=="__main__":
    p=argparse.ArgumentParser();g=p.add_mutually_exclusive_group(required=True)
    g.add_argument("--source-only",action="store_true");g.add_argument("--owned-exe",type=Path)
    p.add_argument('--original-loop',action='store_true')
    args=p.parse_args();run(args.owned_exe,args.original_loop)
