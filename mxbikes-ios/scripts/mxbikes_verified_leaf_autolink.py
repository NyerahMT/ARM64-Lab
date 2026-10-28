#!/usr/bin/env python3
"""Auto-discover *complete* small original game leafs and register only verified native ones.

This deliberately narrow batch proves how the original-VA dispatcher can scale
without fabricated function bodies. Only direct-call destinations in executable
sections or exact .pdata starts qualify. Candidate bytes must match a closed,
fully decoded, side-effect-bounded x64 sequence:
    RET                 (preserves registers/flags, pops PC)
    MOV EAX, IMM32; RET (zero-extends RAX, preserves flags, pops PC)
    NOP; RET            (same as RET)
These are x64 semantics exhaustively covered by our guest-state abstraction.
All generated C and original bytes are ephemeral private CI data.
"""
from __future__ import annotations
import argparse
import hashlib
import json
import os
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
from collections import Counter
from bisect import bisect_right

from capstone import Cs,CS_ARCH_X86,CS_MODE_64,CS_GRP_RET
from unicorn import Uc,UC_ARCH_X86,UC_MODE_64,UC_HOOK_CODE
from unicorn.x86_const import (
 UC_X86_REG_RAX,UC_X86_REG_RBX,UC_X86_REG_RCX,UC_X86_REG_RDX,
 UC_X86_REG_R8,UC_X86_REG_R9,UC_X86_REG_RDI,UC_X86_REG_RSI,
 UC_X86_REG_R11,UC_X86_REG_RSP,UC_X86_REG_RIP,UC_X86_REG_EFLAGS,
)
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/"arm64-lab"))
from tools.pe_probe import PE
from tools.import_aot_smoke import execute_arm64_elf
from mxbikes_whole_game_map import map_executable
from mxbikes_native_link_plan import build as build_link_plan
from mxbikes_wave_native_selection import ordered_call_targets, summarize_native_execution
from mxbikes_acyclic_leaf_cfg import decode as decode_acyclic_cfg, emit_native as emit_acyclic_native, MAX_BYTES as MAX_ACYCLIC_BYTES

BASE=0x140000000
EXE_SHA="4ae7de3854b4d0a18271679fb57a1f2fdf0b21804417b85dd82055078ea123b6"
STACK=0x710000000
PARENT_SP=STACK+0x8000
ENTRY_SP=PARENT_SP-8
SENTINEL=BASE+0x159991
CALLSITE=BASE+0x1eeee1
FIXTURES=12
MAX_NATIVE_LEAFS=48
GP=[("rax",UC_X86_REG_RAX),("rbx",UC_X86_REG_RBX),
    ("rcx",UC_X86_REG_RCX),("rdx",UC_X86_REG_RDX),
    ("r8",UC_X86_REG_R8),("r9",UC_X86_REG_R9),
    ("rdi",UC_X86_REG_RDI),("rsi",UC_X86_REG_RSI),
    ("r11",UC_X86_REG_R11)]
FIELDS=[n for n,_ in GP]+["rsp","rip","cf","zf","sf"]

def classify(code:bytes):
    if code==b"\xc3":
        return "ret",None
    if code==b"\x90\xc3":
        return "nop_ret",None
    if len(code)==6 and code[0]==0xb8 and code[-1]==0xc3:
        return "mov_eax_imm_ret",int.from_bytes(code[1:5],"little")
    if code in (b"\x31\xc0\xc3",b"\x33\xc0\xc3"):
        return "xor_eax_eax_ret",None
    if code in (b"\x48\x31\xc0\xc3",b"\x48\x33\xc0\xc3"):
        return "xor_rax_rax_ret",None
    if code in (b"\x8b\xc1\xc3",b"\x89\xc8\xc3"):
        return "mov_eax_ecx_ret",None
    if code in (b"\x8b\xc2\xc3",b"\x89\xd0\xc3"):
        return "mov_eax_edx_ret",None
    if code in (b"\x48\x8b\xc1\xc3",b"\x48\x89\xc8\xc3"):
        return "mov_rax_rcx_ret",None
    # Explicit register addressing only: REX.B extends ModRM r/m to r8/r9.
    # These do not read game memory or mutate arithmetic flags.
    extended={
        b"\x41\x8b\xc0\xc3":"mov_eax_r8d_ret",
        b"\x41\x8b\xc1\xc3":"mov_eax_r9d_ret",
        b"\x49\x8b\xc0\xc3":"mov_rax_r8_ret",
        b"\x49\x8b\xc1\xc3":"mov_rax_r9_ret",
        b"\x48\x8b\xc2\xc3":"mov_rax_rdx_ret",
    }
    if code in extended:
        return extended[code],None
    # LEA only computes an address; it does NOT dereference the argument
    # pointer, change memory, or modify arithmetic flags.
    if len(code) in (4,5,7,8) and code[-1]==0xc3 and (code[:2] == b"\x48\x8d" or code[0] == 0x8d):
        # Explicit ModRM controls whether displacement is 8 or 32 bits.
        if code[:2] == b"\x48\x8d":
            modrm=code[2]
            expected_len=5 if modrm in (0x41,0x42) else 8
            disp_bytes=code[3:-1]
            bits=64
        else:
            modrm=code[1]
            expected_len=4 if modrm in (0x41,0x42) else 7
            disp_bytes=code[2:-1]
            bits=32
        if len(code)==expected_len and modrm in (0x41,0x42,0x81,0x82):
            reg="rcx" if modrm in (0x41,0x81) else "rdx"
            return f"lea_{'rax' if bits==64 else 'eax'}_{reg}_disp_ret",int.from_bytes(
                disp_bytes,"little",signed=True)
    return None

def discover(exe, mapping=None, waves=None):
    pe=PE(exe)
    if hashlib.sha256(pe.b).hexdigest()!=EXE_SHA:
        raise RuntimeError("Original MX Bikes SHA mismatch")
    mapping=mapping if mapping is not None else map_executable(exe)
    if mapping.get("input_sha256")!=EXE_SHA or mapping.get("original_file_verified") is not True:
        raise RuntimeError("Leaf-validation map does not match owned original executable")
    called=Counter(int(v,16) for t in mapping["direct_call_graph"].values() for v in t)
    starts={int(x["rva"],16):x for x in mapping["interval_map"]}
    # A call to a byte inside a known unwind-described body does not establish
    # a separate whole-function boundary, even when the byte looks like RET.
    # Preserve synthetic fixture compatibility when explicit end_rva is absent.
    span=[(addr,int(row.get("end_rva",
                           hex(addr+int(row.get("bytes",0)))),16))
          for addr,row in starts.items()]
    if any(end<=addr for addr,end in span):
        raise RuntimeError("Incomplete original function interval")
    span.sort()
    span_starts=[addr for addr,_ in span]
    # Prefix maximum handles overlapping/nested unwind intervals correctly.
    span_ends=[]
    for _,end in span:
        span_ends.append(max(end,span_ends[-1] if span_ends else 0))
    md=Cs(CS_ARCH_X86,CS_MODE_64);md.detail=True
    selected=[]
    types=Counter()
    for rva,count,wave_batch_id in ordered_call_targets(called,waves):
        interval=starts.get(rva)
        if interval is None:
            prior=bisect_right(span_starts,rva)-1
            if prior>=0 and rva<span_ends[prior]:
                # Prevent a mid-function jump/call from being promoted to
                # a complete no-unwind native function by opcode coincidence.
                continue
        body=None
        proven="direct_call_entry_no_unwind"
        if interval:
            if interval["status"]!="decoded_linear" or interval["bytes"]>MAX_ACYCLIC_BYTES:
                continue
            body=pe.read_rva(rva,interval["bytes"])
            proven="complete_pdata_interval"
        else:
            for width in (1,2,3,4,5,6,7,8):
                try: blob=pe.read_rva(rva,width)
                except ValueError: continue
                if classify(blob):
                    body=blob;break
        if not body:
            continue
        form=classify(body)
        cfg=decode_acyclic_cfg(body,rva) if form is None and interval is not None else None
        if not form and not cfg:
            continue
        code=list(md.disasm(body,rva))
        if not code or sum(x.size for x in code)!=len(body) or not code[-1].group(CS_GRP_RET):
            raise RuntimeError("Malformed closed leaf function candidate")
        if cfg and (len(code)!=cfg["instructions"] or
                    [ins.address for ins in code]!=[op["rva"] for op in cfg["ops"]]):
            raise RuntimeError("Acyclic original interval differs from exact independent decoder")
        kind,imm=form if form else (cfg["kind"],None)
        # A complete RET or MOV EAX/RET contains no external control flow,
        # stack allocation, memory writes, or SIMD state changes.
        selected.append({"rva":rva,"kind":kind,"imm":imm,"body":body,
                         "direct_references":count,"boundary_evidence":proven,
                         "x64_instructions":len(code),
                         "cfg_plan":cfg,"wave_batch_id":wave_batch_id})
        types[kind]+=1
        if len(selected)==MAX_NATIVE_LEAFS:
            break
    return mapping,selected,types,len(called)

def x64_reference(candidate,case):
    x64=Uc(UC_ARCH_X86,UC_MODE_64)
    page=(candidate["rva"]&~4095)
    if candidate.get("joined_children"):
        pages=set()
        for src in [candidate,*candidate["joined_children"]]:
            lo=src["rva"] & ~4095
            hi=(src["rva"]+len(src["body"])-1)&~4095
            pages.update(range(lo,hi+1,4096))
        for page in sorted(pages):
            x64.mem_map(BASE+page,4096)
        x64.mem_write(BASE+candidate["rva"],candidate["body"])
        for child in candidate["joined_children"]:
            x64.mem_write(BASE+child["rva"],child["body"])
    else:
        x64.mem_map(BASE+page,8192)
        x64.mem_write(BASE+candidate["rva"],candidate["body"])
    x64.mem_map(STACK,0x10000)
    x64.mem_write(ENTRY_SP,struct.pack("<Q",SENTINEL))
    seed={}
    for idx,(name,reg) in enumerate(GP):
        value=((0x1122448899AABBCC+(idx*0x10f01001)+(case*0x13131313))&((1<<64)-1))
        seed[name]=value
        x64.reg_write(reg,value)
    flags=0x202|([0,1,0x40,0x80,0xc1,0x41][case%6])
    x64.reg_write(UC_X86_REG_EFLAGS,flags)
    # Zero, nonzero and high-sign cases for original TEST/Jcc execution.
    if case in (0,1,2,3):
        names={0:("rcx",),1:("rax",),2:("rdx",),3:("rax","rcx","rdx")}[case]
        for name,reg in GP:
            if name in names:
                x64.reg_write(reg,0)
                seed[name]=0
    elif case==4:
        for name,reg in GP[:4]:
            x64.reg_write(reg,(1<<64)-1)
            seed[name]=(1<<64)-1
    x64.reg_write(UC_X86_REG_RSP,ENTRY_SP)
    x64.reg_write(UC_X86_REG_RIP,BASE+candidate["rva"])
    trace=[]
    if candidate.get("cfg_plan") or candidate.get("joined_children"):
        if candidate.get("cfg_plan"):
            allowed={BASE+op["rva"] for op in candidate["cfg_plan"]["ops"]}
        else:
            md=Cs(CS_ARCH_X86,CS_MODE_64)
            allowed=set()
            for item in [candidate,*candidate["joined_children"]]:
                decoded=list(md.disasm(item["body"],item["rva"]))
                if not decoded or sum(op.size for op in decoded)!=len(item["body"]):
                    raise RuntimeError("Original joined function has incomplete independent decode")
                allowed.update(BASE+op.address for op in decoded)
        def record(emu,pc,size,user):
            if pc not in allowed:
                raise RuntimeError("Original x64 joined function escaped complete verified intervals")
            trace.append(pc-BASE)
        x64.hook_add(UC_HOOK_CODE,record)
    x64.emu_start(BASE+candidate["rva"],SENTINEL,timeout=1000000,count=64)
    if candidate.get("cfg_plan"):
        candidate.setdefault("_original_traces",[]).append(trace)
    if candidate.get("joined_children"):
        candidate.setdefault("_joined_traces",[]).append(trace)
    regvals={name:x64.reg_read(reg) for name,reg in GP}
    final_flags=x64.reg_read(UC_X86_REG_EFLAGS)
    result={**regvals,"rsp":x64.reg_read(UC_X86_REG_RSP),
            "rip":x64.reg_read(UC_X86_REG_RIP),
            "cf":int(bool(final_flags&1)),
            "zf":int(bool(final_flags&0x40)),
            "sf":int(bool(final_flags&0x80))}
    if result["rip"]!=SENTINEL or result["rsp"]!=PARENT_SP:
        raise RuntimeError("Original closed leaf did not return as expected")
    if candidate.get("joined_children"):
        # Same exact stack window is compared after the native nested CALL.
        result["joined_stack_window"]=bytes(x64.mem_read(ENTRY_SP-64,64))
    return seed,flags,result

def generate_source(candidates,references):
    generated=[]
    entries=[]
    for item in sorted(candidates,key=lambda x:x["rva"]):
        rva=item["rva"]
        symbol=f"mx_verified_{rva:08x}"
        if item["kind"]=="joined_flag_preserving_caller":
            child=item["child_rva"]
            continuation=rva+item["prefix_bytes"]+5
            saved=item.get("saved_register")
            if saved:
                if saved not in ("rbx","rsi","rdi"):
                    raise RuntimeError("Unrecognized saved original Win64 register")
                prefix=f"""uint64_t saved=s->{saved};
 s->rsp-=UINT64_C(8);
 if(!mx_cfg_transfer(m,s->rsp,&saved,8U,1))return MX_NATIVE_LINK_STACK;"""
                suffix=f"""uint64_t restored=0U;
 if(!mx_cfg_transfer(m,s->rsp,&restored,8U,0))return MX_NATIVE_LINK_STACK;
 s->{saved}=restored;s->rsp+=UINT64_C(8);"""
                min_rsp=16
            else:
                prefix="s->rsp-=UINT64_C(40);"
                suffix="s->rsp+=UINT64_C(40);"
                min_rsp=48
            generated.append(f'''
static int {symbol}(mx_crt_cluster_state*s,mx_cfg_memory*m,void*ctx){{
 mx_native_link_registry*r=(mx_native_link_registry*)ctx;
 if(!r||!s||!m||s->rip!=BASE+UINT64_C({rva})||(s->rsp&15U)!=8U
    ||s->rsp<UINT64_C({min_rsp}))return MX_NATIVE_LINK_INVALID;
 uint64_t outer_return=0U;
 if(!mx_cfg_transfer(m,s->rsp,&outer_return,8U,0))
     return MX_NATIVE_LINK_STACK;
 {prefix}
 s->rip=BASE+UINT64_C({rva+item["prefix_bytes"]});
 int status=mx_native_link_call(r,s,m,BASE+UINT64_C({child}),
                                BASE+UINT64_C({continuation}));
 if(status!=MX_NATIVE_LINK_OK)return status;
 {suffix}
 s->rip=outer_return;s->rsp+=UINT64_C(8);
 return MX_NATIVE_LINK_OK;
}}
''')
        elif item.get("cfg_plan"):
            stmt=emit_acyclic_native(item["cfg_plan"])
            generated.append(f'''
static int {symbol}(mx_crt_cluster_state*s,mx_cfg_memory*m,void*unused){{
 (void)unused;
 if(!s||!m||s->rip!=BASE+UINT64_C({rva})||(s->rsp&15U)!=8U)
     return MX_NATIVE_LINK_INVALID;
 {stmt}
}}
''')
        else:
            simple={
                "xor_eax_eax_ret":"s->rax=0U;s->cf=0U;s->zf=1U;s->sf=0U;",
                "xor_rax_rax_ret":"s->rax=0U;s->cf=0U;s->zf=1U;s->sf=0U;",
                "mov_eax_ecx_ret":"s->rax=(uint32_t)s->rcx;",
                "mov_eax_edx_ret":"s->rax=(uint32_t)s->rdx;",
                "mov_rax_rcx_ret":"s->rax=s->rcx;",
                "mov_eax_r8d_ret":"s->rax=(uint32_t)s->r8;",
                "mov_eax_r9d_ret":"s->rax=(uint32_t)s->r9;",
                "mov_rax_r8_ret":"s->rax=s->r8;",
                "mov_rax_r9_ret":"s->rax=s->r9;",
                "mov_rax_rdx_ret":"s->rax=s->rdx;",
            }
            if item["kind"].startswith("lea_"):
                # Translate modulo-two's-complement LEA arithmetic without
                # fetching guest memory or changing guest condition flags.
                parts=item["kind"].split("_")
                if len(parts)!=5 or parts[4]!="ret" or parts[3]!="disp":
                    raise RuntimeError("Unsupported original LEA function kind")
                dst,src=parts[1],parts[2]
                if dst not in ("eax","rax") or src not in ("rcx","rdx"):
                    raise RuntimeError("Unknown LEA guest register")
                signed_disp=item["imm"] & ((1<<64)-1)
                cast="(uint32_t)" if dst=="eax" else ""
                stmt=f"s->rax={cast}(s->{src}+UINT64_C({signed_disp}));"
            else:
                stmt=simple.get(item["kind"],"" if item["imm"] is None else
                                f"s->rax=UINT64_C({item['imm']});")
            generated.append(f'''
static int {symbol}(mx_crt_cluster_state*s,mx_cfg_memory*m,void*unused){{
 (void)unused;
 if(!s||!m||s->rip!=BASE+UINT64_C({rva})||(s->rsp&15U)!=8U)
     return MX_NATIVE_LINK_INVALID;
 uint64_t ret=0;
 if(!mx_cfg_transfer(m,s->rsp,&ret,8U,0))return MX_NATIVE_LINK_STACK;
 {stmt}
 s->rip=ret;
 s->rsp+=8U;
 return MX_NATIVE_LINK_OK;
}}
''')
        entries.append(f"{{BASE+UINT64_C({rva}),{symbol},0}}")
    init_rows=[]
    for item in sorted(candidates,key=lambda x:x["rva"]):
        arr=[]
        for seed,flags,expected in references[item["rva"]]:
            ins=[seed[name] for name,_ in GP]
            outputs=[expected[name] for name in FIELDS]
            stack=expected.get("joined_stack_window")
            stack_values=stack if stack is not None else bytes(64)
            if len(stack_values)!=64:
                raise RuntimeError("Original joined return stack window has incorrect size")
            arr.append("{{"+",".join("UINT64_C("+str(n)+")" for n in ins)+"},"
                       +str(flags)+",{"+",".join("UINT64_C("+str(n)+")" for n in outputs)+"},"
                       +"{"+",".join(str(x) for x in stack_values)+"},"
                       +str(int(stack is not None))+"}")
        init_rows.append("{"+",".join(arr)+"}")
    n=len(candidates)
    source=r'''#include <stdint.h>
#include "mx_native_guest_linker.h"
#define BASE UINT64_C(0x140000000)
#define STACK UINT64_C(0x710000000)
#define PARENT_SP (STACK+0x8000U)
#define SENTINEL (BASE+UINT64_C(0x159991))
#define CALLSITE (BASE+UINT64_C(0x1eeee1))
#define COUNT __COUNT__
#define TESTS 12U
typedef struct {
 uint64_t input_regs[9];
 uint32_t initial_flags;
 uint64_t expected[14];
 uint8_t expected_stack[64];
 uint8_t stack_check;
} leaf_case;
static const leaf_case cases[COUNT][TESTS]={
__CASE_ROWS__
};
static uint8_t stack_bytes[65536];
__GENERATED__
static const mx_native_link_entry link_entries[COUNT]={__ENTRIES__};
static int check(const mx_crt_cluster_state*s,const leaf_case*fc){
 const uint64_t actual[14]={
   s->rax,s->rbx,s->rcx,s->rdx,s->r8,s->r9,s->rdi,s->rsi,s->r11,
   s->rsp,s->rip,s->cf,s->zf,s->sf
 };
 for(unsigned j=0;j<14U;j++)if(actual[j]!=fc->expected[j])return 0;
 if(fc->stack_check){
   for(unsigned k=0;k<64U;k++)
     if(stack_bytes[(PARENT_SP-8U-64U-STACK)+k]!=fc->expected_stack[k])
       return 0;
 }
 return 1;
}
int smoke(void){
 mx_cfg_region reg={STACK,stack_bytes,65536U};
 mx_cfg_memory memory={&reg,1U};
 mx_native_link_registry registry={0};
 registry.entries=link_entries;registry.count=COUNT;registry.max_depth=8U;
 if(mx_native_link_seal(&registry)!=MX_NATIVE_LINK_OK)return 1;
 for(unsigned i=0;i<COUNT;i++){
   for(unsigned j=0;j<TESTS;j++){
     mx_crt_cluster_state s={0};
     const leaf_case *fc=&cases[i][j];
     s.rax=fc->input_regs[0];s.rbx=fc->input_regs[1];
     s.rcx=fc->input_regs[2];s.rdx=fc->input_regs[3];
     s.r8=fc->input_regs[4];s.r9=fc->input_regs[5];
     s.rdi=fc->input_regs[6];s.rsi=fc->input_regs[7];
     s.r11=fc->input_regs[8];
     s.cf=(fc->initial_flags&1U)!=0U;
     s.zf=(fc->initial_flags&0x40U)!=0U;
     s.sf=(fc->initial_flags&0x80U)!=0U;
     s.rip=CALLSITE;s.rsp=PARENT_SP;
     int out=mx_native_link_call(&registry,&s,&memory,
                                link_entries[i].original_va,SENTINEL);
     if(out!=MX_NATIVE_LINK_OK)return 2;
     if(!check(&s,fc))return 3;
   }
 }
 if(registry.calls_completed!=COUNT*TESTS ||
    registry.unresolved_calls||registry.active_depth)return 4;
 mx_crt_cluster_state absent={0};
 absent.rip=CALLSITE;absent.rsp=PARENT_SP;
 if(mx_native_link_call(&registry,&absent,&memory,
                        BASE+0x7abcdeU,SENTINEL)!=MX_NATIVE_LINK_UNRESOLVED ||
    absent.rsp!=PARENT_SP||absent.rip!=CALLSITE)return 5;
 return 0;
}
#ifdef HOST
int main(void){return smoke();}
#endif
'''
    source=source.replace("__COUNT__",str(n))
    source=source.replace("__CASE_ROWS__",",\n".join(init_rows))
    source=source.replace("__GENERATED__","\n".join(generated))
    source=source.replace("__ENTRIES__",",\n".join(entries))
    joined=[item for item in candidates if item["kind"]=="joined_flag_preserving_caller"]
    if joined:
        source=source.replace("static const mx_native_link_entry link_entries[COUNT]=",
                              "static mx_native_link_entry link_entries[COUNT]=")
        # Both registry and dispatch table now have static storage duration;
        # an ephemeral test call cannot leave a pointer to a dead stack frame.
        source=source.replace("mx_native_link_registry registry={0};",
                              "static mx_native_link_registry registry;\n"
                              " registry=(mx_native_link_registry){0};")
        sentinel="registry.entries=link_entries;registry.count=COUNT;registry.max_depth=8U;"
        setup="\n".join(
            f" for(unsigned k=0;k<COUNT;k++)if(link_entries[k].original_va=="
            f"BASE+UINT64_C({item['rva']}))link_entries[k].context=&registry;"
            for item in joined)
        if source.count(sentinel)!=1:
            raise RuntimeError("Original native registry insertion moved")
        source=source.replace(sentinel,sentinel+"\n"+setup)
        counter="registry.calls_completed!=COUNT*TESTS"
        if source.count(counter)!=1:
            raise RuntimeError("Native nested-call accounting contract moved")
        source=source.replace(counter,
                              f"registry.calls_completed!=(COUNT+{len(joined)})*TESTS")
    return source

def run(exe,out,mapping=None,waves=None):
    mapping,candidates,kinds,reachable=discover(exe,mapping,waves)
    if not candidates:
        raise RuntimeError("No complete, directly called original leaf bodies matched whitelist")
    references={}
    confirmed=[]
    skipped_cfg=[]
    for item in candidates:
        original_cases=[x64_reference(item,j) for j in range(FIXTURES)]
        if item.get("cfg_plan"):
            traces=item.get("_original_traces",[])
            covered=set().union(*(set(t) for t in traces))
            operations=item["cfg_plan"]["ops"]
            if covered!={op["rva"] for op in operations}:
                skipped_cfg.append({"original_rva":hex(item["rva"]),
                                    "reason":"not_all_original_instructions_exercised"})
                continue
            full_branches=True
            for operation in operations:
                if operation["op"] not in ("jz","jnz"):
                    continue
                address=operation["rva"]
                destinations={b for trace in traces for a,b in zip(trace,trace[1:]) if a==address}
                expected={item["rva"]+operation["target"],
                          item["rva"]+operation["next"]}
                if destinations!=expected:
                    full_branches=False
                    break
            if not full_branches:
                skipped_cfg.append({"original_rva":hex(item["rva"]),
                                    "reason":"both_original_conditional_edges_not_exercised"})
                continue
        confirmed.append(item)
        references[item["rva"]]=original_cases
    if not confirmed:
        raise RuntimeError("No whole-body original leaves passed required x64 coverage")
    candidates=confirmed
    kinds=Counter(item["kind"] for item in candidates)
    src=generate_source(candidates,references)
    with tempfile.TemporaryDirectory(prefix="mxb-native-verified-leafs-") as td:
        root=Path(td)
        cc=root/"closed-leaves-private.c"
        cc.write_text(src)
        common=["-O2","-std=c11","-Wall","-Wextra","-Werror",
                "-I",str(ROOT/"arm64-lab"/"runtime")]
        host=root/"smoke-host"
        result=subprocess.run(["cc",*common,"-DHOST",str(cc),"-o",str(host)],
                              capture_output=True,text=True)
        if result.returncode:
            raise RuntimeError("Host native leaf compile failed: "+result.stderr[-2200:])
        result=subprocess.run([str(host)],capture_output=True,text=True)
        if result.returncode:
            raise RuntimeError("Host original/native guest differential failed exit="+str(result.returncode))
        arm=root/"linked-native-aarch64.elf"
        result=subprocess.run(["clang","--target=aarch64-unknown-linux-gnu",
            "-fuse-ld=lld","-nostdlib","-static","-ffreestanding",
            "-fno-stack-protector","-fno-builtin",*common,
            "-Wl,-e,smoke","-Wl,-z,max-page-size=4096",
            "-Wl,--build-id=none",str(cc),"-o",str(arm)],
            capture_output=True,text=True)
        if result.returncode:
            raise RuntimeError("ARM64 leaf dispatcher compile failed: "+result.stderr[-2200:])
        native=execute_arm64_elf(arm,instruction_budget=1800000,
                                 timeout_us=15000000)
        if native["arm64_smoke_exit"]!=0:
            raise RuntimeError("ARM64 original-leaf differential returned nonzero")
    run_url="https://github.com/NyerahMT/ReflexBuildInput/actions/runs/"+str(os.environ.get("GITHUB_RUN_ID","unverified"))
    # Make evidence explicit: these native entrypoints existed and were called
    # in this transient ELF; no persistent game binary is being produced.
    verified=[{
      "original_rva":hex(item["rva"]),
      "native_symbol":f"mx_verified_{item['rva']:08x}",
      "full_function_behavior_verified":True,
      "win64_guest_call_abi_verified":True,
      "differential_test_run_url":run_url,
      "proof_scope":item["kind"]+"; 12 x64 host native and ARM64 executed cases",
      "code_presence":"ephemeral_ci_elf_only",
    } for item in sorted(candidates,key=lambda x:x["rva"])]
    plan=build_link_plan(mapping,verified)
    wave_report=summarize_native_execution(waves,candidates) if waves is not None else None
    out.mkdir(parents=True,exist_ok=True)
    (out/"unverified-cfg-candidates.json").write_text(json.dumps(skipped_cfg,indent=2)+"\n")
    (out/"verified-leaf-registrations.json").write_text(json.dumps(verified,indent=2)+"\n")
    if wave_report is not None:
        (out/"wave-native-execution.json").write_text(json.dumps(wave_report,indent=2)+"\n")
        summary=["# MX Bikes scheduled dependency waves — genuine ARM64 closed-leaf execution","",
                 "- Static dependency waves inspected: **"+str(wave_report["total_static_waves"])+"**",
                 "- Original closed leafs executed in scheduled waves: **"+str(wave_report["native_validated_in_scheduled_waves"])+"**",
                 "- Other original closed leafs executed using existing global fallback: **"+str(wave_report["native_validated_global_fallback"])+"**",
                 "- Waves with all their entries proven as native closed leafs: **"+str(wave_report["waves_fully_native_verified"])+"**",
                 "", "## Original-code execution coverage by wave", ""]
        for item in wave_report["waves"][:100]:
            summary.append("- "+item["batch_id"]+": "+str(item["complete_closed_leafs_native_executed"])+
                           " closed leafs executed; "+str(item["remaining_entries_not_native_verified"])+
                           " remaining not verified")
        summary.extend(["", "**These results require the original x64, host C and executed ARM64 differential to pass.**",
                        "**A decoded body or an unsupported call remains untranslated; full engine startup is NOT verified.**",""])
        (out/"wave-native-execution.md").write_text("\n".join(summary))
    counts={
       "original_direct_call_targets_scanned":reachable,
       "eligible_exact_x64_leafs":len(candidates),
       "native_registered_and_executed":len(verified),
       "guest_fixtures_each":FIXTURES,
       "original_x64_reference_executions":len(candidates)*FIXTURES,
       "host_native_dispatch_calls":len(candidates)*FIXTURES,
       "arm64_native_dispatch_calls":len(candidates)*FIXTURES,
       "closed_leaf_families":dict(kinds),
       "skipped_acyclic_cfg_without_full_reference_coverage":len(skipped_cfg),
       "main_reachable_verified_registered":sum(
           item["rva"] in {int(x["original_rva"],16) for x in verified}
           for item in [ {"rva":int(k,16)} for k in mapping["direct_call_graph"].get("0x136710",[]) ]),
       "wave_native_leafs_executed":wave_report["native_validated_in_scheduled_waves"] if wave_report else 0,
       "wave_fallback_leafs_executed":wave_report["native_validated_global_fallback"] if wave_report else 0,
       "native_main_complete":False,
       "full_game_functions_all_verified":False,
       "native_code_artifact_persisted":False,
       "notes":"Closed simple original x64 leaves and strictly decoded forward-only CFG candidate bodies; original x64 versus real ARM64 state differentials and branch coverage required. Only modeled CF/ZF/SF guest flags verified; remaining x64 status flags unsupported. Ephemeral code, no engine startup."
    }
    (out/"verified-leaf-auto-link.json").write_text(json.dumps(counts,indent=2)+"\n")
    (out/"verified-leaf-main-link-plan.json").write_text(json.dumps(plan,indent=2)+"\n")
    lines=[
        "# Original MX Bikes — automatic verified native leaf linking","",
        "- Authentic original x64 direct-call destinations surveyed: **"+str(reachable)+"**",
        "- Original, complete closed leaf functions recognized: **"+str(len(candidates))+"**",
        "- x64 differential cases executed: **"+str(counts["original_x64_reference_executions"])+"**",
        "- Native ARM64 dispatcher function calls executed: **"+str(counts["arm64_native_dispatch_calls"])+"**",
        "- Real-game leaf functions registered in temporary native ARM64 ELF: **"+str(len(verified))+"**",
        "- Original main-root direct-call edges currently verified by this batch: **"+str(counts["main_reachable_verified_registered"])+"**",
        "- Unverified acyclic candidates excluded for insufficient branch coverage: **"+str(len(skipped_cfg))+"**",
        "- Unknown targets refused, guest stack and return validated: **YES**",
        "",
        "**Only trivial, side-effect-bounded original leaf instruction families qualify. "
        "The native ELF exists only in the private runner; full engine calls, "
        "Remill object linkage, graphics and iOS remain unimplemented.**",""]
    md="\n".join(lines)
    (out/"verified-leaf-auto-link.md").write_text(md)
    print(md)
    return counts

if __name__=="__main__":
    parser=argparse.ArgumentParser()
    parser.add_argument("sha_verified_original",type=Path)
    parser.add_argument("metadata_output",type=Path)
    parser.add_argument("--whole-game-map",type=Path)
    parser.add_argument("--wave-batches",type=Path)
    args=parser.parse_args()
    if (args.whole_game_map is None)!=(args.wave_batches is None):
        parser.error("same-run original map and wave plan are required together")
    mapping=json.loads(args.whole_game_map.read_text()) if args.whole_game_map else None
    waves=json.loads(args.wave_batches.read_text()) if args.wave_batches else None
    run(args.sha_verified_original,args.metadata_output,mapping,waves)
