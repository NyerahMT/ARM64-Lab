#!/usr/bin/env python3
"""Bounded original x64 multi-basic-block function CFG -> executed native ARM64.

Disassembles *reachable* instruction blocks starting at exact original unwind
entries; all direct branch destinations / fallthroughs must resolve to a
bounded contiguous code window without crossing another known function entry.
A path to CALL/import/indirect JMP/unmodelled op/stack merge fails closed.
Complete reached RET paths, balanced original guest RSP, bounded guest stack
effects, and exact translated CF/ZF/SF/OF/PF are mandatory.

Original PE bytes, generated host C and native ARM64 ELF stay private in CI.
Only real-x64 / host C / executed ARM64 matching complete-function metadata
is emitted; no pure static candidates are promoted to native functions.
"""
from __future__ import annotations
import argparse
from collections import Counter,deque
import hashlib,json,os
from pathlib import Path
import subprocess,sys,tempfile
from capstone import Cs,CS_ARCH_X86,CS_MODE_64,CS_GRP_CALL,CS_GRP_JUMP,CS_GRP_RET
from capstone.x86 import X86_OP_REG,X86_OP_IMM,X86_OP_MEM
from unicorn import Uc,UcError,UC_ARCH_X86,UC_MODE_64,UC_HOOK_CODE,UC_HOOK_MEM_READ,UC_HOOK_MEM_WRITE,UC_HOOK_MEM_READ_UNMAPPED,UC_HOOK_MEM_WRITE_UNMAPPED,UC_HOOK_MEM_FETCH_UNMAPPED
from unicorn.x86_const import (UC_X86_REG_EFLAGS,UC_X86_REG_RIP,UC_X86_REG_RSP,
    UC_X86_REG_R12,UC_X86_REG_R13,UC_X86_REG_R14,UC_X86_REG_R15)
import mxbikes_native_prefix_wave as prefix
import mxbikes_cfg_flag_ops as flags_op
import mxbikes_cfg_extended_regs as extended
import mxbikes_cfg_guest_heap as heapops
import mxbikes_cfg_guest_stack as stackops
import mxbikes_cfg_lea_address as leaops
import mxbikes_cfg_conditional_moves as cmovops
import mxbikes_cfg_imul_ops as imulops
import mxbikes_cfg_static_image as staticops
from mxbikes_whole_game_map import INPUT_SHA

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/"arm64-lab"))
from tools.pe_probe import PE
from tools.import_aot_smoke import execute_arm64_elf

BASE=prefix.BASE
STACK=prefix.STACK
ENTRY=prefix.ENTRY
SENTINEL=BASE+0x151515
# All stack bytes reachable by statically proven Win64 operands are compared.
STACK_BELOW=8192
STACK_ABOVE=8192
WINDOW_LO=ENTRY-STACK_BELOW
STACK_WINDOW=STACK_BELOW+STACK_ABOVE
MAX_WALK_BYTES=1024
MAX_WALK_INSNS=112
MAX_PDATA_ROWS=9000
MAX_NATIVE_SAMPLES=192
BATCH_SIZE=24
CASES=4
MASK=(1<<64)-1
EXTRA_REGS=[("r12",UC_X86_REG_R12),("r13",UC_X86_REG_R13),
            ("r14",UC_X86_REG_R14),("r15",UC_X86_REG_R15)]
NATIVE_REGS=prefix.REGS+EXTRA_REGS
HEAP=0x720000000
HEAP_BYTES=1024
HEAP_BASE_OFFSET=256

def deterministic_pointer_fixture(case):
    """Build a bounded linked-object test heap (no fabricated game data)."""
    data=bytearray((k*17+case*23+7)&255 for k in range(HEAP_BYTES))
    for slot in range(HEAP_BYTES//8):
        target=HEAP+256+(((slot+3*case)%32)*8)
        data[slot*8:slot*8+8]=target.to_bytes(8,"little")
    return bytes(data)

def opcode_shape(ins):
    """Aggregate exact operand *families* without retaining original bytes."""
    parts=[]
    for operand in ins.operands:
        bits=operand.size*8
        if operand.type==X86_OP_REG:
            n=ins.reg_name(operand.reg)
            if n in ("rip","rsp","rbp"):
                family=n
            elif n.startswith(("xmm","ymm","zmm")):
                family="vector"
            elif n in ("r12","r13","r14","r15","r12d","r13d","r14d","r15d"):
                family="extended_gpr"
            elif n in ("eax","ebx","ecx","edx","rax","rbx","rcx","rdx",
                       "esi","edi","rsi","rdi","r8","r9","r10","r11",
                       "r8d","r9d","r10d","r11d"):
                family="common_gpr"
            else:
                family="narrow_or_other_gpr"
            parts.append(f"R{bits}_{family}")
        elif operand.type==X86_OP_IMM:
            parts.append(f"I{bits}")
        elif operand.type==X86_OP_MEM:
            base=ins.reg_name(operand.mem.base)
            if base in ("rsp","rbp"):
                group="guest_stack"
            elif base=="rip":
                group="rip_relative_data"
            elif base in ("r12","r13","r14","r15"):
                group="extended_reg_pointer"
            else:
                group="guest_heap_pointer"
            index="_indexed" if operand.mem.index else "_plain"
            parts.append(f"M{bits}_{group}{index}")
        else:
            parts.append(f"unknown_{bits}")
    return "_".join(parts) if parts else "none"

def unsupported_opcode_reason(ins):
    """Metadata-only shared semantic blocker; never publish guest code or offsets."""
    reason="unsupported_original_opcode_"+ins.mnemonic+"_"+opcode_shape(ins)
    ops=ins.operands
    if ins.mnemonic=="mov" and len(ops)==2 and ops[0].type==X86_OP_MEM:
        mem=ops[0]
        m=mem.mem
        base=ins.reg_name(m.base)
        if base in ("rsp","rbp") and not m.index:
            if m.segment:
                return "unsupported_original_stack_store_segment_override"
            if abs(m.disp)>stackops.MAX_DISP:
                return "unsupported_original_stack_store_displacement_over_"+str(stackops.MAX_DISP)
            if mem.size not in (4,8):
                return "unsupported_original_stack_store_width"
            if ops[1].type==X86_OP_REG:
                r=extended.native_reg(ins,ops[1])
                if r is None:
                    return "unsupported_original_stack_store_register_form"
                if r[1]!=mem.size:
                    return "unsupported_original_stack_store_width_mismatch"
    return reason

def translate(ins):
    code=staticops.emit(ins)
    if code is not None:return code
    code=heapops.emit(ins)
    if code is not None:return code
    code=stackops.emit(ins)
    if code is not None:return code
    code=leaops.emit(ins)
    if code is not None:return code
    code=cmovops.emit(ins)
    if code is not None:return code
    code=imulops.emit(ins)
    if code is not None:return code
    code=extended.emit(ins)
    if code is not None:return code
    if ins.mnemonic in flags_op.KINDS:
        stmt=flags_op.translate(ins)
        if stmt is not None:return stmt
    return prefix.translate_instruction(ins)

def decode_one(pe,rva,decoder):
    # Avoid accidentally accepting 1-14 bytes belonging to a different RVA.
    # PE.read_rva validates executable file mapping, never guesses missing bytes.
    blob=None
    for length in (15,12,8,6,4,2,1):
        try:
            blob=pe.read_rva(rva,length)
            break
        except (ValueError,OverflowError):
            continue
    if not blob:return None
    instr=list(decoder.disasm(blob,BASE+rva,count=1))
    if not instr:return None
    ins=instr[0]
    if ins.size>len(blob):return None
    return ins

def successors(row):
    if row["kind"]=="ret":return []
    if row["kind"]=="jmp":return [row["target"]]
    if row["kind"]=="jcc":return [row["next"],row["target"]]
    return [row["next"]]

def recover_cfg(pe,rva,known_roots,*,max_bytes=MAX_WALK_BYTES,require_branch=True):
    if not 1<=max_bytes<=MAX_WALK_BYTES:
        raise ValueError("CFG walker must be bounded")
    decoder=Cs(CS_ARCH_X86,CS_MODE_64)
    decoder.detail=True
    queue=deque([rva])
    records={}
    occupied={}
    reasons=Counter()
    while queue:
        pc=queue.popleft()
        if pc in records:
            continue
        if pc<rva or pc>=rva+max_bytes:
            return None,"out_of_bounded_function_window"
        if pc in known_roots and pc!=rva:
            return None,"reached_other_original_function_entry"
        ins=decode_one(pe,pc,decoder)
        if ins is None or ins.address!=BASE+pc:
            return None,"unmapped_or_incomplete_original_instruction"
        if len(records)>=MAX_WALK_INSNS:
            return None,"original_cfg_instruction_budget"
        for loc in range(pc,pc+ins.size):
            if loc>=rva+max_bytes:
                return None,"original_instruction_crosses_cfg_window"
            if loc in occupied and occupied[loc]!=pc:
                return None,"branch_into_middle_of_original_instruction"
            occupied[loc]=pc
        row={"rva":pc,"next":pc+ins.size,"size":ins.size,"ins":ins}
        if ins.group(CS_GRP_CALL):
            return None,"original_call_requires_verified_runtime_link"
        elif ins.group(CS_GRP_RET):
            if ins.mnemonic!="ret" or ins.operands:
                return None,"nonstandard_original_ret"
            row["kind"]="ret"
        elif ins.group(CS_GRP_JUMP):
            if not ins.operands or ins.operands[0].type!=X86_OP_IMM:
                return None,"indirect_or_unbounded_jump"
            target=ins.operands[0].imm-BASE
            if ins.mnemonic=="jmp":
                row.update(kind="jmp",target=target)
            elif ins.mnemonic in flags_op.predicates():
                row.update(kind="jcc",target=target,
                           predicate=flags_op.predicates()[ins.mnemonic])
            else:
                return None,"unsupported_condition_"+ins.mnemonic
        else:
            stmt=translate(ins)
            if stmt is None:
                return None,unsupported_opcode_reason(ins)
            row.update(kind="op",stmt=stmt)
        records[pc]=row
        for neighbor in successors(row):
            queue.append(neighbor)
    if not any(r["kind"]=="ret" for r in records.values()):
        return None,"no_original_return_reached"
    # Post-discovery reject reachable code that dynamically points into the
    # middle of a decoded instruction (including branch targets found early).
    for row in records.values():
        for nxt in successors(row):
            if nxt not in records:
                return None,"unresolved_cfg_successor"
    error=prove_stack_dataflow(records,rva)
    if error:return None,error
    heap_bases=set()
    static_sites={}
    for row in records.values():
        ins=row["ins"]
        heap_bases.update(heapops.memory_bases(ins))
        for addr,width in staticops.references(ins):
            if addr<BASE:
                return None,"original_image_reference_outside_PE"
            try:raw=bytes(pe.read_rva(addr-BASE,width))
            except (ValueError,OverflowError):
                return None,"original_image_read_unmapped"
            if len(raw)!=width:
                return None,"original_image_read_truncated"
            if addr in static_sites and static_sites[addr]!=raw:
                return None,"conflicting_original_static_data_read"
            static_sites[addr]=raw
    if len(static_sites)>staticops.MAX_STATIC_REFERENCES:
        return None,"too_many_original_image_data_accesses"
    ordered_static=sorted(static_sites.items())
    for i, (addr,data) in enumerate(ordered_static):
        if i and ordered_static[i-1][0]+len(ordered_static[i-1][1])>addr:
            return None,"overlapping_original_static_data_regions"
    if require_branch and not any(row["kind"]=="jcc" for row in records.values()):
        return None,"no_branch_uses_new_cfg_translator"
    return {
        "rva":rva,"rows":[records[a] for a in sorted(records)],
        "branch_count":sum(x["kind"]=="jcc" for x in records.values()),
        "return_count":sum(x["kind"]=="ret" for x in records.values()),
        "total_reached_instructions":len(records),
        "max_offset":max(records)-rva,
        "complete_original_reachable_cfg":True,
        "verified_native":False,
        "guest_heap_base_registers":sorted(heap_bases),
        "original_immutable_data_reads":ordered_static,
    },None

def prove_stack_dataflow(records,start):
    """Check every reachable original path, not only sampled runtime traces."""
    pending=deque([(start,0,None)])
    saved={} # pc -> (SP relative to original entry, BP relative or unknown)
    while pending:
        pc,sp,bp=pending.popleft()
        state=(sp,bp)
        if pc in saved:
            if saved[pc]!=state:
                return "original_control_flow_unbalanced_stack_merge"
            continue
        saved[pc]=state
        row=records[pc]
        ins=row["ins"]
        ops=ins.operands
        name=ins.mnemonic
        if row["kind"]=="ret":
            if sp!=0:return "original_ret_stack_not_restored_on_all_paths"
            continue
        if name=="push":
            sp-=8
            if not -STACK_BELOW<=sp<=STACK_ABOVE-8:
                return "stack_push_outside_compared_guest_window"
        elif name=="pop":
            if not -STACK_BELOW<=sp<=STACK_ABOVE-8:
                return "stack_pop_outside_compared_guest_window"
            sp+=8
            if ops[0].type==X86_OP_REG and ins.reg_name(ops[0].reg)=="rbp":
                bp=None
        elif name in ("add","sub") and len(ops)==2:
            if ops[0].type==X86_OP_REG and ins.reg_name(ops[0].reg)=="rsp":
                if ops[1].type!=X86_OP_IMM or not 0<=ops[1].imm<=65536:
                    return "unbounded_win64_rsp_arithmetic"
                sp+=ops[1].imm if name=="add" else -ops[1].imm
        elif name=="lea" and len(ops)==2 and ops[0].type==X86_OP_REG:
            dst=ins.reg_name(ops[0].reg)
            if dst in ("rbp","rsp"):
                src=ops[1]
                if src.type!=X86_OP_MEM or src.mem.index:
                    return "untracked_original_frame_base"
                base=ins.reg_name(src.mem.base)
                origin={"rsp":sp,"rbp":bp}.get(base)
                if origin is None:return "untracked_original_frame_base"
                if dst=="rsp":sp=origin+src.mem.disp
                else:bp=origin+src.mem.disp
        elif name=="mov" and len(ops)==2 and ops[0].type==X86_OP_REG:
            dst=ins.reg_name(ops[0].reg)
            if dst in ("rbp","rsp"):
                src=ins.reg_name(ops[1].reg) if ops[1].type==X86_OP_REG else None
                if dst=="rsp":
                    val={"rsp":sp,"rbp":bp}.get(src)
                    if val is None:return "untracked_original_rsp_assignment"
                    sp=val
                else:bp={"rsp":sp,"rbp":bp}.get(src)
        for op in ops:
            if op.type!=X86_OP_MEM or name=="lea":
                continue
            base=ins.reg_name(op.mem.base)
            origin={"rsp":sp,"rbp":bp}.get(base)
            loc=origin+op.mem.disp if origin is not None and not op.mem.index else None
            if loc is None:
                if heapops.guest_access(ins,op) is None and not staticops.references(ins):
                    return "unverified_nonstack_guest_memory_access"
            elif loc< -STACK_BELOW or loc+op.size>STACK_ABOVE:
                return "guest_stack_memory_outside_verified_window"
        if sp< -STACK_BELOW or sp>STACK_ABOVE-8:
            return "rsp_outside_compared_guest_window"
        for nxt in successors(row):
            pending.append((nxt,sp,bp))
    if len(saved)!=len(records):
        return "missing_reachable_cfg_stack_states"
    return None

def x64_reference(pe,plan,case):
    start=BASE+plan["rva"]
    cpu=Uc(UC_ARCH_X86,UC_MODE_64)
    pages={((BASE+row["rva"])&~4095) for row in plan["rows"]}
    for addr,raw in plan.get("original_immutable_data_reads",[]):
        pages.add(addr&~4095)
        pages.add((addr+len(raw)-1)&~4095)
    for page in sorted(pages):cpu.mem_map(page,4096)
    # Exact decoded original instruction bytes are private and ephemeral.
    for row in plan["rows"]:
        cpu.mem_write(BASE+row["rva"],bytes(row["ins"].bytes))
    for addr,raw in plan.get("original_immutable_data_reads",[]):
        cpu.mem_write(addr,raw)
    cpu.mem_map(STACK,0x10000)
    cpu.mem_map(HEAP,4096)
    heap_seed=deterministic_pointer_fixture(case)
    cpu.mem_write(HEAP,heap_seed)
    seed=bytes((i*13+case*19+3)&255 for i in range(STACK_WINDOW))
    cpu.mem_write(WINDOW_LO,seed)
    cpu.mem_write(ENTRY,SENTINEL.to_bytes(8,"little"))
    initial=prefix.initial_state(case)
    for i,(name,_) in enumerate(EXTRA_REGS):
        initial[name]=(0x123456789abcdef0+17*i*0x15151111+case*0x1010121)&MASK
    for name in plan.get("guest_heap_base_registers",[]):
        initial[name]=HEAP+HEAP_BASE_OFFSET+case*16
    flag=0x202|[0,1|4,0x40|0x800,0x80|4][case]
    for name,reg in NATIVE_REGS:
        cpu.reg_write(reg,start if name=="rip" else initial[name])
    cpu.reg_write(UC_X86_REG_EFLAGS,flag)
    seen=set()
    allowed={BASE+row["rva"] for row in plan["rows"]}
    invalid=[False]
    def on_inst(uc,addr,size,user):
        if addr not in allowed:
            invalid[0]=True
            uc.emu_stop()
        else:seen.add(addr)
    cpu.hook_add(UC_HOOK_CODE,on_inst)
    invalid_guest_mem=[]
    def missing_guest_address(uc,access,addr,size,value,user):
        kind={UC_HOOK_MEM_READ_UNMAPPED:"read",UC_HOOK_MEM_WRITE_UNMAPPED:"write",
              UC_HOOK_MEM_FETCH_UNMAPPED:"fetch"}.get(access,"memory")
        area=("heap" if HEAP<=addr<HEAP+0x10000 else
              "stack" if STACK<=addr<STACK+0x10000 else
              "original_image" if BASE<=addr<BASE+0x10000000 else "unmapped_external")
        invalid_guest_mem.append(f"{kind}_{area}")
        return False
    cpu.hook_add(UC_HOOK_MEM_READ_UNMAPPED|UC_HOOK_MEM_WRITE_UNMAPPED|
                 UC_HOOK_MEM_FETCH_UNMAPPED,missing_guest_address)
    def on_heap_access(uc,access,addr,size,value,user):
        if HEAP<=addr<HEAP+4096 and not (HEAP<=addr and addr+size<=HEAP+HEAP_BYTES):
            invalid[0]=True
            uc.emu_stop()
    cpu.hook_add(UC_HOOK_MEM_READ|UC_HOOK_MEM_WRITE,on_heap_access)
    for addr,raw in plan.get("original_immutable_data_reads",[]):
        def on_image_write(uc,access,address,size,value,user):
            for a,chunk in plan.get("original_immutable_data_reads",[]):
                if address<a+len(chunk) and address+size>a:
                    invalid[0]=True
                    uc.emu_stop()
        cpu.hook_add(UC_HOOK_MEM_WRITE,on_image_write)
        break
    try:
        cpu.emu_start(start,SENTINEL,timeout=1500000,count=MAX_WALK_INSNS*16)
    except UcError as e:
        pc=cpu.reg_read(UC_X86_REG_RIP)
        where="start" if pc==start else "within_cfg" if pc in allowed else "escaped_cfg"
        kind=invalid_guest_mem[0] if invalid_guest_mem else type(e).__name__
        return None,"original_x64_execution_fault_"+kind+"_"+where
    if invalid[0] or cpu.reg_read(UC_X86_REG_RIP)!=SENTINEL:
        return None,"original_x64_cfg_escaped_or_budget"
    if cpu.reg_read(UC_X86_REG_RSP)!=ENTRY+8:
        return None,"original_x64_ret_stack_mismatch"
    actual={name:cpu.reg_read(reg) for name,reg in NATIVE_REGS}
    eflags=cpu.reg_read(UC_X86_REG_EFLAGS)
    actualflags={key:int(bool(eflags&bit)) for key,bit in
                 (("cf",1),("zf",0x40),("sf",0x80),("of",0x800),("pf",4))}
    return (initial,flag,actual,actualflags,
            bytes(cpu.mem_read(WINDOW_LO,STACK_WINDOW)),
            bytes(cpu.mem_read(HEAP,HEAP_BYTES))),None

def generate(batch,references):
    original_data={}
    for plan in batch:
        for addr,raw in plan.get("original_immutable_data_reads",[]):
            if addr in original_data and original_data[addr]!=raw:
                raise RuntimeError("Conflicting immutable original data in batch")
            original_data[addr]=raw
    if len(original_data)>staticops.MAX_STATIC_REFERENCES:
        raise RuntimeError("batch_static_image_region_budget: group must be split")
    static_declarations=[]
    static_regions=[]
    for index,(addr,raw) in enumerate(sorted(original_data.items())):
        static_declarations.append(
            f"static uint8_t original_data_{index}[{len(raw)}]={{"+
            ",".join(str(k) for k in raw)+"};")
        static_regions.append(f"{{UINT64_C({addr}),original_data_{index},{len(raw)}U}}")
    pieces=[]
    rows=[]
    for idx,plan in enumerate(batch):
        instructions=[]
        for row in plan["rows"]:
            line=f"case {row['rva']}U:"
            if row["kind"]=="ret":
                line+=(" {uint64_t guest_return=0U;"
                       "if(!mx_cfg_transfer(&mem,s.rsp,&guest_return,8U,0))return 11;"
                       "s.rsp+=8U;s.rip=guest_return;*sp=s;return 0;}")
            elif row["kind"]=="jmp":
                line+=f" pc={row['target']}U;break;"
            elif row["kind"]=="jcc":
                line+=(f" pc=({row['predicate']})?{row['target']}U:"
                       f"{row['next']}U;break;")
            else:
                line+=f" {row['stmt']} pc={row['next']}U;break;"
            instructions.append(line)
        body=(
            f"static int run_{idx}(struct cpu*sp,mx_cfg_memory*memory){{\n"
            " struct cpu s=*sp;mx_cfg_memory mem=*memory;(void)mem;\n"
            f" uint32_t pc={plan['rva']}U;\n"
            " for(unsigned budget=0U;budget<1792U;budget++){\n"
            "  switch(pc){\n"
            +"\n".join(instructions)+
            "\n default:return 12;\n } }\n return 13;\n}\n"
        )
        pieces.append(body)
        all_cases=[]
        for state,eflags,actual,final,stack,heap_mem in references[plan["rva"]]:
            inp=[state[n] for n,_ in NATIVE_REGS]
            outputs=[actual[n] for n,_ in NATIVE_REGS]
            fbits=[final[n] for n in ("cf","zf","sf","of","pf")]
            all_cases.append("{{"+",".join(f"UINT64_C({n})" for n in inp)+"},"
                             +str(eflags)+",{"
                             +",".join(f"UINT64_C({n})" for n in outputs)+"},{"
                             +",".join(str(f) for f in fbits)+"},{"
                             +",".join(str(x) for x in stack)+"},{"
                             +",".join(str(x) for x in heap_mem)+"}}")
        rows.append("{"+",\n".join(all_cases)+"}")
    code=r'''#include <stdint.h>
#include "mx_cfg_vm.h"
#define COUNT __COUNT__
#define STACK UINT64_C(0x710000000)
#define ENTRY (STACK+UINT64_C(0x7ff8))
#define SENTINEL UINT64_C(__SENTINEL__)
#define WINDOW (ENTRY-UINT64_C(__STACK_BELOW__))
#define WINDOW_BYTES __STACK_WINDOW__U
struct cpu {
 uint64_t rax,rbx,rcx,rdx,r8,r9,rdi,rsi,r10,r11,rbp,rsp,rip,r12,r13,r14,r15;
 uint8_t cf,zf,sf,of,pf;
};
typedef struct{
 uint64_t input[17];uint32_t eflags;uint64_t expected[17];
 uint8_t expected_flags[5];uint8_t expected_memory[__STACK_WINDOW__];
 uint8_t expected_heap[1024];
} fixture;
static const fixture cases[COUNT][4]={__DATA__};
static uint8_t guest_memory[65536];
static uint8_t heap_memory[1024];
__STATIC_IMAGE_BUFFERS__
__FUNCTIONS__
typedef int(*worker)(struct cpu*,mx_cfg_memory*);
static const worker workers[COUNT]={__WORKERS__};
static const uint64_t originals[COUNT]={__STARTS__};
int smoke(void){
 mx_cfg_region regions[]={{STACK,guest_memory,sizeof(guest_memory)},
  {UINT64_C(0x720000000),heap_memory,sizeof(heap_memory)}__STATIC_IMAGE_REGIONS__};
 mx_cfg_memory mem={regions,(uint32_t)(sizeof(regions)/sizeof(regions[0]))};
 for(unsigned i=0;i<COUNT;i++)for(unsigned t=0;t<4U;t++){
  const fixture*f=&cases[i][t];
  for(unsigned k=0;k<WINDOW_BYTES;k++)
   guest_memory[WINDOW-STACK+k]=(uint8_t)((k*13U+t*19U+3U)&255U);
  for(unsigned k=0;k<8U;k++)
   guest_memory[ENTRY-STACK+k]=(uint8_t)(SENTINEL>>(8U*k));
  for(unsigned k=0;k<1024U;k++)
   heap_memory[k]=(uint8_t)((k*17U+t*23U+7U)&255U);
  for(unsigned q=0;q<128U;q++){
   uint64_t target=UINT64_C(0x720000000)+UINT64_C(256)+
     (uint64_t)(((q+3U*t)%32U)*8U);
   for(unsigned j=0;j<8U;j++)
    heap_memory[q*8U+j]=(uint8_t)(target>>(8U*j));
  }
  struct cpu s={0};uint64_t*regs=&s.rax;
  for(unsigned k=0;k<17U;k++)regs[k]=f->input[k];
  s.rip=originals[i];
  s.cf=(f->eflags&1U)!=0U;s.pf=(f->eflags&4U)!=0U;
  s.zf=(f->eflags&64U)!=0U;s.sf=(f->eflags&128U)!=0U;
  s.of=(f->eflags&2048U)!=0U;
  if(workers[i](&s,&mem)!=0)return 1;
  for(unsigned k=0;k<17U;k++)if(regs[k]!=f->expected[k])return 2;
  if(s.cf!=f->expected_flags[0])return 31;
  if(s.zf!=f->expected_flags[1])return 32;
  if(s.sf!=f->expected_flags[2])return 33;
  if(s.of!=f->expected_flags[3])return 34;
  if(s.pf!=f->expected_flags[4])return 35;
  for(unsigned k=0;k<WINDOW_BYTES;k++)
   if(guest_memory[WINDOW-STACK+k]!=f->expected_memory[k])return 4;
  for(unsigned k=0;k<1024U;k++)
   if(heap_memory[k]!=f->expected_heap[k])return 5;
 }
 return 0;
}
#ifdef HOST
int main(void){return smoke();}
#endif
'''
    inserts={
        "__COUNT__":str(len(batch)),
        "__STACK_BELOW__":str(STACK_BELOW),
        "__STACK_WINDOW__":str(STACK_WINDOW),
        "__STATIC_IMAGE_BUFFERS__":"\n".join(static_declarations),
        "__STATIC_IMAGE_REGIONS__":(",\n"+",\n".join(static_regions)) if static_regions else "",
        "__SENTINEL__":str(SENTINEL),
        "__DATA__":",\n".join(rows),
        "__FUNCTIONS__":"\n".join(pieces),
        "__WORKERS__":",".join(f"run_{i}" for i in range(len(batch))),
        "__STARTS__":",".join(f"UINT64_C({BASE+v['rva']})" for v in batch),
    }
    for a,b in inserts.items():code=code.replace(a,b)
    return code

def compile_batch(batch,references):
    src=generate(batch,references)
    with tempfile.TemporaryDirectory(prefix="mx-private-cfg-native-") as td:
        root=Path(td)
        name=root/"full-original-cfg-private.c"
        name.write_text(src)
        args=["-O2","-std=c11","-Wall","-Wextra","-Werror",
              "-I",str(ROOT/"arm64-lab"/"runtime")]
        host=root/"host"
        p=subprocess.run(["cc",*args,"-DHOST",str(name),"-o",str(host)],
                         capture_output=True,text=True)
        if p.returncode:
            raise RuntimeError("host_compile: "+p.stderr[-1000:])
        p=subprocess.run([str(host)],capture_output=True,text=True)
        if p.returncode:
            raise RuntimeError("host_differential: "+str(p.returncode))
        arm=root/"native-arm64.elf"
        p=subprocess.run(["clang","--target=aarch64-unknown-linux-gnu",
            "-fuse-ld=lld","-nostdlib","-static","-ffreestanding",
            "-fno-builtin","-fno-stack-protector",*args,
            "-Wl,-e,smoke","-Wl,-z,max-page-size=4096",
            "-Wl,--build-id=none",str(name),"-o",str(arm)],
            capture_output=True,text=True)
        if p.returncode:
            raise RuntimeError("arm64_compile: "+p.stderr[-1000:])
        result=execute_arm64_elf(arm,instruction_budget=6000000,timeout_us=15000000)
        if result["arm64_smoke_exit"]!=0:
            raise RuntimeError("arm64_differential: "+str(result["arm64_smoke_exit"]))

def run(original,map_file,proof_file,out):
    pe=PE(original)
    if hashlib.sha256(pe.b).hexdigest()!=INPUT_SHA:
        raise RuntimeError("Original game SHA-256 not approved")
    mapping=json.loads(map_file.read_text())
    if mapping.get("input_sha256")!=INPUT_SHA or mapping.get("original_file_verified") is not True:
        raise RuntimeError("Stale/untrusted original whole-game map")
    proof=json.loads(proof_file.read_text())
    if not isinstance(proof,list):raise ValueError("Native manifest missing")
    already={int(v["original_rva"],16) for v in proof
             if v.get("full_function_behavior_verified") is True}
    roots={int(r["rva"],16) for r in mapping["interval_map"]}
    rows=mapping["interval_map"]
    if not 1<=len(rows)<=MAX_PDATA_ROWS:raise ValueError("Unbounded game map")
    candidates=[]
    rejects=Counter()
    total=0
    for item in sorted(rows,key=lambda r:(
        r.get("depth_from_known_roots",99) if r.get("depth_from_known_roots") is not None else 99,
        int(r["rva"],16))):
        rva=int(item["rva"],16)
        if rva in already:
            rejects["already_native_verified"]+=1
            continue
        if item.get("status")!="decoded_linear":
            rejects["unmapped_or_incomplete_unwind_interval"]+=1
            continue
        if item.get("direct_calls") or item.get("indirect_calls") or item.get("import_thunk_calls"):
            rejects["requires_guest_CALL_or_import_runtime"]+=1
            continue
        if item.get("indirect_jumps"):
            rejects["indirect_jump_or_dispatch"]+=1
            continue
        total+=1
        plan,reason=recover_cfg(pe,rva,roots)
        if plan is None:rejects[reason]+=1
        else:candidates.append(plan)
    original_refs={}
    passed_refs=[]
    x64_failures=[]
    for item in candidates:
        samples=[]
        for case in range(CASES):
            expected,error=x64_reference(pe,item,case)
            if error:
                rejects[error]+=1
                x64_failures.append({"rva":hex(item["rva"]),"reason":error})
                break
            samples.append(expected)
        if len(samples)==CASES:
            passed_refs.append(item)
            original_refs[item["rva"]]=samples
    # Run all bounded original references; stop instead of pretending excess
    # candidates were checked by native compilation.
    if len(passed_refs)>MAX_NATIVE_SAMPLES:
        rejects["not_yet_native_checked_budget_limit"]+=len(passed_refs)-MAX_NATIVE_SAMPLES
    queue=passed_refs[:MAX_NATIVE_SAMPLES]
    translated=[]
    native_rejections=Counter()
    def attempt(batch):
        if not batch:return
        try:compile_batch(batch,original_refs)
        except (RuntimeError,ValueError,subprocess.SubprocessError) as err:
            if len(batch)>1:
                n=len(batch)//2
                attempt(batch[:n]);attempt(batch[n:])
            else:
                native_rejections[str(err).split(":",1)[0]]+=1
        else:translated.extend(batch)
    for i in range(0,len(queue),BATCH_SIZE):
        attempt(queue[i:i+BATCH_SIZE])
    if len(translated)>len(queue):
        raise RuntimeError("Invalid function proof accounting")
    run_id=os.environ.get("GITHUB_RUN_ID","")
    if translated and not run_id.isdecimal():
        raise RuntimeError("No verified CI run URL for original native proof")
    additions=[{
        "original_rva":hex(p["rva"]),
        "native_symbol":f"mx_cfg_native_{p['rva']:08x}",
        "full_function_behavior_verified":True,
        "win64_guest_call_abi_verified":True,
        "code_presence":"ephemeral_ci_elf_only",
        "differential_test_run_url":
          "https://github.com/NyerahMT/ReflexBuildInput/actions/runs/"+run_id,
        "proof_scope":"Fully recovered bounded original reachable branch CFG; x64/host/native ARM64 four case full Win64 return stack register CF ZF SF OF PF and guest stack differential",
    } for p in translated]
    combined={int(x["original_rva"],16):x for x in proof}
    for e in additions:
        addr=int(e["original_rva"],16)
        if addr in combined:raise RuntimeError("Original verified native entry collision")
        combined[addr]=e
    out.mkdir(parents=True,exist_ok=True)
    (out/"verified-batch-registrations.json").write_text(
        json.dumps(list(combined.values()),indent=2)+"\n")
    metadata={
        "schema":1,"original_sha256":INPUT_SHA,
        "all_pdata_intervals_inspected":len(rows),
        "original_without_static_CALL_entries_checked":total,
        "complete_bounded_original_multi_block_candidates":len(candidates),
        "real_x64_full_return_candidates":len(passed_refs),
        "actually_native_executed_whole_new_functions":len(translated),
        "original_x64_host_arm64_complete_cfg_test_cases":len(translated)*CASES,
        "merged_verified_native_function_proofs":len(combined),
        "new_verified_function_rvas":[hex(x["rva"]) for x in translated],
        "exact_translation_blockers":dict(rejects.most_common()),
        "native_execution_blockers":dict(native_rejections.most_common()),
        "original_x64_reference_failures":x64_failures[:32],
        "static_original_pe_memory_read_sites_admitted":sum(len(p.get("original_immutable_data_reads",[])) for p in candidates),
        "cross_pdata_function_stitching":False,
        "commercial_original_bytes_exported":False,
        "game_booted":False,
        "iphone_ipa_built":False,
    }
    (out/"full-native-cfg-wave.json").write_text(json.dumps(metadata,indent=2)+"\n")
    lines=["# Original MX Bikes multi-basic-block native function conversion","",
        "- Unwind function entries inventoried: **"+str(len(rows))+"**",
        "- Original no-direct-CALL entries CFG-walked: **"+str(total)+"**",
        "- Complete reachable bounded original branch CFG candidates: **"+str(len(candidates))+"**",
        "- Original x64 complete returning CFGs: **"+str(len(passed_refs))+"**",
        "- New original complete functions executed and proven on ARM64: **"+str(len(translated))+"**",
        "- Matching x64/host/native ARM64 full-state test cases: **"+str(len(translated)*CASES)+"**",
        "- Total verified native entries after this stage: **"+str(len(combined))+"**",
        "- Engine/menu/IPA booted: **NO**","",
        "## Most frequent fail-closed blocker groups",
        "| Blocker | Intervals |","| --- | ---: |"]
    lines.extend("| "+k+" | "+str(v)+" |" for k,v in rejects.most_common(22))
    lines.extend(["","**Original machine bytes and generated native artifacts remain transient inside private CI.**",""])
    (out/"full-native-cfg-wave.md").write_text("\n".join(lines))
    print("\n".join(lines))
    return metadata

if __name__=="__main__":
    ap=argparse.ArgumentParser()
    ap.add_argument("original_exe",type=Path)
    ap.add_argument("original_map",type=Path)
    ap.add_argument("prior_native_proofs",type=Path)
    ap.add_argument("output_dir",type=Path)
    a=ap.parse_args()
    run(a.original_exe,a.original_map,a.prior_native_proofs,a.output_dir)
