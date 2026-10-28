#!/usr/bin/env python3
"""Inspect original game's immediate post-main CALLEE conditional frontier.

Original x64 instructions are decoded from the user's SHA-verified executable
in private CI. Executes only a bounded straight-line prefix until first Jcc;
then single-steps the branch under reproducible input states. No synthetic
claim that the real engine callee or its alternate paths are implemented.
"""
import hashlib,json,struct,sys
from pathlib import Path
from capstone import Cs,CS_ARCH_X86,CS_MODE_64,CS_GRP_CALL,CS_GRP_JUMP,CS_GRP_RET
from capstone.x86 import X86_OP_IMM
from unicorn import Uc,UC_ARCH_X86,UC_MODE_64,UC_HOOK_MEM_INVALID
from unicorn.x86_const import (
 UC_X86_REG_RIP,UC_X86_REG_RSP,UC_X86_REG_RAX,UC_X86_REG_RBX,
 UC_X86_REG_RCX,UC_X86_REG_RDX,UC_X86_REG_R8,UC_X86_REG_R9,
 UC_X86_REG_RDI,UC_X86_REG_RSI,UC_X86_REG_EFLAGS,UC_X86_REG_GS_BASE,
)
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/"arm64-lab"))
from tools.pe_probe import PE
from mxbikes_main_first_block import align4k,BASE,EXE_SHA

START=0x136120
IMAGE_LIMIT=128*1024*1024
STACK=0x700000000
TEB=0x720000000
DATA=0x600010000
MAX_PREFIX=128

def analyze(exe):
    pe=PE(exe)
    if hashlib.sha256(pe.b).hexdigest()!=EXE_SHA:
        raise RuntimeError("Unexpected original executable revision")
    md=Cs(CS_ARCH_X86,CS_MODE_64);md.detail=True
    instructions=[]
    control=None
    for inst in md.disasm(pe.read_rva(START,MAX_PREFIX),START):
        if inst.group(CS_GRP_CALL) or inst.group(CS_GRP_JUMP) or inst.group(CS_GRP_RET):
            control=inst
            break
        instructions.append(inst)
    if control is None or control.mnemonic not in ("je","jne","jz","jnz") or len(instructions)>24:
        raise RuntimeError("Original main callee first conditional moved or exceeds bounded scope")
    if len(control.operands)!=1 or control.operands[0].type!=X86_OP_IMM:
        raise RuntimeError("Indirect or unrecognized original main callee branch")
    target=int(control.operands[0].imm)
    direct=BASE+target
    after=BASE+control.address+control.size
    end=max(int(rva)+max(int(vsize),int(raw)) for _,vsize,rva,raw,_,_ in pe.sections)
    if end>IMAGE_LIMIT:
        raise RuntimeError("PE image exceeds bounded original x64 emulation")
    samples=[]
    for variant in range(8):
        cpu=Uc(UC_ARCH_X86,UC_MODE_64)
        cpu.mem_map(BASE,align4k(end))
        header=min(pe.size_of_headers if hasattr(pe,"size_of_headers") else 4096,len(pe.b))
        cpu.mem_write(BASE,pe.b[:header])
        for name,vsize,rva,raw,ptr,flags in pe.sections:
            if raw:
                cpu.mem_write(BASE+rva,pe.b[ptr:ptr+raw])
        cpu.mem_map(STACK,0x20000)
        cpu.mem_map(TEB,0x1000)
        cpu.mem_map(DATA,0x2000)
        rsp=STACK+0x10000-0x108
        cpu.mem_write(rsp,struct.pack("<Q",BASE+0x136746))
        cpu.mem_write(DATA+0x100,b"\x00\x00\x00\x00\x00\x00\x00\x00")
        cpu.mem_write(TEB+0x30,struct.pack("<Q",TEB))
        initial={
            UC_X86_REG_RIP:BASE+START,UC_X86_REG_RSP:rsp,
            UC_X86_REG_RAX:0x1000+variant,UC_X86_REG_RBX:0,
            UC_X86_REG_RCX:DATA+0x100,UC_X86_REG_RDX:0,
            UC_X86_REG_R8:DATA+0x100,UC_X86_REG_R9:10,
            UC_X86_REG_RDI:DATA+0x100,UC_X86_REG_RSI:0,
            UC_X86_REG_GS_BASE:TEB,
            UC_X86_REG_EFLAGS:0x202|([0,0x40][variant%2]),
        }
        for r,v in initial.items():cpu.reg_write(r,v)
        faults=[]
        def invalid(uc,access,address,size,value,ctx):
            faults.append({"instruction_rva":hex(uc.reg_read(UC_X86_REG_RIP)-BASE),
                           "guest_address":hex(address),"size":size})
            return False
        cpu.hook_add(UC_HOOK_MEM_INVALID,invalid)
        observed={"case":variant,"original_pre_branch_executed":0,
                  "original_branch_executed":False}
        try:
            cpu.emu_start(BASE+START,BASE+control.address,
                          timeout=2000000,count=30)
            observed["original_pre_branch_executed"]=len(instructions)
            if cpu.reg_read(UC_X86_REG_RIP)!=BASE+control.address:
                raise RuntimeError("Original pre-branch did not reach expected Jcc")
            before_flags=cpu.reg_read(UC_X86_REG_EFLAGS)
            before_regs={n:hex(cpu.reg_read(r)) for n,r in (
                ("rax",UC_X86_REG_RAX),("rcx",UC_X86_REG_RCX),
                ("rdx",UC_X86_REG_RDX),("rsp",UC_X86_REG_RSP))}
            cpu.emu_start(BASE+control.address,0,timeout=2000000,count=1)
            observed["original_branch_executed"]=True
            observed["branch_taken"]=(cpu.reg_read(UC_X86_REG_RIP)==direct)
            observed["branch_next_rva"]=hex(cpu.reg_read(UC_X86_REG_RIP)-BASE)
            observed["branch_pre_flags"]={
                 "zf":bool(before_flags&64),"cf":bool(before_flags&1),
                 "sf":bool(before_flags&128)}
            observed["pre_branch_registers"]=before_regs
        except Exception as exc:
            observed["error"]=str(exc)[:240]
            observed["faults"]=faults[-2:]
        samples.append(observed)
    valid=[x for x in samples if x["original_branch_executed"]]
    metadata={
      "original_sha_verified":True,
      "entry_callee_rva":hex(START),
      "first_control_rva":hex(control.address),
      "first_control_kind":control.mnemonic,
      "direct_branch_target_rva":hex(target),
      "fallthrough_rva":hex(after-BASE),
      "original_straightline_instructions_before_first_branch":len(instructions),
      "original_pre_branch_forms":[{"rva":hex(i.address),
          "mnemonic":i.mnemonic,"operands":i.op_str} for i in instructions],
      "samples":samples,
      "successful_original_x64_single_step_branch_cases":len(valid),
      "native_aarch64_callee_executed":False,
      "engine_booted":False,
      "notes":"Only first control frontier, with original PE data and synthetic deterministic inputs. No full function or game engine execution."
    }
    return metadata

def run(exe,dest):
    dest.mkdir(parents=True,exist_ok=True)
    data=analyze(exe)
    (dest/"main-callee-first-branch.json").write_text(json.dumps(data,indent=2)+"\n")
    lines=[
      "# MX Bikes 0x136120 conditional branch frontier","",
      "- Original callee: **"+data["entry_callee_rva"]+"**",
      "- Original instructions before Jcc: **"+str(data["original_straightline_instructions_before_first_branch"])+"**",
      "- Branch instruction: **"+data["first_control_rva"]+" "+data["first_control_kind"]+"**",
      "- Branch target: **"+data["direct_branch_target_rva"]+"**",
      "- Fallthrough: **"+data["fallthrough_rva"]+"**",
      "- Original x64 branch cases executed: **"+str(data["successful_original_x64_single_step_branch_cases"])+"/8**",
      "","## Original pre-branch instructions"
    ]
    lines += ["- "+item["rva"]+": "+item["mnemonic"]+" "+item["operands"] for item in data["original_pre_branch_forms"]]
    lines += ["","**This does not establish a full original function or native ARM64 conditional caller.**",""]
    summary="\n".join(lines)
    (dest/"main-callee-first-branch.md").write_text(summary)
    print(summary)
    return data

if __name__=="__main__":
    if len(sys.argv)!=3:raise SystemExit("usage: branch_probe.py original.exe report-dir")
    run(Path(sys.argv[1]),Path(sys.argv[2]))
