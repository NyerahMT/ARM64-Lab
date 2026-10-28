#!/usr/bin/env python3
"""Group BOTH genuine MX Bikes callee successors after original third JLE.

Emit decoded instructions and bounded original-x64 runtime evidence up to the
next control transfer, never infer new executed native AArch64 behavior.
The original game executable is SHA-validated and never exported to artifacts.
"""
from pathlib import Path
import hashlib
import json
import struct
import sys

from capstone import Cs,CS_ARCH_X86,CS_MODE_64,CS_GRP_CALL,CS_GRP_JUMP,CS_GRP_RET
from capstone.x86 import X86_OP_IMM
from unicorn import UC_ARCH_X86,UC_MODE_64,UC_HOOK_CODE
from unicorn.x86_const import (
  UC_X86_REG_RIP,UC_X86_REG_RSP,UC_X86_REG_RAX,UC_X86_REG_RBX,
  UC_X86_REG_RCX,UC_X86_REG_RDX,UC_X86_REG_R8,UC_X86_REG_R9,
  UC_X86_REG_RDI,UC_X86_REG_RSI,UC_X86_REG_R11,UC_X86_REG_R10,UC_X86_REG_EFLAGS
)

import mxbikes_main_joined_callee_native as main
import mxbikes_main_callee_third_jle_native as third
from mxbikes_main_callee_native_branch import INPUT
from mxbikes_whole_game_map import INPUT_SHA as SHA

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/"arm64-lab"))
from tools.pe_probe import PE

MAX_SUCCESSOR_BYTES=192
MAX_SUCCESSOR_INSNS=36
ROOTS=(third.FALLTHROUGH,third.TAKEN)
FOLLOWUP_ROOTS=(0x136176,0x136178,0x136183,0x13618a,0x1361b9,0x136194,0x1361d5,0x13619b,0x1361dc,0x1361f2,0x13619f,0x1361e4,0x1361f7,0x1361fd,0x1361a3,0x1361ab,0x1361ad,0x1361e8,0x136201,0x136207,0x136152,0x1361cf,0x1361d0,0x1361e0)


def first_control(pe,entry):
    """Decode bounded straight-line candidate; label import/return/indirect."""
    if entry not in ROOTS+FOLLOWUP_ROOTS:
        raise ValueError("Unknown authenticated third-JLE successor")
    md=Cs(CS_ARCH_X86,CS_MODE_64);md.detail=True
    raw=bytes(pe.read_rva(entry,MAX_SUCCESSOR_BYTES))
    rows=[]
    control=None
    for ins in md.disasm(raw,entry):
        if ins.group(CS_GRP_CALL) or ins.group(CS_GRP_JUMP) or ins.group(CS_GRP_RET):
            control=ins
            break
        if len(rows)>=MAX_SUCCESSOR_INSNS or ins.mnemonic in (
            "syscall","sysenter","int3","hlt","ud2"):
            raise ValueError("Unsafe or unbounded original successor")
        rows.append(ins)
    if not control:
        raise ValueError("No next original control within static budget")
    return {
        "entry_rva":hex(entry),"straightline_instructions":len(rows),
        "control_rva":hex(control.address),
        "control_kind":control.mnemonic,
        "control_operands":control.op_str,
        "control_next_rva":hex(control.address+control.size),
        "control_direct_target_rva":(
            hex(control.operands[0].imm)
            if control.operands and control.operands[0].type==X86_OP_IMM
            else None),
        "instruction_forms":[{"rva":hex(i.address),"mnemonic":i.mnemonic,
                              "op_str":i.op_str} for i in rows],
        "native_arm64_successor_executed":False
    }


def run_original_to_next_control(pe,original_layout,case,blocks):
    """Start at original game main; follow authentic CALL/JE/JGE/JLE to control."""
    byte=INPUT[case]
    if byte==0:
        return None
    cpu=main.new_cpu(pe)
    cpu.mem_write(main.TEST_INPUT,bytes([byte]))
    cpu.mem_write(main.ENTRY_SP,struct.pack("<Q",main.BASE+0x777777))
    regs={
      UC_X86_REG_RIP:main.BASE+main.MAIN,
      UC_X86_REG_RSP:main.ENTRY_SP,
      UC_X86_REG_RAX:0x888876543210+case,
      UC_X86_REG_RBX:main.SEED_RBX,
      UC_X86_REG_RCX:main.BASE,
      UC_X86_REG_RDX:0,
      UC_X86_REG_R8:main.TEST_INPUT,
      UC_X86_REG_R9:10,
      UC_X86_REG_RDI:main.SEED_RDI,
      UC_X86_REG_RSI:main.SEED_RSI,
      UC_X86_REG_R11:main.SEED_R11,
      UC_X86_REG_R10:0x78123456789,
      UC_X86_REG_EFLAGS:0x202|[0,1,0x40,0x80,0xc1,0x41,0x200,0x81][case%8]
    }
    for reg,value in regs.items():cpu.reg_write(reg,value)
    seen=[]
    cpu.hook_add(UC_HOOK_CODE,lambda _u,a,_s,_c:seen.append(a))
    cpu.emu_start(main.BASE+main.MAIN,0,timeout=3000000,count=23)
    if (len(seen)!=23 or seen[8]!=main.BASE+main.CALL_SITE or
        seen[9]!=main.BASE+main.CALLEE or
        seen[-1]!=main.BASE+third.JLE):
        raise ValueError("Original x64 main/CALL/third-JLE code trace changed")
    successor=cpu.reg_read(UC_X86_REG_RIP)-main.BASE
    if successor not in blocks:
        raise ValueError("Third original JLE escaped authenticated successors")
    entry_block=blocks[successor]
    target=int(entry_block["control_rva"],16)
    traced=[]
    def stop_at_original_control(u,a,_size,_data):
        traced.append(a)
        if a==main.BASE+target or len(traced)>MAX_SUCCESSOR_INSNS+1:
            u.emu_stop()
    hook=cpu.hook_add(UC_HOOK_CODE,stop_at_original_control)
    cpu.emu_start(main.BASE+successor,0,timeout=3000000,count=MAX_SUCCESSOR_INSNS+2)
    cpu.hook_del(hook)
    expected=[main.BASE+int(v["rva"],16) for v in entry_block["instruction_forms"]]
    if (traced!=expected+[main.BASE+target] or
        cpu.reg_read(UC_X86_REG_RIP)!=main.BASE+target or
        cpu.reg_read(UC_X86_REG_RSP)!=main.ENTRY_SP-0x288-8):
        raise RuntimeError("Original successor did not reach first control with intact CALL")
    return {"case":case,"input":byte,
            "entered_rva":hex(successor),"next_control_rva":hex(target),
            "original_instructions_from_main_to_control":23+len(expected),
            "original_win64_call_pending":True}


def run(original,out):
    pe=PE(original)
    if hashlib.sha256(pe.b).hexdigest()!=SHA:
        raise ValueError("Original executable identity changed")
    joined_layout,_,_=main.inspect_original(pe)
    third.verify_third_branch(pe)
    blocks={rva:first_control(pe,rva) for rva in ROOTS}
    followup_blocks=[first_control(pe,addr) for addr in FOLLOWUP_ROOTS]
    observations=[run_original_to_next_control(pe,joined_layout,case,blocks)
                  for case in range(len(INPUT)) if INPUT[case]!=0]
    observed={x["entered_rva"] for x in observations}
    if observed!={hex(x) for x in ROOTS}:
        raise RuntimeError("Both original JLE successor blocks not dynamically covered")
    report={
      "original_sha256":SHA,
      "two_original_successor_rvas":[hex(x) for x in ROOTS],
      "static_successor_blocks":[blocks[rva] for rva in ROOTS],
      "next_untranslated_native_frontier_blockers":followup_blocks,
      "original_x64_joined_main_callee_successor_cases":len(observations),
      "original_x64_covered_successors":sorted(observed),
      "original_x64_full_joined_successor_observations":observations,
      "native_0x136164_0x136168_executed":False,
      "native_full_callee_verified":False,
      "game_booted":False,
      "original_or_translated_bytes_exported":False
    }
    out.mkdir(parents=True,exist_ok=True)
    (out/"main-callee-both-successors.json").write_text(json.dumps(report,indent=2)+"\n")
    lines=["# Original MX Bikes grouped JLE successor blocker inventory","",
        "- SHA-pinned original x64 traced from game main through real CALL/three branches: **YES**",
        "- Both successors actually entered in original x64: **YES**",
        "- Authentic original nonempty cases: **"+str(len(observations))+"**",
        "- Native execution for THESE new successors: **not yet**",""]
    for row in report["static_successor_blocks"]:
        lines+=["## "+row["entry_rva"],
                "- Original straight-line instructions: **"+str(row["straightline_instructions"])+"**",
                "- Next original control: **"+row["control_rva"]+": "+
                   row["control_kind"]+" "+row["control_operands"]+"**",""]
        lines += ["- "+x["rva"]+" "+x["mnemonic"]+" "+x["op_str"]
                  for x in row["instruction_forms"]]
        lines.append("")
    lines+=["## Authenticated original JLE/JNE follow-up frontiers, including new quote branches"]
    for row in followup_blocks:
        lines += ["### "+row["entry_rva"],
                  "- Original instructions up to next control: **"+
                   str(row["straightline_instructions"])+"**",
                  "- Next control: **"+row["control_rva"]+" "+
                   row["control_kind"]+" "+row["control_operands"]+"**",""]
        lines += ["- "+v["rva"]+" "+v["mnemonic"]+" "+v["op_str"]
                  for v in row["instruction_forms"]]
    lines+=["","No executable, instruction bytes or lifted code is exported. This is original-x64 exploration, not ARM64 startup.",""]
    (out/"main-callee-both-successors.md").write_text("\n".join(lines))
    print("\n".join(lines))
    return report


if __name__=="__main__":
    if len(sys.argv)!=3:
        raise SystemExit("usage: branch_pair_map.py original-owned-game.exe metadata-directory")
    run(Path(sys.argv[1]),Path(sys.argv[2]))
