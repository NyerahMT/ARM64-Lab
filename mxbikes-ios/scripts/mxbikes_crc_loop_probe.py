#!/usr/bin/env python3
"""Authentic original SHA-pinned hot checksum/CRC loop reverse-trace.

Analyze a bounded interval around RVA 0x130670 including branches and
buffer bounds, and create original x64 single-iteration CPU/memory oracles.
Emits instruction *semantics* / registers only, never original PE bytes.
"""
from pathlib import Path
import hashlib,json,sys
from capstone import Cs,CS_ARCH_X86,CS_MODE_64,CS_GRP_JUMP
from capstone.x86 import X86_OP_IMM
from unicorn.x86_const import (
 UC_X86_REG_RIP,UC_X86_REG_RSP,UC_X86_REG_RAX,UC_X86_REG_RBX,
 UC_X86_REG_RCX,UC_X86_REG_RDX,UC_X86_REG_R8,UC_X86_REG_R9,
 UC_X86_REG_RSI,UC_X86_REG_RDI,UC_X86_REG_EFLAGS
)
from unicorn import UcError
import mxbikes_main_joined_callee_native as joined
from mxbikes_whole_game_map import INPUT_SHA
BASE=joined.BASE
BEGIN=0x130630
HOT=0x130670
END=0x1306cf
DATA=joined.CODE_DATA+0x200
def decoded(pe):
    md=Cs(CS_ARCH_X86,CS_MODE_64);md.detail=True
    ins=list(md.disasm(pe.read_rva(BEGIN,END-BEGIN),BEGIN))
    records=[{"rva":hex(i.address),"size":i.size,
              "mnemonic":i.mnemonic,"operands":i.op_str,
              "direct_target":hex(i.operands[0].imm) if
              i.group(CS_GRP_JUMP) and i.operands and
              i.operands[0].type==X86_OP_IMM else None}
             for i in ins]
    if not any(i.address==HOT for i in ins):
        raise ValueError("Original hot checksum block address changed")
    return records
def one_step(pe,seed,byte):
    cpu=joined.new_cpu(pe)
    cpu.mem_write(DATA,bytes([byte,0x53,0x91,0]))
    cpu.reg_write(UC_X86_REG_RIP,BASE+HOT)
    cpu.reg_write(UC_X86_REG_RSP,joined.ENTRY_SP-0x440)
    cpu.reg_write(UC_X86_REG_RBX,seed)
    cpu.reg_write(UC_X86_REG_RCX,DATA)
    cpu.reg_write(UC_X86_REG_RDX,0)
    cpu.reg_write(UC_X86_REG_RAX,0)
    cpu.reg_write(UC_X86_REG_R8,0)
    cpu.reg_write(UC_X86_REG_R9,0)
    cpu.reg_write(UC_X86_REG_RSI,0)
    cpu.reg_write(UC_X86_REG_RDI,0)
    result={"seed_bx":seed,"input_byte":byte}
    try:
        # Do not assume the pointer bound or branch transfer conditions:
        # execute exactly 17 original x64 instructions in hot block.
        cpu.emu_start(BASE+HOT,0,timeout=1000000,count=17)
        result["stop_rva"]=hex(cpu.reg_read(UC_X86_REG_RIP)-BASE)
        result["result_bx"]=cpu.reg_read(UC_X86_REG_RBX)&0xffff
        result["result_rax"]=cpu.reg_read(UC_X86_REG_RAX)
        result["result_rcx"]=hex(cpu.reg_read(UC_X86_REG_RCX))
        flags=cpu.reg_read(UC_X86_REG_EFLAGS)
        result["flags_zf_sf_cf"]=[int(bool(flags&64)),int(bool(flags&128)),int(bool(flags&1))]
        result["status"]="executed_original_17"
    except UcError as exc:
        result.update(status="original_x64_fault",fault_class=type(exc).__name__)
    return result
def run(exe,out):
    from tools.pe_probe import PE
    pe=PE(exe)
    if hashlib.sha256(pe.b).hexdigest()!=INPUT_SHA:raise ValueError("Original exe SHA mismatch")
    instructions=decoded(pe)
    samples=[one_step(pe,s,b) for s,b in
              ((0,0),(0,0x12),(0xffff,0xff),(0x1234,0xab),
               (0x8000,0x7f),(0x1d0f,0x00),(0x1234,0))]
    report={"original_sha256":INPUT_SHA,
            "original_disassembly_interval":[hex(BEGIN),hex(END)],
            "original_hot_block_rva":hex(HOT),
            "original_disassembly":instructions,
            "original_x64_samples":samples,
            "arm64_implementation_verified":False,
            "game_loading_screen_running":False}
    out.mkdir(parents=True,exist_ok=True)
    (out/"original-hot-loop-verified.json").write_text(json.dumps(report,indent=2)+"\n")
    lines=["# MX Bikes real x64 CRC-style hot loop","",
       "## Original SHA-verified surrounding Win64 instructions"]
    lines.extend("- "+r["rva"]+": "+r["mnemonic"]+" "+r["operands"] for r in instructions)
    lines.extend(["","## Original x64 17-instruction samples"])
    lines.extend("- BX "+hex(x["seed_bx"])+" byte "+hex(x["input_byte"])+
                 ": "+x["status"]+" PC "+str(x.get("stop_rva"))+
                 ", BX="+hex(x.get("result_bx",0))
                 for x in samples)
    lines.extend(["","Original x64 guest evidence only, no ARM64 CRC yet.",""])
    (out/"original-hot-loop-verified.md").write_text("\n".join(lines))
    print("\n".join(lines))
    return report
if __name__=="__main__":
    if len(sys.argv)!=3:raise SystemExit("usage: original_hot_loop.py owned.exe metadata-dir")
    run(Path(sys.argv[1]),Path(sys.argv[2]))
