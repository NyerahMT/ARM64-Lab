#!/usr/bin/env python3
"""Verify one original MX Bikes entry wrapper's modeled control effects on ARM64.

The original x64 wrapper runs with a synthetic callee stub. The generated
AArch64 code models those wrapper control effects ONLY. Neither real callee
runs on either architecture. Reports contain metadata and validation counts.
"""
import hashlib
import json
import os
from pathlib import Path
import struct
import subprocess
import sys

from elftools.elf.elffile import ELFFile
from unicorn import Uc, UC_ARCH_ARM64, UC_MODE_ARM
from unicorn.arm64_const import UC_ARM64_REG_PC, UC_ARM64_REG_SP, UC_ARM64_REG_LR, UC_ARM64_REG_X0

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "arm64-lab"))
from tools.pe_probe import PE
from tools.entry_wrapper import emulate_stubbed_wrapper
from tools.x64_entry_lift import lift_entry_to_c

KNOWN_SHA = "4ae7de3854b4d0a18271679fb57a1f2fdf0b21804417b85dd82055078ea123b6"
CODE = 0x600000
DATA = 0x700000
STACK = 0x900000
RETURN = 0x800000
INITIAL_RSP = 0x50000000 + 0x10000 - 0x108


def read_arm64_object(path):
    with path.open("rb") as handle:
        elf = ELFFile(handle)
        if elf["e_machine"] != "EM_AARCH64":
            raise RuntimeError("Expected ARM64 ELF")
        sec = elf.get_section_by_name(".text")
        symbols = elf.get_section_by_name(".symtab")
        reloc = elf.get_section_by_name(".rela.text")
        if reloc is not None and list(reloc.iter_relocations()):
            raise RuntimeError("Unresolved code relocations in generated ARM64 object")
        if sec is None or symbols is None:
            raise RuntimeError("Missing ELF section or symbol table")
        hits = symbols.get_symbol_by_name("lifted_entry")
        if not hits or len(hits) != 1:
            raise RuntimeError("Generated ARM64 lifted_entry symbol not found")
        symbol = hits[0]
        start, length = int(symbol["st_value"]), int(symbol["st_size"])
        blob = sec.data()
        if not length or start + length > len(blob) or len(blob) > 0x10000:
            raise RuntimeError("Unexpected size or symbol boundary")
        return blob, start, length


def execute_arm64(blob, offset):
    uc = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
    for addr in (CODE,DATA,STACK,RETURN):
        uc.mem_map(addr,0x10000 if addr != RETURN else 0x1000)
    uc.mem_write(CODE,blob)
    uc.mem_write(RETURN,b"\x1f\x20\x03\xd5")
    uc.mem_write(DATA+0x100,struct.pack("<6Q",INITIAL_RSP,0,0,0,0,0))
    uc.reg_write(UC_ARM64_REG_PC,CODE+offset)
    uc.reg_write(UC_ARM64_REG_LR,RETURN)
    uc.reg_write(UC_ARM64_REG_SP,STACK+0x8000)
    uc.reg_write(UC_ARM64_REG_X0,DATA+0x100)
    uc.emu_start(CODE+offset,RETURN,timeout=2_000_000,count=500)
    if uc.reg_read(UC_ARM64_REG_PC) != RETURN:
        raise RuntimeError("AArch64 entry-model function did not return")
    return struct.unpack("<6Q",uc.mem_read(DATA+0x100,48))


def main():
    if len(sys.argv)!=3:
        raise SystemExit("Usage: python entry_arm64_check.py <original.exe> <reportdir>")
    exe=Path(sys.argv[1])
    reports=Path(sys.argv[2])
    reports.mkdir(parents=True,exist_ok=True)
    pe=PE(exe)
    info=pe.inventory()
    if info["sha256"] != KNOWN_SHA:
        raise RuntimeError("Input executable changed")
    rva=int(info["entry_rva"],16)
    entry_code=pe.read_rva(rva,18)
    x64_result=emulate_stubbed_wrapper(entry_code,rva)
    generated_source=lift_entry_to_c(entry_code,rva)
    # Generated model is private and intentionally never copied to reports.
    temp=reports.parent/"generated-entry-temporary"
    temp.mkdir(parents=True,exist_ok=True)
    src=temp/"entry_model.c"
    obj=temp/"entry_model_aarch64.o"
    src.write_text(generated_source)
    subprocess.run(["clang","--target=aarch64-unknown-linux-gnu","-ffreestanding",
                    "-O0","-fno-pic","-fno-pie","-std=c11","-Wall","-Wextra","-Werror",
                    "-c",str(src),"-o",str(obj)],check=True)
    code,offset,length=read_arm64_object(obj)
    arm_result=execute_arm64(code,offset)
    first_call=int(x64_result["direct_call_rva"],16)
    tail=int(x64_result["tail_jmp_rva"],16)
    expected=(INITIAL_RSP,INITIAL_RSP-48,first_call,tail,1,1)
    matched=arm_result==expected
    report={
        "game_sha256":KNOWN_SHA,
        "entry_rva":hex(rva),
        "original_entry_instruction_count":x64_result["original_entry_instructions_executed"],
        "original_entry_x64_stubbed_execution_pass":bool(
             x64_result["x64_stack_balanced"] and x64_result["x64_tail_transfer_reached"]),
        "generated_aarch64_function_size":length,
        "generated_aarch64_control_effects_pass":matched,
        "stack_restored":arm_result[0]==INITIAL_RSP,
        "synthetic_callee_rsp_preserved":arm_result[1]==INITIAL_RSP-48,
        "first_callee_target_identified":arm_result[2]==first_call,
        "tail_jump_target_identified":arm_result[3]==tail,
        "synthetic_call_count":arm_result[4],
        "synthetic_tail_count":arm_result[5],
        "original_callees_executed":False,
        "original_game_running":False,
        "native_ios_execution":False,
        "limitations":[
            "This is automatically generated ARM64 control-effect simulation for an 18-byte wrapper, NOT native recompilation of either original startup callee.",
            "No original Windows API, CRT startup, window, Steam, or rendering code executed.",
            "The original guest entry was run in Unicorn x64 with a synthetic first-callee RET.",
            "Generated original-specific C and AArch64 object remain private in temporary CI storage, not artifacts.",
        ]
    }
    (reports/"entry-arm64-check.json").write_text(json.dumps(report,indent=2)+"\n")
    summary=("# MX Bikes original-entry-to-ARM64 control-flow proof\n\n"
             f"- Original x64 entry instructions executed with callee stub: {report['original_entry_instruction_count']}\n"
             f"- Original x64 wrapper control test passed: {report['original_entry_x64_stubbed_execution_pass']}\n"
             f"- Generated ARM64 function bytes: {length}\n"
             f"- ARM64 modeled stack/call/jump effects matched: {matched}\n"
             "- Actual original startup callees executed: NO\n"
             "- Original engine boot or native iOS execution: NO\n"
             "\nScope: A compiler-backed ARM64 model of the original four-instruction wrapper, with synthetic call/transfer behavior.\n")
    (reports/"entry-arm64-check.md").write_text(summary)
    print(summary)
    if not matched:
        raise AssertionError("AArch64 model diverged from x64 wrapper structural behavior")


if __name__=="__main__":
    main()
