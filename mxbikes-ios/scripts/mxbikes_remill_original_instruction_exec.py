#!/usr/bin/env python3
"""Private Remill experiment executing one authentic MX Bikes stack-store instruction.

First original instruction in independently Ghidra verified function 0x15c240:
MOV QWORD PTR [RSP+8], RCX. Initial x64 RCX=0 and RSP=0, so a bounded
guest-memory callback must see one 64-bit zero write at address 8.

Remill IR, bytes, source and native ELF are ephemeral in private Actions.
The only uploaded artifact is sanitized outcome metadata. This does NOT
translate the rest of the original callee or run the actual game.
"""
from pathlib import Path
import argparse
import json
import re
import subprocess
import struct
import tempfile
import sys

from capstone import Cs, CS_ARCH_X86, CS_MODE_64
from unicorn import Uc, UC_ARCH_X86, UC_MODE_64
from unicorn.x86_const import UC_X86_REG_RIP, UC_X86_REG_RSP, UC_X86_REG_RCX

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"arm64-lab"))
from tools.pe_probe import PE
from tools.import_aot_smoke import execute_arm64_elf

SHA="4ae7de3854b4d0a18271679fb57a1f2fdf0b21804417b85dd82055078ea123b6"
ENTRY=0x15c240

RUNTIME_LLVM=r'''
@mx_store_count = internal global i32 0
@mx_store_addr = internal global i64 -1
@mx_store_data = internal global i64 -1

define %struct.Memory* @__remill_write_memory_64(%struct.Memory* %memory, i64 %address, i64 %value) {
entry:
 %old = load i32, i32* @mx_store_count
 %count = add i32 %old, 1
 store i32 %count, i32* @mx_store_count
 store i64 %address, i64* @mx_store_addr
 store i64 %value, i64* @mx_store_data
 ret %struct.Memory* %memory
}

define %struct.Memory* @__remill_missing_block(%struct.State* %state, i64 %pc, %struct.Memory* %memory) {
entry:
 ret %struct.Memory* %memory
}

define i32 @smoke() {
entry:
 %state = alloca %struct.State, align 16
 store %struct.State zeroinitializer, %struct.State* %state
 %memory = inttoptr i64 4096 to %struct.Memory*
 %result = call %struct.Memory* @sub_0(%struct.State* %state, i64 0, %struct.Memory* %memory)
 %memory_ok = icmp eq %struct.Memory* %result, %memory
 %writes = load i32, i32* @mx_store_count
 %one_write = icmp eq i32 %writes, 1
 %address = load i64, i64* @mx_store_addr
 %correct_address = icmp eq i64 %address, 8
 %value = load i64, i64* @mx_store_data
 %correct_value = icmp eq i64 %value, 0
 %check1 = and i1 %memory_ok, %one_write
 %check2 = and i1 %correct_address, %correct_value
 %all = and i1 %check1, %check2
 %pass = zext i1 %all to i32
 %exit = sub i32 1, %pass
 ret i32 %exit
}
'''

def original_instruction(exe:Path):
    pe=PE(exe)
    if pe.inventory()["sha256"]!=SHA:
        raise RuntimeError("Incorrect game binary revision")
    decoder=Cs(CS_ARCH_X86,CS_MODE_64)
    decoder.detail=True
    ins=list(decoder.disasm(pe.read_rva(ENTRY,15),ENTRY,count=1))
    if len(ins)!=1 or ins[0].mnemonic!="mov" or ins[0].op_str!="qword ptr [rsp + 8], rcx":
        raise RuntimeError("Original game's expected 64-bit store instruction changed")
    body=pe.read_rva(ENTRY,ins[0].size)
    if len(body)!=ins[0].size:
        raise RuntimeError("Original guest instruction incomplete")
    return body

def x64_reference(body:bytes):
    uc=Uc(UC_ARCH_X86,UC_MODE_64)
    uc.mem_map(0,0x1000)
    uc.mem_map(0x100000,0x1000)
    uc.mem_write(8,struct.pack("<Q",0x1122334455667788))
    uc.mem_write(0x100000,body)
    uc.reg_write(UC_X86_REG_RIP,0x100000)
    uc.reg_write(UC_X86_REG_RSP,0)
    uc.reg_write(UC_X86_REG_RCX,0)
    uc.emu_start(0x100000,0x100000+len(body),timeout=1_000_000,count=10)
    if bytes(uc.mem_read(8,8))!=b"\x00"*8:
        raise RuntimeError("Original game x64 stack store did not write 8 zero bytes")
    return {"guest_write_address":8,"guest_write_value":0,"guest_write_width_bits":64}

def command(cmd):
    proc=subprocess.run(cmd,text=True,capture_output=True)
    if proc.returncode:
        raise RuntimeError("Toolchain failure ["+" ".join(cmd[:2])+"] "+proc.stderr[-3500:])

def perform(exe:Path,ir_file:Path,out:Path):
    body=original_instruction(exe)
    reference=x64_reference(body)
    source=ir_file.read_text()
    if not re.search(r"(?m)^define .*@sub_0\(",source):
        raise RuntimeError("Remill missing instruction trace entry")
    required=("@__remill_write_memory_64(","@__remill_missing_block(")
    declaration_lines=[line for line in source.splitlines()
                       if line.startswith("declare ") and any(x in line for x in required)]
    if len(declaration_lines)!=2:
        raise RuntimeError(f"Unexpected original-instruction Remill ABI helper count: {len(declaration_lines)}")
    filtered="\n".join(line for line in source.splitlines() if line not in declaration_lines)
    with tempfile.TemporaryDirectory(prefix="private-original-remill-exec-") as temporary:
        work=Path(temporary)
        sourcefile=work/"derived-original-instruction-with-runtime.ll"
        sourcefile.write_text(filtered+"\n"+RUNTIME_LLVM)
        bc=work/"original-remill.bc"
        obj=work/"original-remill-arm64.o"
        elf=work/"original-remill-arm64.elf"
        command(["llvm-as-14",str(sourcefile),"-o",str(bc)])
        command(["opt-14","-verify","-disable-output",str(bc)])
        command(["llc-14","-mtriple=aarch64-unknown-linux-gnu","-filetype=obj",str(bc),"-o",str(obj)])
        syms=subprocess.run(["llvm-nm-14","--undefined-only",str(obj)],
                            capture_output=True,text=True,check=True)
        if syms.stdout.strip():
            raise RuntimeError("Unresolved native runtime helpers remain")
        command(["clang","--target=aarch64-unknown-linux-gnu","-fuse-ld=lld",
                 "-nostdlib","-static","-ffreestanding","-Wl,-e,smoke",
                 "-Wl,-z,max-page-size=4096","-Wl,--build-id=none",
                 str(obj),"-o",str(elf)])
        arm_result=execute_arm64_elf(elf)
    out.mkdir(parents=True,exist_ok=True)
    report={
        "original_pe_sha256":SHA,
        "original_function_rva":hex(ENTRY),
        "original_instruction_count_executed":1,
        "instruction_in_independently_verified_function":True,
        "x64_original_code_executed":True,
        "x64_guest_effects":reference,
        "remill_lifted_actual_original_instruction":True,
        "compiled_and_linked_arm64_elf":True,
        "native_remill_runtime_helpers":["__remill_write_memory_64","__remill_missing_block"],
        "aarch64_guest_effects_differentially_matched":arm_result["return_to_sentinel"],
        "aarch64_smoke_exit":arm_result["arm64_smoke_exit"],
        "all_function_instructions_translated":False,
        "game_entry_booted":False,"iphone_build":False,
        "limitations":[
            "Exactly one original guest stack-store instruction run under a zero-initialized guest-state fixture",
            "Memory helper records a bounded write and does not implement full Windows guest memory",
            "Missing-block hook terminates the trace, so CFG/call chain and entire original function are not executed",
            "ARM64 output is freestanding ELF under Unicorn, not signed iOS Mach-O"
        ]
    }
    (out/"original-remill-instruction-exec.json").write_text(json.dumps(report,indent=2)+"\n")
    summary="\n".join([
      "# Authentic MX Bikes x64 instruction via Remill LLVM into executing AArch64","",
      f"- Original shared callee first instruction RVA: **{hex(ENTRY)}**",
      f"- Original x64 isolated instruction guest stack store: address {reference['guest_write_address']}, 64-bit value {reference['guest_write_value']}",
      "- Remill AMD64 lift to LLVM: **passed**",
      "- LLVM14 AArch64 object + linked guest runtime: **passed**",
      "- Unicorn AArch64 semantic memory-write comparison: **passed**",
      "- Executed original x64 instructions on ARM64: **one**",
      "",
      "**This is original-instruction Remill execution only, not full callee, executable startup, game graphics, or iOS app.**",""
    ])
    (out/"original-remill-instruction-exec.md").write_text(summary)
    print(summary)

def main():
    parser=argparse.ArgumentParser()
    sub=parser.add_subparsers(dest="mode",required=True)
    e=sub.add_parser("extract")
    e.add_argument("exe",type=Path);e.add_argument("out_hex",type=Path)
    r=sub.add_parser("execute")
    r.add_argument("exe",type=Path);r.add_argument("ir",type=Path);r.add_argument("report",type=Path)
    args=parser.parse_args()
    if args.mode=="extract":
        body=original_instruction(args.exe)
        args.out_hex.parent.mkdir(parents=True,exist_ok=True)
        args.out_hex.write_text(body.hex()+"\n")
        print(f"Original x64 64-bit memory instruction extracted privately ({len(body)} bytes)")
    else:
        perform(args.exe,args.ir,args.report)

if __name__=="__main__":
    main()
