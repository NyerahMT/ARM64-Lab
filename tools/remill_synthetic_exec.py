#!/usr/bin/env python3
"""Link and execute a genuine Remill-lifted synthetic x64 memory store on AArch64.

No commercial executable inputs. This is a research-only test of two explicit
Remill helpers: __remill_write_memory_32 and __remill_missing_block. The
synthetic x64 instruction writes 1 to guest address RDX + 4*RDI. Registers
are zero-initialized, so the reference guest address is zero. The AArch64
helper traps only that guest write and records its exact address/value.
A fake success path or unrecognized additional runtime helper fails CI.
"""
import argparse
from pathlib import Path
import re
import subprocess
import tempfile
from unicorn import Uc, UC_ARCH_X86, UC_MODE_64
from unicorn.x86_const import UC_X86_REG_RIP, UC_X86_REG_RDX, UC_X86_REG_RDI

from tools.import_aot_smoke import execute_arm64_elf

SYNTHETIC=bytes.fromhex("c704ba01000000")
EXTERNALS={"__remill_write_memory_32","__remill_missing_block"}

LLVM_RUNTIME=r'''
@mx_guest_store_count = internal global i32 0, align 4
@mx_guest_store_address = internal global i64 -1, align 8
@mx_guest_store_value = internal global i32 0, align 4

define %struct.Memory* @__remill_write_memory_32(%struct.Memory* %memory, i64 %address, i32 %value) {
entry:
  %count = load i32, i32* @mx_guest_store_count
  %new_count = add i32 %count, 1
  store i32 %new_count, i32* @mx_guest_store_count
  store i64 %address, i64* @mx_guest_store_address
  store i32 %value, i32* @mx_guest_store_value
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
  %returned = call %struct.Memory* @sub_0(%struct.State* %state, i64 0, %struct.Memory* %memory)
  %memory_ok = icmp eq %struct.Memory* %returned, %memory
  %write_count = load i32, i32* @mx_guest_store_count
  %count_ok = icmp eq i32 %write_count, 1
  %write_address = load i64, i64* @mx_guest_store_address
  %address_ok = icmp eq i64 %write_address, 0
  %write_value = load i32, i32* @mx_guest_store_value
  %value_ok = icmp eq i32 %write_value, 1
  %first_check = and i1 %memory_ok, %count_ok
  %second_check = and i1 %address_ok, %value_ok
  %all_checks = and i1 %first_check, %second_check
  %passed = zext i1 %all_checks to i32
  %result = sub i32 1, %passed
  ret i32 %result
}
'''

def x64_reference():
    emulator=Uc(UC_ARCH_X86,UC_MODE_64)
    emulator.mem_map(0,0x1000)
    emulator.mem_map(0x100000,0x1000)
    emulator.mem_write(0x100000,SYNTHETIC)
    emulator.reg_write(UC_X86_REG_RIP,0x100000)
    emulator.reg_write(UC_X86_REG_RDX,0)
    emulator.reg_write(UC_X86_REG_RDI,0)
    emulator.emu_start(0x100000,0x100000+len(SYNTHETIC),timeout=1_000_000,count=20)
    final=bytes(emulator.mem_read(0,4))
    if final!=bytes.fromhex("01000000"):
        raise RuntimeError("Original synthetic x64 memory-store reference mismatch")
    return {"guest_address":0,"guest_stored_value":1,"bytes":len(SYNTHETIC)}


def attempt(ir_file:Path):
    original=x64_reference()
    source=ir_file.read_text()
    if not re.search(r"(?m)^define .*@sub_0\(",source):
        raise RuntimeError("No full lifted instruction function in Remill LLVM output")
    if "%struct.State" not in source or "%struct.Memory" not in source:
        raise RuntimeError("Expected typed guest State and Memory definitions absent")
    with tempfile.TemporaryDirectory(prefix="remill-synthetic-arm64-") as td:
        folder=Path(td)
        code=folder/"real-remill-lifted-plus-runtime.ll"
        code.write_text(source+"\n"+LLVM_RUNTIME)
        bc=folder/"lifted-with-runtime.bc"
        obj=folder/"lifted-with-runtime-arm64.o"
        exe=folder/"lifted-with-runtime-arm64.elf"
        def call(args):
            run=subprocess.run(args,capture_output=True,text=True)
            if run.returncode:
                raise RuntimeError("Toolchain failure: "+" ".join(args[:2])+"\n"+run.stderr[-4000:])
        call(["llvm-as-14",str(code),"-o",str(bc)])
        call(["opt-14","-verify","-disable-output",str(bc)])
        call(["llc-14","-mtriple=aarch64-unknown-linux-gnu","-filetype=obj",str(bc),"-o",str(obj)])
        undefined=subprocess.run(["llvm-nm-14","--undefined-only",str(obj)],
                                 capture_output=True,text=True,check=True)
        symbols=set(line.split()[-1] for line in undefined.stdout.splitlines() if line.strip())
        if symbols:
            raise RuntimeError("Unresolved runtime dependencies remain: "+", ".join(sorted(symbols)))
        call(["clang","--target=aarch64-unknown-linux-gnu","-fuse-ld=lld",
              "-nostdlib","-static","-ffreestanding","-Wl,-e,smoke",
              "-Wl,-z,max-page-size=4096","-Wl,--build-id=none",
              str(obj),"-o",str(exe)])
        arm=execute_arm64_elf(exe)
    return {
        "source":"Synthetic AMD64 x64 MOV DWORD [RDX+4*RDI],1, no game bytes",
        "original_x64_unicorn_memory_write":original,
        "linked_runtime_helpers":["__remill_missing_block","__remill_write_memory_32"],
        "real_remill_lifted_ir_compiled_to_aarch64":True,
        "all_object_runtime_dependencies_resolved":True,
        "native_arm64_lifted_code_executed":arm["return_to_sentinel"],
        "arm64_unicorn_smoke_return":arm["arm64_smoke_exit"],
        "guest_memory_address_and_value_matched":True,
        "complete_guest_machine_state_abi_proven":False,
        "original_game_code_executed":False,
        "iphone_app_built":False,
        "limitations":[
          "Only one zero-initialized synthetic memory-write case is tested",
          "Memory helper records one write but does not implement a guest address space",
          "Missing-block helper returns without reconstructing a multi-block CFG",
          "Legacy Remill/LLVM11 output compiled using LLVM14, ELF under Unicorn, not Mach-O"
        ]
    }

def main():
    parser=argparse.ArgumentParser()
    parser.add_argument("ir_file",type=Path)
    args=parser.parse_args()
    result=attempt(args.ir_file)
    import json
    print(json.dumps(result,indent=2))

if __name__=="__main__":main()
