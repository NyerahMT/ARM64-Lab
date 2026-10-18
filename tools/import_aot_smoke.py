#!/usr/bin/env python3
"""End-to-end, test-only Win64 import AOT -> native/ARM64 differential proof.

Purpose-built x64 code is disassembled, executed in Unicorn x64,
translated into C, compiled for the host and AArch64, and ARM64-executed
under Unicorn with the *actual* portable import-registry C sources.
No original MX Bikes code or DLL is included.
"""
import argparse
import json
from pathlib import Path
import struct
import subprocess
import tempfile

from elftools.elf.elffile import ELFFile
from unicorn import Uc, UC_ARCH_X86, UC_ARCH_ARM64, UC_MODE_64, UC_MODE_ARM, UC_HOOK_CODE
from unicorn.x86_const import (
    UC_X86_REG_RAX, UC_X86_REG_RCX, UC_X86_REG_RSP, UC_X86_REG_RIP,
)
from unicorn.arm64_const import UC_ARM64_REG_SP, UC_ARM64_REG_LR, UC_ARM64_REG_X0, UC_ARM64_REG_PC

from .x64_import_lift import lift_import_sequence, synthetic_import_sequence

ENTRY_RVA=0x1000
IMAGE_BASE=0x400000
IAT={0x1300:("KERNEL32.dll","Sleep"),0x1308:("KERNEL32.dll","GetTickCount")}
SLEEP_STUB=0x402000
TICK_STUB=0x402010
SENTINEL=0x403000
INITIAL_RSP=0x500000+0xf008


def original_x64_reference(code):
    uc=Uc(UC_ARCH_X86,UC_MODE_64)
    uc.mem_map(IMAGE_BASE,0x10000)
    uc.mem_map(0x500000,0x10000)
    uc.mem_write(IMAGE_BASE+ENTRY_RVA,code)
    for i,addr in enumerate((SLEEP_STUB,TICK_STUB)):
        uc.mem_write(IMAGE_BASE+0x1300+i*8,struct.pack("<Q",addr))
        uc.mem_write(addr,b"\xc3")
    uc.mem_write(INITIAL_RSP,struct.pack("<Q",SENTINEL))
    uc.reg_write(UC_X86_REG_RIP,IMAGE_BASE+ENTRY_RVA)
    uc.reg_write(UC_X86_REG_RSP,INITIAL_RSP)
    calls=[]
    def monitor(emu,pc,size,user):
        if pc in (SLEEP_STUB,TICK_STUB):
            if emu.reg_read(UC_X86_REG_RSP)%16 != 8:
                raise RuntimeError("Win64 callee misaligned stack")
            if pc==SLEEP_STUB:
                calls.append(("Sleep",emu.reg_read(UC_X86_REG_RCX)&0xffffffff))
            else:
                calls.append(("GetTickCount",0))
                emu.reg_write(UC_X86_REG_RAX,1234)
    uc.hook_add(UC_HOOK_CODE,monitor)
    uc.emu_start(IMAGE_BASE+ENTRY_RVA,SENTINEL,timeout=1_000_000,count=100)
    report={
        "call_sequence":calls,
        "return_rax":uc.reg_read(UC_X86_REG_RAX),
        "final_rsp":uc.reg_read(UC_X86_REG_RSP),
        "return_pc":uc.reg_read(UC_X86_REG_RIP)
    }
    if calls != [("Sleep",25),("GetTickCount",0)] or report["return_rax"]!=1234:
        raise RuntimeError("Synthetic x64 reference diverged")
    if report["final_rsp"]!=INITIAL_RSP+8 or report["return_pc"]!=SENTINEL:
        raise RuntimeError("Synthetic x64 return/stack diverged")
    return report


def execute_arm64_elf(path):
    uc=Uc(UC_ARCH_ARM64,UC_MODE_ARM)
    mapped=set()
    with path.open("rb") as handle:
        elf=ELFFile(handle)
        if elf["e_machine"]!="EM_AARCH64":raise RuntimeError("Not AArch64")
        start=int(elf.header["e_entry"])
        for seg in elf.iter_segments():
            if seg["p_type"]!="PT_LOAD":continue
            va=int(seg["p_vaddr"])
            sz=int(seg["p_memsz"])
            if va<0x10000 or sz<=0 or sz>4*1024*1024:
                raise RuntimeError("Unexpected ARM64 load segment")
            end=va+sz
            for p in range(va&~4095,(end+4095)&~4095,4096):
                if p not in mapped:
                    uc.mem_map(p,4096)
                    mapped.add(p)
            data=seg.data()
            if data:
                uc.mem_write(va,data)
    if not mapped:raise RuntimeError("AArch64 executable has no load segments")
    stack=0x80000000
    sentinel=0x80020000
    uc.mem_map(stack,0x20000)
    uc.mem_map(sentinel,4096)
    uc.mem_write(sentinel,b"\x1f\x20\x03\xd5")  # ARM64 NOP; not executed
    uc.reg_write(UC_ARM64_REG_SP,stack+0x1f000)
    uc.reg_write(UC_ARM64_REG_LR,sentinel)
    uc.reg_write(UC_ARM64_REG_PC,start)
    uc.emu_start(start,sentinel,timeout=3_000_000,count=100000)
    result=int(uc.reg_read(UC_ARM64_REG_X0))
    if uc.reg_read(UC_ARM64_REG_PC)!=sentinel or result!=0:
        raise RuntimeError(f"ARM64 runtime mismatch: pc={uc.reg_read(UC_ARM64_REG_PC):x}, smoke={result}")
    return {"entry_va":hex(start),"arm64_smoke_exit":result,"return_to_sentinel":True,
            "loaded_pages":len(mapped)}


def run(out):
    root=Path(__file__).resolve().parents[1]
    code=synthetic_import_sequence()
    x64=original_x64_reference(code)
    lifted,metadata=lift_import_sequence(code,ENTRY_RVA,IAT)
    with tempfile.TemporaryDirectory(prefix="win64-import-aot-") as td:
        work=Path(td)
        generated=work/"synthetic_lift.c"
        generated.write_text(lifted)
        runtime=[root/"runtime"/name for name in
            ("mx_time_compat.c","mx_guest_imports.c","mx_import_registry.c")]
        smoke=root/"tests"/"mx_import_aot_smoke.c"
        obj=work/"aot_host"
        cmd=["cc","-std=c11","-O2","-Wall","-Wextra","-Werror",
             "-DHOST_SMOKE",f"-I{root/'runtime'}",str(generated),str(smoke),
             *map(str,runtime),"-o",str(obj)]
        subprocess.run(cmd,check=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
        subprocess.run([str(obj)],check=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
        arm=work/"aot_arm64.elf"
        cmd=["clang","--target=aarch64-unknown-linux-gnu","-fuse-ld=lld",
             "-nostdlib","-static","-ffreestanding","-fno-stack-protector","-fno-builtin",
             "-O2","-std=c11",f"-I{root/'runtime'}",
             "-Wl,-e,smoke","-Wl,--build-id=none","-Wl,-z,max-page-size=4096",
             str(generated),str(smoke),*map(str,runtime),"-o",str(arm)]
        arm_compile=subprocess.run(cmd,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
        if arm_compile.returncode:
            raise RuntimeError("AArch64 compiler/linker failed: " + arm_compile.stderr[-5000:])
        arm_result=execute_arm64_elf(arm)
    report={
       "input":"purpose-built synthetic x86-64 code only",
       "original_x64":x64,
       "translated_instruction_count":metadata["instructions"],
       "translated_imports":metadata["imports"],
       "native_host_test":"pass",
       "arm64_emulation":arm_result,
       "native_import_registry_executed_on_arm64":True,
       "steam_success_faked":False,
       "original_game_code_translated":False,
       "ios_app_built":False,
       "limitations":[
           "Only short x64 import-call sequences and strict ABI shape are supported.",
           "Tests exercise synthetic source, not MX Bikes executable functions.",
           "ARM64 ELF under Unicorn is not signed Mach-O iOS execution.",
           "A full Windows x64 guest memory, exception and function dispatcher is not implemented."
       ]
    }
    out.mkdir(parents=True,exist_ok=True)
    (out/"import-aot-proof.json").write_text(json.dumps(report,indent=2)+"\n")
    summary="\n".join([
      "# x64-to-ARM64 import dispatch differential proof","",
      "- Source: purpose-built synthetic x64 instructions, not game code",
      f"- x64 original instructions decoded and lifted: {metadata['instructions']}",
      "- x64 emulation: call Sleep(25), then GetTickCount() => 1234",
      "- Native C linked runtime: PASS",
      "- **AArch64 ELF executed actual typed import registry and timing implementation in Unicorn: PASS**",
      "- SteamAPI_Init refusal checked (no success fabricated)",
      "- Win64 guest RSP restored and x64 reference behavior matched",
      "",
      "**This is not original MX Bikes recompilation, an iPhone build, or engine startup.**",""
    ])
    (out/"import-aot-proof.md").write_text(summary)
    print(summary)
    return report


def main():
    ap=argparse.ArgumentParser()
    ap.add_argument("--output-dir",type=Path,required=True)
    args=ap.parse_args()
    run(args.output_dir)


if __name__=="__main__":
    main()
