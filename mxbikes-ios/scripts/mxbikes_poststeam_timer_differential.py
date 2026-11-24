#!/usr/bin/env python3
"""Original x64 -> host C -> AArch64 differential for a REAL post-Steam block.

Private mode independently executes three unmodified SHA-pinned original x64
instructions in Unicorn and compares the complete affected guest state with
a compiled, portable C translation running on the host AND AArch64 Unicorn.
The game executable is NEVER embedded in the generated C or public report.

Public --source-only mode uses an independent instruction-semantic fixture,
NOT original executable proof; do not confuse their evidence levels.
No Steam APIs, entitlement, original rendering, or engine boot is executed.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile

ROOT=Path(__file__).resolve().parents[1]
REPO=ROOT.parent
if str(REPO) not in sys.path:
    sys.path.insert(0,str(REPO))
from tools.import_aot_smoke import execute_arm64_elf

SHA="4ae7de3854b4d0a18271679fb57a1f2fdf0b21804417b85dd82055078ea123b6"
BASE=0x140000000
BEGIN=0x133F66
END=0x133F76
GUEST_GLOBAL=0xE4B240
MASK=(1<<64)-1

# Five independently seeded cases catch register zero extension, wraparound,
# flag preservation, and 32-bit DWORD store (including nonzero RAX high half).
SEEDS=(
    {"rax":0,"rcx":MASK,"rdx":MASK,"rflags":0x202,"global_time_ms":0xBAD00BAD},
    {"rax":0x1A2B3C,"rcx":0,"rdx":0,"rflags":0x246,"global_time_ms":0xFFFFFFFF},
    {"rax":0xFFFFFFFF87654321,"rcx":0x1234567800000001,
     "rdx":0xABCDEF0000000000,"rflags":0x202,"global_time_ms":0x1234},
    {"rax":MASK,"rcx":MASK,"rdx":MASK,"rflags":0x246,"global_time_ms":0},
    {"rax":0x100000000,"rcx":0x1111222233334444,
     "rdx":0x5555666677778888,"rflags":0x202,"global_time_ms":0x44444444},
)

def source_only_expected(seed):
    """Public semantic fixture, NOT original x64 instruction execution."""
    return {"rip":BASE+END,"rax":seed["rax"],
            "rcx":0xD3B8,"rdx":1,"rflags":seed["rflags"],
            "global_time_ms":seed["rax"]&0xffffffff}

def original_x64_expected(exe):
    from capstone import Cs,CS_ARCH_X86,CS_MODE_64
    from unicorn import Uc,UC_ARCH_X86,UC_MODE_64
    from unicorn.x86_const import (
        UC_X86_REG_RIP,UC_X86_REG_RAX,UC_X86_REG_RCX,
        UC_X86_REG_RDX,UC_X86_REG_EFLAGS,
    )
    from tools.pe_probe import PE
    exe=Path(exe)
    if hashlib.sha256(exe.read_bytes()).hexdigest()!=SHA:
        raise ValueError("SHA-pinned original MX Bikes x64 executable required")
    pe=PE(exe)
    raw=bytes(pe.read_rva(BEGIN,END-BEGIN))
    decoder=Cs(CS_ARCH_X86,CS_MODE_64)
    original=list(decoder.disasm(raw,BASE+BEGIN))
    expected=(
        (BEGIN,"mov","edx, 1"),
        (0x133F6B,"mov","ecx, 0xd3b8"),
        (0x133F70,"mov","dword ptr [rip + 0xd172ca], eax"),
    )
    if len(original)!=len(expected) or any(
        (ins.address-BASE,ins.mnemonic,ins.op_str)!=contract
        for ins,contract in zip(original,expected)
    ) or sum(i.size for i in original)!=len(raw):
        raise RuntimeError("Original pinned x64 timer code no longer matches ABI contract")
    # Next original instruction is a direct CALL to an unimplemented function.
    # Stop strictly BEFORE it; do not claim that call has been translated.
    following=bytes(pe.read_rva(END,1))
    if following!=b"\xe8":
        raise RuntimeError("Original next game callsite has changed")
    verified=[]
    for seed in SEEDS:
        guest=Uc(UC_ARCH_X86,UC_MODE_64)
        code_addr=BASE+BEGIN
        image_global=BASE+GUEST_GLOBAL
        guest.mem_map(code_addr&~4095,4096)
        guest.mem_map(image_global&~4095,4096)
        guest.mem_write(code_addr,raw)
        guest.mem_write(image_global,int(seed["global_time_ms"]).to_bytes(4,"little"))
        guest.reg_write(UC_X86_REG_RIP,code_addr)
        guest.reg_write(UC_X86_REG_RAX,seed["rax"])
        guest.reg_write(UC_X86_REG_RCX,seed["rcx"])
        guest.reg_write(UC_X86_REG_RDX,seed["rdx"])
        guest.reg_write(UC_X86_REG_EFLAGS,seed["rflags"])
        guest.emu_start(code_addr,BASE+END,count=3,timeout=1_000_000)
        result={
            "rip":guest.reg_read(UC_X86_REG_RIP),
            "rax":guest.reg_read(UC_X86_REG_RAX),
            "rcx":guest.reg_read(UC_X86_REG_RCX),
            "rdx":guest.reg_read(UC_X86_REG_RDX),
            "rflags":guest.reg_read(UC_X86_REG_EFLAGS),
            "global_time_ms":int.from_bytes(
                guest.mem_read(image_global,4),"little"),
        }
        if result["rip"]!=BASE+END or result!=source_only_expected(seed):
            raise RuntimeError("Original three-instruction oracle did not reach exact expected guest state")
        verified.append(result)
    return verified

def c_u64(v):
    return "UINT64_C(0x{:x})".format(v)

def c_u32(v):
    return "UINT32_C(0x{:x})".format(v)

def c_smoke_source(expected):
    body=[]
    for i,(seed,reference) in enumerate(zip(SEEDS,expected),1):
        body.append("""
    {
        mxb_poststeam_timer_guest guest = {
            .rip = MXB_POSTSTEAM_TIMER_BEGIN_PC,
            .rax = %s,
            .rcx = %s,
            .rdx = %s,
            .rflags = %s,
            .global_time_ms = %s,
            .reserved = 0xC0DE1234U
        };
        if (!mxb_poststeam_timer_apply(&guest)) return %d;
        if (guest.rip != %s || guest.rax != %s ||
            guest.rcx != %s || guest.rdx != %s ||
            guest.rflags != %s || guest.global_time_ms != %s ||
            guest.reserved != 0xC0DE1234U) return %d;
    }
""" % (c_u64(seed["rax"]),c_u64(seed["rcx"]),c_u64(seed["rdx"]),
       c_u64(seed["rflags"]),c_u32(seed["global_time_ms"]),i,
       c_u64(reference["rip"]),c_u64(reference["rax"]),
       c_u64(reference["rcx"]),c_u64(reference["rdx"]),
       c_u64(reference["rflags"]),c_u32(reference["global_time_ms"]),i+10))
    return """#include <stdint.h>
#include "mxb_poststeam_timer_native.h"
int smoke(void) {
""" + "".join(body) + """
    mxb_poststeam_timer_guest invalid = {
        .rip = MXB_POSTSTEAM_TIMER_BEGIN_PC + 1U,
        .rax = UINT64_C(0x12345678),
        .rcx = UINT64_C(0xAA),
        .rdx = UINT64_C(0xBB),
        .rflags = UINT64_C(0x202),
        .global_time_ms = UINT32_C(0x99887766)
    };
    if (mxb_poststeam_timer_apply(&invalid) ||
        invalid.rip != MXB_POSTSTEAM_TIMER_BEGIN_PC + 1U ||
        invalid.rax != UINT64_C(0x12345678) ||
        invalid.rcx != UINT64_C(0xAA) ||
        invalid.rdx != UINT64_C(0xBB) ||
        invalid.rflags != UINT64_C(0x202) ||
        invalid.global_time_ms != UINT32_C(0x99887766)) return 30;
    if (mxb_poststeam_timer_apply(0)) return 31;
    return 0;
}
#ifdef HOST
int main(void) { return smoke(); }
#endif
"""

def test_host_and_aarch64(expected):
    native=ROOT/"runtime"/"mxb_poststeam_timer_native.c"
    includes=["-I"+str(ROOT/"runtime")]
    flags=["-O2","-std=c11","-Wall","-Wextra","-Werror"]
    with tempfile.TemporaryDirectory(prefix="mxb-poststeam-native-") as folder:
        p=Path(folder)
        fixture=p/"poststeam_test.c"
        fixture.write_text(c_smoke_source(expected))
        host=p/"host_x64"
        subprocess.run(["cc",*flags,*includes,"-DHOST",str(fixture),
                        str(native),"-o",str(host)],
                       check=True,capture_output=True,text=True)
        subprocess.run([str(host)],check=True,capture_output=True,text=True)
        arm=p/"poststeam_arm64.elf"
        subprocess.run([
            "clang","--target=aarch64-unknown-linux-gnu","-fuse-ld=lld",
            "-nostdlib","-static","-ffreestanding","-fno-builtin",
            "-fno-stack-protector",*flags,*includes,
            "-Wl,-e,smoke","-Wl,-z,max-page-size=4096",
            "-Wl,--build-id=none",str(fixture),str(native),"-o",str(arm)
        ],check=True,capture_output=True,text=True)
        result=execute_arm64_elf(arm,instruction_budget=150000,
                                 timeout_us=3_000_000)
        if not result.get("return_to_sentinel"):
            raise RuntimeError("AArch64 compiled timer state check did not return")
        return result

def run(executable=None,report=None):
    if executable is not None:
        expected=original_x64_expected(executable)
        mode="original_x64_SHA_pinned_private_oracle"
    else:
        expected=[source_only_expected(seed) for seed in SEEDS]
        mode="source_only_instruction_semantics_not_original_proof"
    arm=test_host_and_aarch64(expected)
    info={
        "schema":1,
        "contract":"poststeam_winmm_second_timegettime_global_write_v1",
        "original_executable_sha256_expected":SHA,
        "original_x64_oracle_executed":executable is not None,
        "original_code_byte_exported":False,
        "original_imports_executed":False,
        "original_rva_begin":hex(BEGIN),"original_rva_end":hex(END),
        "original_global_dword_rva":hex(GUEST_GLOBAL),
        "original_instructions_verified":3 if executable is not None else 0,
        "differential_fixture_count":len(SEEDS),
        "host_native_c_passed":True,
        "compiled_aarch64_unicorn_passed":True,
        "aarch64_machine_state_preserved":bool(arm.get("same_machine_state")),
        "mode":mode,
        "ios_source_integrated":True,
        "ios_app_build_verified":False,
        "original_game_engine_running":False,
        "original_game_frame_rendered":False,
        "steam_authentication_verified":False,
    }
    if report is not None:
        out=Path(report)
        out.parent.mkdir(parents=True,exist_ok=True)
        out.write_text(json.dumps(info,indent=2)+"\n")
    print(json.dumps(info,indent=2))
    return info

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-only",action="store_true")
    parser.add_argument("--owned-exe",type=Path)
    parser.add_argument("--report",type=Path)
    args=parser.parse_args()
    if args.source_only==(args.owned_exe is not None):
        parser.error("Choose exactly one of --source-only or --owned-exe")
    run(args.owned_exe,args.report)

if __name__=="__main__":
    main()
