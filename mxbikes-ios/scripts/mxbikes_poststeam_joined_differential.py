#!/usr/bin/env python3
"""Differential join: original 3 timer x64 + E8 call + 9 helper prologue ops.

Private: execute unmodified SHA-pinned original x64 instruction bytes against
synthetic register, stack and cookie inputs, then compile and run a DIFFERENT
portable C guest-state implementation on x86-64 host and AArch64 Unicorn.
Public: independent semantic fixture only, not original-executable proof.

The helper is NOT finished: stop at its FIRST nested original call (0x2A9B08).
No Steam session, game binary, proprietary stack contents or renderer.
"""
from __future__ import annotations
import argparse
import hashlib
import json
import struct
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
REPO=ROOT.parent
if str(REPO) not in sys.path:sys.path.insert(0,str(REPO))
sys.path.insert(0,str(ROOT/"scripts"))
from tools.import_aot_smoke import execute_arm64_elf
import mxbikes_poststeam_timer_differential as first

BASE=first.BASE
BEGIN=first.BEGIN
CALL=0x133F76
HELPER=0x2A9AE0
STOP=0x2A9B08
COOKIE_RVA=0x3928A0
STACK_BASE=0x720000000
STACK_BYTES=1024
RSP=STACK_BASE+0x300
MASK=(1<<64)-1
SHA=first.SHA
ORIGINAL_INSTRUCTIONS=13
FNV_INIT=0xcbf29ce484222325
FNV_MULT=0x100000001b3
SCENARIOS=(
    (0,0x11,0x22,0x33,0xCAFED00D,0x202,0xBAADFACE),
    (0x1a2b3c,0xFFFFFFFFEEEEEEEE,0x100000001,0,0x0000000000001234,0x246,0),
    (0xFFFFFFFF87654321,0xAABBCCDDEEFF0102,0xABCD1234567890AA,
     MASK,0xFFFFFFFFFFFFFFFF,0x202,0x11223344),
    (MASK,0,0x8000000000000000,0x12345678,0,0x246,0xFFFFFFFF),
    (0x100000000,0x80,0x700000001,0x1234ABCD1234,
     RSP-0x140,0x202,0x55667788),
)
# tuple: initial RAX, RBX, RSI, RDI, 64-bit guest cookie,
#       Win64 RFLAGS, initial original game timer global

def hash_stack(data):
    h=FNV_INIT
    for item in data:
        h=(h^item)*FNV_MULT&MASK
    return h

def parity8(n):
    return ((n&255).bit_count()&1)==0

def semantic_fixture(params):
    """Independent hand-described x64 semantics, NOT original code proof."""
    rax,rbx,rsi,rdi,cookie,flags,initial_time=params
    after_rsp=RSP-0x140
    c=cookie^after_rsp
    buffer=bytearray(b"\xa5"*STACK_BYTES)
    def write(va,v):struct.pack_into("<Q",buffer,va-STACK_BASE,v)
    write(RSP-8,BASE+CALL+5)
    write(RSP+0x10,rbx)
    write(RSP+0x18,rsi)
    write(RSP-0x10,rdi)
    write(RSP-0x20,c)
    flags&=~(0x1|0x4|0x40|0x80|0x800)
    if parity8(c):flags|=0x4
    if c==0:flags|=0x40
    if c>>63:flags|=0x80
    return {
        "rip":BASE+STOP,"rsp":after_rsp,"rax":c,"rbx":rbx,
        "rcx":0xD3B8,"rdx":1,"rsi":1,"rdi":0xD3B8,
        "rflags":flags,"global_time_ms":rax&0xffffffff,
        "stack_hash":hash_stack(buffer),
        "return_slot":struct.unpack_from("<Q",buffer,RSP-8-STACK_BASE)[0],
        "saved_rbx":struct.unpack_from("<Q",buffer,RSP+0x10-STACK_BASE)[0],
        "saved_rsi":struct.unpack_from("<Q",buffer,RSP+0x18-STACK_BASE)[0],
        "saved_rdi":struct.unpack_from("<Q",buffer,RSP-0x10-STACK_BASE)[0],
        "stored_cookie":struct.unpack_from("<Q",buffer,RSP-0x20-STACK_BASE)[0],
    }

def validate_original(executable):
    from tools.pe_probe import PE
    from capstone import Cs,CS_ARCH_X86,CS_MODE_64
    exe=Path(executable)
    if hashlib.sha256(exe.read_bytes()).hexdigest()!=SHA:
        raise ValueError("The private owned original MX Bikes SHA must match")
    pe=PE(exe)
    cap=Cs(CS_ARCH_X86,CS_MODE_64)
    entry=bytes(pe.read_rva(CALL,5))
    if len(entry)!=5 or entry[0]!=0xe8 or (
        CALL+5+struct.unpack_from("<i",entry,1)[0])!=HELPER:
        raise RuntimeError("Original x64 CALL no longer targets audited helper")
    ops=bytes(pe.read_rva(HELPER,STOP-HELPER))
    original=list(cap.disasm(ops,BASE+HELPER))
    anticipated=(
        (0x2a9ae0,"mov","qword ptr [rsp + 0x18], rbx"),
        (0x2a9ae5,"mov","qword ptr [rsp + 0x20], rsi"),
        (0x2a9aea,"push","rdi"),
        (0x2a9aeb,"sub","rsp, 0x130"),
        (0x2a9af2,"mov","rax, qword ptr [rip + 0xe8da7]"),
        (0x2a9af9,"xor","rax, rsp"),
        (0x2a9afc,"mov","qword ptr [rsp + 0x120], rax"),
        (0x2a9b04,"mov","esi, edx"),
        (0x2a9b06,"mov","edi, ecx"),
    )
    if len(original)!=len(anticipated) or any(
        (ins.address-BASE,ins.mnemonic,ins.op_str)!=spec
        for ins,spec in zip(original,anticipated)
    ) or sum(ins.size for ins in original)!=len(ops):
        raise RuntimeError("Original helper x64 prologue changed: fail closed")
    following=list(cap.disasm(pe.read_rva(STOP,5),BASE+STOP))
    if len(following)!=1 or following[0].mnemonic!="call":
        raise RuntimeError("Original next unported helper CALL has changed")
    # Confirm original static security cookie image address, not its contents.
    if 0x2a9af9+0xe8da7!=COOKIE_RVA:
        raise RuntimeError("Original security cookie operand displacement changed")
    return pe,entry,ops

def reference_original(executable):
    from unicorn import Uc,UC_ARCH_X86,UC_MODE_64
    from unicorn.x86_const import (
        UC_X86_REG_RAX,UC_X86_REG_RBX,UC_X86_REG_RCX,
        UC_X86_REG_RDX,UC_X86_REG_RSI,UC_X86_REG_RDI,
        UC_X86_REG_RSP,UC_X86_REG_RIP,UC_X86_REG_EFLAGS,
    )
    pe,entry,ops=validate_original(executable)
    verified=[]
    for params in SCENARIOS:
        rax,rbx,rsi,rdi,cookie,flags,initial_time=params
        uc=Uc(UC_ARCH_X86,UC_MODE_64)
        for ptr in (BASE+BEGIN,BASE+HELPER,BASE+first.GUEST_GLOBAL,
                    BASE+COOKIE_RVA):
            uc.mem_map(ptr&~4095,4096)
        uc.mem_map(STACK_BASE,4096)
        uc.mem_write(BASE+BEGIN,bytes(pe.read_rva(BEGIN,CALL-BEGIN)))
        uc.mem_write(BASE+CALL,entry)
        uc.mem_write(BASE+HELPER,ops)
        uc.mem_write(BASE+first.GUEST_GLOBAL,struct.pack("<I",initial_time))
        uc.mem_write(BASE+COOKIE_RVA,struct.pack("<Q",cookie))
        uc.mem_write(STACK_BASE,b"\xa5"*STACK_BYTES)
        for reg,v in (
            (UC_X86_REG_RIP,BASE+BEGIN),(UC_X86_REG_RSP,RSP),
            (UC_X86_REG_RAX,rax),(UC_X86_REG_RBX,rbx),
            (UC_X86_REG_RCX,0xFFFFFFFFFFFFFFFF),
            (UC_X86_REG_RDX,0xCCCCCCCCDDDDDDDD),
            (UC_X86_REG_RSI,rsi),(UC_X86_REG_RDI,rdi),
            (UC_X86_REG_EFLAGS,flags)):
            uc.reg_write(reg,v)
        uc.emu_start(BASE+BEGIN,BASE+STOP,count=ORIGINAL_INSTRUCTIONS,
                     timeout=2_000_000)
        stack=bytes(uc.mem_read(STACK_BASE,STACK_BYTES))
        def get64(va):return struct.unpack_from("<Q",stack,va-STACK_BASE)[0]
        observed={
            "rip":uc.reg_read(UC_X86_REG_RIP),
            "rsp":uc.reg_read(UC_X86_REG_RSP),
            "rax":uc.reg_read(UC_X86_REG_RAX),
            "rbx":uc.reg_read(UC_X86_REG_RBX),
            "rcx":uc.reg_read(UC_X86_REG_RCX),
            "rdx":uc.reg_read(UC_X86_REG_RDX),
            "rsi":uc.reg_read(UC_X86_REG_RSI),
            "rdi":uc.reg_read(UC_X86_REG_RDI),
            "rflags":uc.reg_read(UC_X86_REG_EFLAGS),
            "global_time_ms":struct.unpack("<I",
                uc.mem_read(BASE+first.GUEST_GLOBAL,4))[0],
            "stack_hash":hash_stack(stack),
            "return_slot":get64(RSP-8),
            "saved_rbx":get64(RSP+0x10),
            "saved_rsi":get64(RSP+0x18),
            "saved_rdi":get64(RSP-0x10),
            "stored_cookie":get64(RSP-0x20),
        }
        fixture=semantic_fixture(params)
        # AF after XOR is architecturally undefined: compare its defined flags.
        if (observed["rflags"]^fixture["rflags"])&~0x10:
            raise RuntimeError("Original x64 XOR defined flags mismatch")
        for key in fixture:
            if key=="rflags":continue
            if fixture[key]!=observed[key]:
                raise RuntimeError("Original x64 joined oracle differs at "+key)
        verified.append(observed)
    return verified

def u64(n):return "UINT64_C(0x%x)"%n
def u32(n):return "UINT32_C(0x%x)"%n

def generated_native_test(expected):
    statements=[]
    fields=("rip","rax","rcx","rdx","rbx","rsi","rdi","rsp",
            "global_time_ms","return_slot","saved_rbx","saved_rsi",
            "saved_rdi","stored_cookie","stack_hash")
    for index,(params,reference) in enumerate(zip(SCENARIOS,expected),1):
        rax,rbx,rsi,rdi,cookie,flags,initial_time=params
        expected_checks=[
            "s.timer.rip=="+u64(reference["rip"]),
            "s.timer.rax=="+u64(reference["rax"]),
            "s.timer.rcx=="+u64(reference["rcx"]),
            "s.timer.rdx=="+u64(reference["rdx"]),
            "s.timer.global_time_ms=="+u32(reference["global_time_ms"]),
            "s.rsp=="+u64(reference["rsp"]),
            "s.rbx=="+u64(reference["rbx"]),
            "s.rsi=="+u64(reference["rsi"]),
            "s.rdi=="+u64(reference["rdi"]),
            "s.security_cookie=="+u64(cookie),
            "(s.timer.rflags&~UINT64_C(0x10))=="+
              u64(reference["rflags"]&~0x10),
            "guest_u64(&s,"+u64(RSP-8)+")=="+u64(reference["return_slot"]),
            "guest_u64(&s,"+u64(RSP+0x10)+")=="+u64(reference["saved_rbx"]),
            "guest_u64(&s,"+u64(RSP+0x18)+")=="+u64(reference["saved_rsi"]),
            "guest_u64(&s,"+u64(RSP-0x10)+")=="+u64(reference["saved_rdi"]),
            "guest_u64(&s,"+u64(RSP-0x20)+")=="+u64(reference["stored_cookie"]),
            "guest_hash(&s)=="+u64(reference["stack_hash"]),
        ]
        statements.append("""
    {
        mxb_poststeam_joined_guest s = {0};
        s.timer.rip=MXB_POSTSTEAM_TIMER_BEGIN_PC;
        s.timer.rax=%s;
        s.timer.rcx=UINT64_C(0xffffffffffffffff);
        s.timer.rdx=UINT64_C(0xccccccccdddddddd);
        s.timer.rflags=%s;
        s.timer.global_time_ms=%s;
        s.rsp=%s; s.stack_base=%s;
        s.rbx=%s; s.rsi=%s; s.rdi=%s; s.security_cookie=%s;
        for(unsigned k=0;k<MXB_POSTSTEAM_JOINED_STACK_BYTES;++k)
            s.stack[k]=0xa5U;
        if(!mxb_poststeam_join_to_helper_entry(&s))return %d;
        if(!(%s))return %d;
    }
"""%(u64(rax),u64(flags),u32(initial_time),u64(RSP),
      u64(STACK_BASE),u64(rbx),u64(rsi),u64(rdi),u64(cookie),
      index," &&\n            ".join(expected_checks),index+10))
    return """#include <stdint.h>
#include "mxb_poststeam_helper_entry_native.h"
/* Test-only freestanding runtime: Clang emits a memset libcall for the
 * deliberately large synthetic 1024-byte guest-state stack. Production
 * iOS links against its normal C runtime; the shim is NOT in the app. */
#ifndef HOST
void *memset(void *target, int byte, unsigned long count) {
    volatile unsigned char *p=(volatile unsigned char *)target;
    for (unsigned long i=0;i<count;++i)p[i]=(unsigned char)byte;
    return target;
}
#endif
static uint64_t guest_u64(const mxb_poststeam_joined_guest *s,uint64_t addr) {
    uint64_t out=0;
    uint64_t off=addr-s->stack_base;
    for(unsigned k=0;k<8U;++k)
        out|=((uint64_t)s->stack[off+k])<<(k*8U);
    return out;
}
static uint64_t guest_hash(const mxb_poststeam_joined_guest *s) {
    uint64_t h=UINT64_C(0xcbf29ce484222325);
    for(unsigned k=0;k<MXB_POSTSTEAM_JOINED_STACK_BYTES;++k)
        h=(h^(uint64_t)s->stack[k])*UINT64_C(0x100000001b3);
    return h;
}
int smoke(void) {
"""+"".join(statements)+"""
    mxb_poststeam_joined_guest invalid={0};
    invalid.timer.rip=MXB_POSTSTEAM_TIMER_BEGIN_PC+1U;
    invalid.timer.rax=0x11223344U;
    invalid.stack_base=UINT64_C(0x720000000);
    invalid.rsp=UINT64_C(0x720000300);
    if(mxb_poststeam_join_to_helper_entry(&invalid)||
        invalid.timer.rax!=0x11223344U||
        invalid.timer.rip!=MXB_POSTSTEAM_TIMER_BEGIN_PC+1U)return 30;
    invalid.timer.rip=MXB_POSTSTEAM_TIMER_BEGIN_PC;
    invalid.rsp=invalid.stack_base+UINT64_C(0x100);
    if(mxb_poststeam_join_to_helper_entry(&invalid)||
        invalid.timer.rip!=MXB_POSTSTEAM_TIMER_BEGIN_PC)return 31;
    invalid.rsp=invalid.stack_base+UINT64_C(0x300);
    invalid.stack_base=UINT64_C(0xfffffffffffffeff);
    if(mxb_poststeam_join_to_helper_entry(&invalid)||
        invalid.timer.rip!=MXB_POSTSTEAM_TIMER_BEGIN_PC)return 32;
    if(mxb_poststeam_join_to_helper_entry(0))return 33;
    return 0;
}
#ifdef HOST
int main(void){return smoke();}
#endif
"""

def compile_and_run_native(expected):
    native=[ROOT/"runtime"/"mxb_poststeam_timer_native.c",
            ROOT/"runtime"/"mxb_poststeam_helper_entry_native.c"]
    flags=["-std=c11","-O2","-Wall","-Wextra","-Werror",
           "-I"+str(ROOT/"runtime")]
    with tempfile.TemporaryDirectory(prefix="mxb-joined-original-arm64-") as folder:
        p=Path(folder)
        source=p/"joined.c"
        source.write_text(generated_native_test(expected))
        host=p/"joined_host"
        subprocess.run(["cc",*flags,"-DHOST",str(source),*map(str,native),
                        "-o",str(host)],check=True,capture_output=True,text=True)
        subprocess.run([str(host)],check=True,capture_output=True,text=True)
        elf=p/"joined_arm64.elf"
        compile_result=subprocess.run([
            "clang","--target=aarch64-unknown-linux-gnu","-fuse-ld=lld",
            "-nostdlib","-static","-ffreestanding",
            "-fno-builtin","-fno-stack-protector",*flags,
            "-Wl,-e,smoke","-Wl,-z,max-page-size=4096",
            "-Wl,--build-id=none",str(source),*map(str,native),"-o",str(elf)
        ],capture_output=True,text=True)
        if compile_result.returncode:
            raise RuntimeError("Original joined AArch64 compile/link rejected: "+
                               compile_result.stderr[-5000:])
        arm=execute_arm64_elf(elf,instruction_budget=500000,timeout_us=5_000_000)
        return bool(arm["return_to_sentinel"])

def verify_contract():
    contract=json.loads((ROOT/"contracts"/"poststeam-joined-entry-v1.json").read_text())
    if (contract.get("schema")!=1
        or contract["original_exe_sha256"]!=SHA
        or int(contract["original_entry_rva"],16)!=BEGIN
        or int(contract["original_helper_rva"],16)!=HELPER
        or int(contract["original_stop_rva"],16)!=STOP
        or contract["original_verified_instruction_count"]!=ORIGINAL_INSTRUCTIONS):
        raise RuntimeError("Original joined x64->ARM64 contract stale")
    for path in contract["native_sources"]:
        if not (ROOT/path).is_file():
            raise RuntimeError("Missing joined native source: "+path)
        if path not in (ROOT/"project.yml").read_text():
            raise RuntimeError("Joined code absent from iOS XcodeGen project")
    if ("mxb_poststeam_helper_entry_native.h" not in
        (ROOT/"ios/MXBViewportPrototype/Bridge.h").read_text()):
        raise RuntimeError("Joined native header not exposed to Swift")
    if ("mxb_poststeam_joined_synthetic_smoke()" not in
        (ROOT/"ios/MXBViewportPrototype/MXBViewportPrototypeApp.swift").read_text()):
        raise RuntimeError("Joined helper guest-state smoke is not connected to Swift")

def run(exe=None,out=None):
    verify_contract()
    mode="private_owned_original_x64_differential" if exe else "public_synthetic_semantic_fixture"
    expected=reference_original(exe) if exe else [semantic_fixture(p) for p in SCENARIOS]
    passed=compile_and_run_native(expected)
    report={
        "schema":1,
        "contract":"poststeam_timer_e8_call_helper_prologue_v1",
        "mode":mode,
        "original_x64_executed":exe is not None,
        "authentic_original_instructions_verified":ORIGINAL_INSTRUCTIONS if exe else 0,
        "original_call_rva":hex(CALL),
        "original_helper_rva":hex(HELPER),
        "original_next_untranslated_call_rva":hex(STOP),
        "differential_cases":len(SCENARIOS),
        "native_host_pass":True,
        "native_aarch64_unicorn_pass":passed,
        "guest_stack_bytes_compared_per_case":STACK_BYTES,
        "security_cookie_bytes_from_game_disclosed":False,
        "private_original_instruction_bytes_disclosed":False,
        "original_game_helper_fully_translated":False,
        "original_game_engine_running":False,
        "native_ios_project_source_connected":True,
        "native_ios_app_built_in_this_script":False,
        "game_frame_rendered":False,
        "steam_license_verified":False,
    }
    if out:
        path=Path(out)
        path.parent.mkdir(parents=True,exist_ok=True)
        path.write_text(json.dumps(report,indent=2)+"\n")
    print(json.dumps(report,indent=2))
    return report

if __name__=="__main__":
    p=argparse.ArgumentParser()
    group=p.add_mutually_exclusive_group(required=True)
    group.add_argument("--source-only",action="store_true")
    group.add_argument("--owned-exe",type=Path)
    p.add_argument("--report",type=Path)
    a=p.parse_args()
    run(a.owned_exe,a.report)
