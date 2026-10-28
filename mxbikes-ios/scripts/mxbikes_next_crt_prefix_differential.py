#!/usr/bin/env python3
"""Differentially verify five original second-CRT instructions before the first API call.

The SHA-pinned executable, original x64 bytes and generated original-code C/ELF
remain ephemeral in private Actions. Only metadata is written to artifacts.
"""
from pathlib import Path
import hashlib
import json
import struct
import subprocess
import sys
import tempfile

from capstone import Cs,CS_ARCH_X86,CS_MODE_64
from unicorn import Uc, UC_ARCH_X86, UC_MODE_64, UC_HOOK_CODE
from unicorn.x86_const import (UC_X86_REG_RIP,UC_X86_REG_RSP,UC_X86_REG_RSI,
    UC_X86_REG_RDI,UC_X86_REG_RAX,UC_X86_REG_RCX,UC_X86_REG_EFLAGS)

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/"arm64-lab"))
from tools.pe_probe import PE
from tools.crt_entry_prefix_lift import lift_crt_entry_prefix
from tools.import_aot_smoke import execute_arm64_elf
from mxbikes_first_callee_emu import import_slots

SHA="4ae7de3854b4d0a18271679fb57a1f2fdf0b21804417b85dd82055078ea123b6"
BASE=0x140000000
ENTRY=0x2ab02c
BOUNDARY=0x2ab043
END=0x2ab049
STACK=0x700000000
RSP0=STACK+0xff08
WINDOW=RSP0-256
WINDOW_BYTES=512
MASK=0xffffffffffffffff

def fixtures():
    for i in range(12):
        yield {
            "rsi":(0x1122334455667788+i*0x103301)&MASK,
            "rdi":(0x8877665544332211+i*0x876543)&MASK,
            "rax":(0x1200abcde123+i*0x11111111)&MASK,
            "rcx":(0x1234567890abcdef+i*0x123456)&MASK,
        }

def x64_reference(code,inputs):
    u=Uc(UC_ARCH_X86,UC_MODE_64)
    code_page=(BASE+ENTRY)&~0xfff
    u.mem_map(code_page,0x1000)
    u.mem_map(STACK,0x20000)  # Stack comparison window extends 8 bytes above 64 KiB.
    u.mem_write(BASE+ENTRY,code)
    u.reg_write(UC_X86_REG_RIP,BASE+ENTRY)
    u.reg_write(UC_X86_REG_RSP,RSP0)
    for key,reg in (("rsi",UC_X86_REG_RSI),("rdi",UC_X86_REG_RDI),
                    ("rax",UC_X86_REG_RAX),("rcx",UC_X86_REG_RCX)):
        u.reg_write(reg,inputs[key])
    visited=[]
    original_pcs={BASE+0x2ab02c,BASE+0x2ab031,BASE+0x2ab032,
                  BASE+0x2ab039,BASE+0x2ab03e}
    def hook(emu,pc,width,_):
        if pc not in original_pcs:
            raise RuntimeError("Original second-CRT prefix escaped bounded path")
        visited.append(pc)
    u.hook_add(UC_HOOK_CODE,hook)
    u.emu_start(BASE+ENTRY,BASE+BOUNDARY,timeout=2_000_000,count=10)
    if len(visited)!=5 or len(set(visited))!=5:
        raise RuntimeError("Incorrect original x64 prefix length")
    vals={}
    for key,reg in (("rsi",UC_X86_REG_RSI),("rdi",UC_X86_REG_RDI),
                    ("rax",UC_X86_REG_RAX),("rcx",UC_X86_REG_RCX),
                    ("rsp",UC_X86_REG_RSP),("rip",UC_X86_REG_RIP)):
        vals[key]=u.reg_read(reg)
    vals["zf"]=int(bool(u.reg_read(UC_X86_REG_EFLAGS)&64))
    vals["window"]=bytes(u.mem_read(WINDOW,WINDOW_BYTES))
    if (vals["rip"]!=BASE+BOUNDARY or vals["rsp"]!=RSP0-0xa8 or
        vals["rsi"]!=inputs["rsi"] or vals["rdi"]!=inputs["rdi"] or
        vals["rax"]!=inputs["rax"] or vals["rcx"]!=RSP0-0xa8+0x30 or
        vals["zf"]!=1):
        raise RuntimeError("Pinned original x64 prefix semantics unexpectedly changed")
    return vals

HARNESS=r"""
#include <stdint.h>
#include "mx_crt_vm.h"
#define GUEST_WINDOW UINT64_C(ADDR_WINDOW)
#define GUEST_ENTRY UINT64_C(ADDR_ENTRY)
#define GUEST_RSP UINT64_C(ADDR_RSP)
typedef struct {
    uint64_t rsi,rdi,rax,rcx;
    uint64_t e_rsi,e_rdi,e_rax,e_rcx,e_rsp,e_rip,e_zf;
    uint8_t e_window[512];
} fixture;
static const fixture samples[]={
__CASES__
};
static uint8_t stack_window[512];
int lifted_crt_entry_prefix(mx_crt_state *,mx_cfg_memory *);
int smoke(void) {
    mx_cfg_region region={GUEST_WINDOW,stack_window,sizeof(stack_window)};
    mx_cfg_memory memory={&region,1};
    for(unsigned i=0;i<sizeof(samples)/sizeof(samples[0]);i++) {
        const fixture *f=&samples[i];
        volatile uint8_t *p=stack_window;
        for(unsigned j=0;j<512;j++)p[j]=0;
        mx_crt_state s={0};
        s.rip=GUEST_ENTRY;s.rsp=GUEST_RSP;
        s.rsi=f->rsi;s.rdi=f->rdi;s.rax=f->rax;s.rcx=f->rcx;
        int result=lifted_crt_entry_prefix(&s,&memory);
        if(result!=MX_CRT_IMPORT_BOUNDARY || s.fault ||
           s.pending_import!=0U || s.imports!=0U)return 10+i;
        if(s.instructions!=5U || s.visited!=UINT64_C(31))return 30+i;
        if(s.rsi!=f->e_rsi || s.rdi!=f->e_rdi ||
           s.rax!=f->e_rax || s.rcx!=f->e_rcx)return 50+i;
        if(s.rsp!=f->e_rsp || s.rip!=f->e_rip ||
           s.zf!=f->e_zf)return 70+i;
        for(unsigned j=0;j<512;j++) {
            if(stack_window[j]!=f->e_window[j])return 90+i;
        }
    }
    return 0;
}
#ifdef HOST_TEST
int main(void) {return smoke();}
#endif
"""

def c_cases(pairs):
    rows=[]
    for item,expected in pairs:
        values=[item[k] for k in ("rsi","rdi","rax","rcx")]
        values += [expected[k] for k in ("rsi","rdi","rax","rcx","rsp","rip","zf")]
        bytestring="{"+",".join(str(b) for b in expected["window"])+"}"
        rows.append(" {"+",".join("UINT64_C("+str(v)+")" for v in values)+","+bytestring+"},")
    return "\n".join(rows)

def checked(args):
    p=subprocess.run(args,capture_output=True,text=True)
    if p.returncode:
        raise RuntimeError("Compiler/runtime failed (exit "+str(p.returncode)+"): "+
                           (p.stderr or p.stdout)[-3500:])

def run(executable,reports):
    pe=PE(executable)
    if hashlib.sha256(pe.b).hexdigest()!=SHA:
        raise RuntimeError("Original executable revision mismatch")
    code=pe.read_rva(ENTRY,END-ENTRY)
    iat={rva:(dll.lower(),name) for rva,dll,name in import_slots(pe)}
    compiled,metadata=lift_crt_entry_prefix(code,ENTRY,iat,image_base=BASE)
    if (metadata["original_prefix_instruction_count"]!=5 or
        metadata["stop_before_import_rva"]!=hex(BOUNDARY) or
        metadata["verified_import_symbol"]!="kernel32.dll::GetStartupInfoA"):
        raise RuntimeError("Unexpected second CRT import boundary")
    cases=[(f,x64_reference(code,f)) for f in fixtures()]
    with tempfile.TemporaryDirectory(prefix="private-second-crt-prefix-") as temp:
        root=Path(temp)
        generated=root/"private-translated-crt-prefix.c"
        checkfile=root/"private-crt-prefix-smoke.c"
        generated.write_text(compiled)
        checkfile.write_text(HARNESS.replace("ADDR_WINDOW",str(WINDOW))
                             .replace("ADDR_ENTRY",str(BASE+ENTRY))
                             .replace("ADDR_RSP",str(RSP0))
                             .replace("__CASES__",c_cases(cases)))
        runtime=ROOT/"arm64-lab"/"runtime"
        host=root/"crt-prefix-host"
        checked(["cc","-std=c11","-O2","-Wall","-Wextra","-Werror",
                 "-DHOST_TEST","-I"+str(runtime),str(generated),str(checkfile),
                 "-o",str(host)])
        checked([str(host)])
        arm=root/"crt-prefix-arm64.elf"
        checked(["clang","--target=aarch64-unknown-linux-gnu","-fuse-ld=lld",
                 "-nostdlib","-static","-ffreestanding","-fno-builtin",
                 "-fno-stack-protector","-O2","-std=c11","-I"+str(runtime),
                 "-Wl,-e,smoke","-Wl,-z,max-page-size=4096",
                 "-Wl,--build-id=none",str(generated),str(checkfile),
                 "-o",str(arm)])
        a64=execute_arm64_elf(arm)
    report={
        "original_crt_rva":hex(ENTRY),
        "original_crt_full_region_instructions":126,
        "original_prefix_instructions_executed":5,
        "original_prefix_first_unsupported_import":"kernel32.dll::GetStartupInfoA",
        "original_prefix_x64_cases":len(cases),
        "native_arm64_prefix_cases":len(cases),
        "all_tested_register_stack_memory_effects_match":True,
        "arm64_smoke_exit":a64["arm64_smoke_exit"],
        "first_import_executed":False,
        "full_second_crt_executed":False,
        "native_iphone_game_booted":False,
        "limitations":"Only five original instructions preceding the first Win64 API boundary. The native API, GS/TEB, compare-exchange, branches and remainder are not executed."
    }
    reports.mkdir(parents=True,exist_ok=True)
    (reports/"next-crt-prefix-arm64.json").write_text(json.dumps(report,indent=2)+"\n")
    md=["# Original MX Bikes next CRT — first native ARM64 prefix differential","",
        "- Original RVA: "+hex(ENTRY),
        "- Original x64 instructions executed per case: **5**",
        "- Original x64 vs native host C vs ARM64 Unicorn: **"+str(len(cases))+"/"+str(len(cases))+"**",
        "- Guest RAX/RCX/RDI/RSI, RSP/RIP, ZF and 512-byte stack window: **matched**",
        "- Stop BEFORE original first Kernel32 GetStartupInfoA imported call",
        "- Native ARM64 ELF execution returned **"+str(a64["arm64_smoke_exit"])+"**","",
        "**Only the first 5/126 original instructions verified. No imported API, thread environment or lock cmpxchg executed.**",""]
    summary="\n".join(md)
    (reports/"next-crt-prefix-arm64.md").write_text(summary)
    print(summary)

if __name__=="__main__":
    if len(sys.argv)!=3:raise SystemExit("usage: script.py original.exe metadata-output-dir")
    run(Path(sys.argv[1]),Path(sys.argv[2]))
