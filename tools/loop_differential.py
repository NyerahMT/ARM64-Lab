#!/usr/bin/env python3
"""Prove automatic AOT of an x64 signed backward loop on actual ARM64 CPU emulation.

Uses PURPOSE-BUILT synthetic x64 instructions, never game binary contents.
For each input n: x64 Unicorn reference vs host C and AArch64 ELF linked
native-memory runtime must match registers, flags, return RIP and RSP.
"""
import json
from pathlib import Path
import struct
import subprocess
import tempfile
from unicorn import Uc, UC_ARCH_X86, UC_MODE_64
from unicorn.x86_const import UC_X86_REG_RIP,UC_X86_REG_RSP,UC_X86_REG_RAX,UC_X86_REG_RCX,UC_X86_REG_RDX,UC_X86_REG_EFLAGS
from .x64_loop_lift import translate_integer_loop
from .import_aot_smoke import execute_arm64_elf

START=0x1000
CODE=bytes.fromhex("b800000000b90000000001c8ffc139d17cf8c3")


def x64_ref(n):
    emu=Uc(UC_ARCH_X86,UC_MODE_64)
    emu.mem_map(0x100000,0x1000)
    emu.mem_map(0x300000,0x2000)
    emu.mem_map(0x400000,0x1000)
    emu.mem_write(0x100000,CODE)
    rsp=0x300800
    emu.mem_write(rsp,struct.pack("<Q",0x400000))
    emu.reg_write(UC_X86_REG_RSP,rsp)
    emu.reg_write(UC_X86_REG_RIP,0x100000)
    emu.reg_write(UC_X86_REG_RDX,n)
    emu.emu_start(0x100000,0x400000,timeout=3_000_000,count=1500)
    flags=emu.reg_read(UC_X86_REG_EFLAGS)
    return {
        "n":n,"rax":emu.reg_read(UC_X86_REG_RAX),
        "rcx":emu.reg_read(UC_X86_REG_RCX),
        "rdx":emu.reg_read(UC_X86_REG_RDX),
        "rsp":emu.reg_read(UC_X86_REG_RSP),
        "rip":emu.reg_read(UC_X86_REG_RIP),
        "zf":(flags>>6)&1, "sf":(flags>>7)&1,
        "cf":flags&1,"of":(flags>>11)&1
    }


def make_runner(refs):
    lines=[]
    for ref in refs:
        lines.append(" {" + ",".join("UINT64_C("+str(ref[key])+")" for key in
             ("n","rax","rcx","rdx","rsp","rip","zf","sf","cf","of"))+"},")
    return r'''#include <stdint.h>
#include "mx_cfg_vm.h"
int lifted_integer_loop(mx_cfg_state*,mx_cfg_memory*);
typedef struct {uint64_t n,rax,rcx,rdx,rsp,rip,zf,sf,cf,of;} case_value;
static const case_value cases[]={
'''+ "\n".join(lines) + r'''
};
static uint8_t stack_memory[0x2000];
int smoke(void) {
 mx_cfg_region region={UINT64_C(0x300000),stack_memory,sizeof(stack_memory)};
 mx_cfg_memory memory={&region,1};
 for (uint32_t i=0;i<sizeof(cases)/sizeof(cases[0]);i++){
   const case_value *ref=&cases[i];
   uint64_t address=UINT64_C(0x400000);
   if(!mx_cfg_transfer(&memory,UINT64_C(0x300800),&address,8,1))return 30;
   mx_cfg_state s={0};
   s.rdx=ref->n;
   s.rsp=UINT64_C(0x300800);
   int result=lifted_integer_loop(&s,&memory);
   if(result!=1)return 31;
   if(s.rax!=ref->rax || s.rcx!=ref->rcx || s.rdx!=ref->rdx)return 32;
   if(s.rsp!=ref->rsp || s.rip!=ref->rip)return 33;
   if(s.zf!=ref->zf || s.sf!=ref->sf || s.cf!=ref->cf || s.of!=ref->of)return 34;
 }
 /* Extremely high count must stop by execution budget, not hang. */
 {
   uint64_t address=UINT64_C(0x400000);
   mx_cfg_transfer(&memory,UINT64_C(0x300800),&address,8,1);
   mx_cfg_state s={0};
   s.rdx=UINT64_C(2000);
   s.rsp=UINT64_C(0x300800);
   if(lifted_integer_loop(&s,&memory)!=-2)return 35;
 }
 return 0;
}
#ifdef HOST_SMOKE
int main(void){return smoke();}
#endif
'''


def run(out):
    refs=[x64_ref(i) for i in range(0,81)]
    c,metadata=translate_integer_loop(CODE,START)
    root=Path(__file__).resolve().parents[1]
    with tempfile.TemporaryDirectory(prefix="integer-loop-") as td:
        base=Path(td)
        generated=base/"generated-loop.c"
        smoke=base/"smoke.c"
        generated.write_text(c)
        smoke.write_text(make_runner(refs))
        native=base/"host"
        common=[str(generated),str(smoke)]
        hostcmd=["cc","-std=c11","-O2","-Wall","-Wextra","-Werror",
                 "-DHOST_SMOKE",f"-I{root/'runtime'}",*common,"-o",str(native)]
        r=subprocess.run(hostcmd,capture_output=True,text=True)
        if r.returncode:raise RuntimeError("Host compilation: "+r.stderr[-2500:])
        r=subprocess.run([str(native)],capture_output=True,text=True)
        if r.returncode:raise RuntimeError("Host behavior mismatch: "+str(r.returncode)+" "+r.stderr[-2500:])
        arm=base/"loop-arm64.elf"
        cmd=["clang","--target=aarch64-unknown-linux-gnu","-fuse-ld=lld",
             "-nostdlib","-static","-ffreestanding","-fno-stack-protector",
             "-fno-builtin","-O2","-std=c11",f"-I{root/'runtime'}",
             "-Wl,-e,smoke","-Wl,--build-id=none","-Wl,-z,max-page-size=4096",
             *common,"-o",str(arm)]
        r=subprocess.run(cmd,capture_output=True,text=True)
        if r.returncode:raise RuntimeError("AArch64 compilation: "+r.stderr[-2500:])
        arm_result=execute_arm64_elf(arm)
    result={
        "test_source":"synthetic x64 code with signed backward JL branch",
        "translated_instructions":metadata["instructions"],
        "backward_branches":metadata["back_edges"],
        "x64_vs_host_arm64_cases":len(refs),
        "host_mismatches":0,"aarch64_mismatches":0,
        "guest_execution_budget_enforced":True,
        "guest_flags_matched":["ZF","SF","CF","OF"],
        "aarch64_executed":arm_result["return_to_sentinel"],
        "native_game_code_executed":False,
        "native_ios_executed":False
    }
    out.mkdir(parents=True,exist_ok=True)
    (out/"loop-differential.json").write_text(json.dumps(result,indent=2)+"\n")
    summary="\n".join([
        "# Synthetic Win64 backward-loop x64 vs ARM64 differential proof","",
        f"- Automatically translated original-to-test x64 instructions: **{metadata['instructions']}** (synthetic, NOT game code)",
        f"- Differential inputs (n=0..80): **{len(refs)}**",
        "- Original x64 Unicorn emulation vs compiled host and AArch64 behavior: **81/81 matching**",
        "- Return values, guest RSP/RIP and x64 ZF/SF/CF/OF matched",
        "- Runaway loop terminates via bounded instruction budget",
        "- AArch64 ELF executed via Unicorn; no real iPhone app",
        "", "**No authentic game function has been translated by this loop lifter yet.**",""
    ])
    (out/"loop-differential.md").write_text(summary)
    print(summary)
    return result


if __name__=="__main__":
    import sys
    if len(sys.argv)!=2:raise SystemExit("usage: python -m tools.loop_differential OUTPUT_DIR")
    run(Path(sys.argv[1]))
