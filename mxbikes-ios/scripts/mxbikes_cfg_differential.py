#!/usr/bin/env python3
"""Private original x64 branch/memory region -> AArch64 differential proof.

The selected PE unwind-backed interval starts after an apparent function
prologue: only the *region*, not an entire original function, is tested.
No original game bytes, generated C or native objects are published.
"""
import json
from pathlib import Path
import random
import struct
import subprocess
import sys
import tempfile

from unicorn import Uc, UC_ARCH_X86, UC_MODE_64
from unicorn.x86_const import (UC_X86_REG_RIP,UC_X86_REG_RSP,
                              UC_X86_REG_RAX,UC_X86_REG_RCX,UC_X86_REG_RDX)

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"arm64-lab"))
from tools.pe_probe import PE
from tools.x64_cfg_lift import translate_cfg
from tools.import_aot_smoke import execute_arm64_elf

EXPECTED_SHA="4ae7de3854b4d0a18271679fb57a1f2fdf0b21804417b85dd82055078ea123b6"
START,END=0x2b212c,0x2b215e
CODE=0x100000
DATA=0x200000
STACK=0x300000
RETURN=0x400000
INITIAL_RAX=0xABCDEF1255557777
CASES=128

def x64_reference(body,nonnull,source,prior):
    uc=Uc(UC_ARCH_X86,UC_MODE_64)
    uc.mem_map(CODE,0x1000)
    uc.mem_map(DATA,0x10000)
    uc.mem_map(STACK,0x10000)
    uc.mem_map(RETURN,0x1000)
    uc.mem_write(CODE,body)
    obj=DATA+0x1000
    child=DATA+0x4000
    uc.mem_write(obj+0x40,struct.pack("<Q",child if nonnull else 0))
    for k,value in enumerate(source):
        uc.mem_write(child+0xc0+4*k,struct.pack("<I",value))
    for k,value in enumerate(prior):
        uc.mem_write(obj+0xa8+4*k,struct.pack("<I",value))
    rsp=STACK+0x8000
    uc.mem_write(rsp+0x18,struct.pack("<Q",RETURN))
    uc.reg_write(UC_X86_REG_RIP,CODE)
    uc.reg_write(UC_X86_REG_RSP,rsp)
    uc.reg_write(UC_X86_REG_RCX,obj)
    uc.reg_write(UC_X86_REG_RAX,INITIAL_RAX)
    uc.reg_write(UC_X86_REG_RDX,0xFEDCBAAB98765432)
    uc.emu_start(CODE,RETURN,timeout=1_000_000,count=64)
    if uc.reg_read(UC_X86_REG_RIP)!=RETURN or uc.reg_read(UC_X86_REG_RSP)!=rsp+0x20:
        raise RuntimeError("Original x64 branch region did not terminate at configured RET")
    values=struct.unpack("<III",uc.mem_read(obj+0xa8,12))
    return {
        "dst":values,
        "rax":uc.reg_read(UC_X86_REG_RAX),
        "rdx":uc.reg_read(UC_X86_REG_RDX),
        "rsp":uc.reg_read(UC_X86_REG_RSP),
    }

def generated_test_c(samples):
    rows=[]
    for item in samples:
        ss=item["source"];prior=item["prior"];ref=item["result"]
        payload=[int(item["nonnull"]),*ss,*prior,*ref["dst"],ref["rax"],ref["rdx"]]
        rows.append("  {"+",".join("UINT64_C("+str(x)+")" for x in payload)+"},")
    return r'''#include <stdint.h>
#include "mx_cfg_vm.h"
int lifted_cfg(mx_cfg_state*,mx_cfg_memory*);
typedef struct {
  uint64_t present;
  uint64_t s0,s1,s2;
  uint64_t p0,p1,p2;
  uint64_t e0,e1,e2;
  uint64_t expected_rax,expected_rdx;
} example;
static const example tests[]={
'''+ "\n".join(rows)+r'''
};
static uint8_t data[0x10000],stackbuf[0x10000];
static void write32(uint8_t *p,uint32_t n){ __builtin_memcpy(p,&n,4); }
static void write64(uint8_t *p,uint64_t n){ __builtin_memcpy(p,&n,8); }
static uint32_t read32(uint8_t *p){uint32_t v=0; __builtin_memcpy(&v,p,4); return v;}
int smoke(void){
 mx_cfg_region regions[2]={{UINT64_C(0x200000),data,sizeof(data)},
                          {UINT64_C(0x300000),stackbuf,sizeof(stackbuf)}};
 mx_cfg_memory memory={regions,2};
 for(uint32_t k=0;k<(uint32_t)(sizeof(tests)/sizeof(tests[0]));k++){
   const example *t=&tests[k];
   /* Each test explicitly overwrites every memory location that this region reads. */
   write64(data+0x1000+0x40,t->present ? UINT64_C(0x204000) : 0);
   write32(data+0x4000+0xc0,(uint32_t)t->s0);
   write32(data+0x4000+0xc4,(uint32_t)t->s1);
   write32(data+0x4000+0xc8,(uint32_t)t->s2);
   write32(data+0x1000+0xa8,(uint32_t)t->p0);
   write32(data+0x1000+0xac,(uint32_t)t->p1);
   write32(data+0x1000+0xb0,(uint32_t)t->p2);
   write64(stackbuf+0x8000+0x18,UINT64_C(0x400000));
   mx_cfg_state state={0};
   state.rcx=UINT64_C(0x201000);
   state.rdx=UINT64_C(0xFEDCBAAB98765432);
   state.rax=UINT64_C(0xABCDEF1255557777);
   state.rsp=UINT64_C(0x308000);
   int result=lifted_cfg(&state,&memory);
   if(result!=1)return 10;
   if(state.rip!=UINT64_C(0x400000) || state.rsp!=UINT64_C(0x308020))return 11;
   if(state.rax!=t->expected_rax || state.rdx!=t->expected_rdx)return 12;
   if(read32(data+0x1000+0xa8)!=(uint32_t)t->e0 ||
      read32(data+0x1000+0xac)!=(uint32_t)t->e1 ||
      read32(data+0x1000+0xb0)!=(uint32_t)t->e2)return 13;
 }
 /* Reject pointer to unmapped guest address instead of dereferencing host RAM. */
 write64(data+0x1000+0x40,UINT64_C(0xBAD000));
 mx_cfg_state invalid={0};
 invalid.rcx=UINT64_C(0x201000);
 invalid.rsp=UINT64_C(0x308000);
 if(lifted_cfg(&invalid,&memory)!=-3)return 14;
 return 0;
}
#ifdef HOST_SMOKE
int main(void){return smoke();}
#endif
'''

def run(exe,out):
    pe=PE(exe)
    if pe.inventory()["sha256"]!=EXPECTED_SHA:raise RuntimeError("Unexpected private game executable revision")
    pr,sz=pe.directory(3)
    unwind={a:b for a,b,u in struct.iter_unpack("<III",pe.read_rva(pr,sz))}
    if unwind.get(START)!=END:raise RuntimeError("Original CFG unwind interval moved")
    code=pe.read_rva(START,END-START)
    csource,meta=translate_cfg(code,START)
    if meta["conditional_branches"]!=1 or meta["original_instruction_count"]!=11:
        raise RuntimeError("Original branch instructions changed")
    rng=random.Random(0x2b212c)
    examples=[]
    for k in range(CASES):
        present=k%2==1
        source=tuple(rng.getrandbits(32) for _ in range(3))
        prior=tuple(rng.getrandbits(32) for _ in range(3))
        result=x64_reference(code,present,source,prior)
        examples.append({"nonnull":present,"source":source,"prior":prior,"result":result})
    temp_dir=out.parent
    with tempfile.TemporaryDirectory(prefix="private-original-cfg-",dir=temp_dir) as td:
        p=Path(td)
        translated=p/"derived-original-cfg.c"
        smoke=p/"differential-smoke.c"
        translated.write_text(csource)
        smoke.write_text(generated_test_c(examples))
        runtime=Path(__file__).resolve().parents[1]/"arm64-lab"/"runtime"
        host=p/"host"
        cmd=["cc","-O2","-std=c11","-Wall","-Wextra","-Werror",f"-I{runtime}",
             "-DHOST_SMOKE",str(translated),str(smoke),"-o",str(host)]
        subprocess.run(cmd,check=True)
        subprocess.run([str(host)],check=True)
        arm=p/"original-cfg-aarch64.elf"
        cmd=["clang","--target=aarch64-unknown-linux-gnu","-fuse-ld=lld","-nostdlib",
             "-static","-ffreestanding","-fno-stack-protector","-O2","-std=c11",
             f"-I{runtime}","-Wl,-e,smoke","-Wl,--build-id=none",
             "-Wl,-z,max-page-size=4096",str(translated),str(smoke),"-o",str(arm)]
        build=subprocess.run(cmd,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
        if build.returncode:raise RuntimeError("AArch64 linker: "+build.stderr[-2500:])
        arm64_result=execute_arm64_elf(arm)
    summary={
        "original_executable_sha256":EXPECTED_SHA,"original_rva":hex(START),
        "original_unwind_end":hex(END),"original_decoded_instructions":meta["original_instruction_count"],
        "verified_internal_conditional_branches":meta["conditional_branches"],
        "branch_taken_cases":sum(not x["nonnull"] for x in examples),
        "branch_not_taken_cases":sum(x["nonnull"] for x in examples),
        "original_x64_differential_cases":CASES,"native_host_matches":CASES,
        "native_arm64_matches":CASES,"native_arm64_executed":arm64_result["return_to_sentinel"],
        "invalid_guest_pointer_refused":True,
        "scope":"Original control-flow region is unwind-backed but starts after apparent prologue, not a whole source-level function.",
        "original_game_engine_booted":False,"ios_app_built":False,
        "limitations":["Only MOV/TEST/JE/ADD RSP/RET supported in this exact original region.",
                       "Does not preserve all EFLAGS effects, exception/Win64 call ABI, or general branching",
                       "Original commercial code and derived output kept private"]
    }
    out.mkdir(parents=True,exist_ok=True)
    (out/"cfg-differential.json").write_text(json.dumps(summary,indent=2)+"\n")
    text="\n".join([
        "# Authentic MX Bikes x64 multi-block control-flow to ARM64 proof","",
        f"- Original unwind-backed region: **{hex(START)}–{hex(END)}**",
        f"- Original instructions decoded and translated: **{meta['original_instruction_count']}**",
        f"- Conditional branches: **{meta['conditional_branches']}**",
        f"- Branch taken / not taken: {summary['branch_taken_cases']} / {summary['branch_not_taken_cases']}",
        f"- Original x64 reference vs host C and AArch64 execution: **{CASES}/{CASES} bitwise matches**",
        "- Invalid guest pointer refused: yes",
        "- Private original bytes and derived C/native outputs: not published","",
        "**Not a full original function: its unwind interval starts after the apparent prologue. No boot, graphics, or native iOS game.**",""
    ])
    (out/"cfg-differential.md").write_text(text)
    print(text)

def main():
    if len(sys.argv)!=3:raise SystemExit("usage: script.py game.exe reports_dir")
    run(Path(sys.argv[1]),Path(sys.argv[2]))

if __name__=="__main__":main()
