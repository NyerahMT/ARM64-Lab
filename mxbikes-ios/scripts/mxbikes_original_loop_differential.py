#!/usr/bin/env python3
"""Original MX Bikes indexed-accumulator loop x64-to-AArch64 differential test.

One real original unwind-backed *region*, RVA 0x1fc710, using a backward
JL, indexed array read-modify-write, signed comparison and Win64 epilogue.
All commercial bytes, generated source and native binaries stay ephemeral
in the owner's private CI runner. Only aggregated metadata is exported.
"""
import json
from pathlib import Path
import random
import struct
import subprocess
import sys
import tempfile
from unicorn import Uc,UC_ARCH_X86,UC_MODE_64
from unicorn.x86_const import (
    UC_X86_REG_RIP,UC_X86_REG_RSP,UC_X86_REG_RAX,UC_X86_REG_RCX,
    UC_X86_REG_RDX,UC_X86_REG_RBX,UC_X86_REG_RBP,UC_X86_REG_RDI,
    UC_X86_REG_R12,UC_X86_REG_R13,UC_X86_REG_EFLAGS
)

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"arm64-lab"))
from tools.pe_probe import PE
from tools.x64_indexed_loop_lift import lift_indexed_loop
from tools.import_aot_smoke import execute_arm64_elf

EXPECTED="4ae7de3854b4d0a18271679fb57a1f2fdf0b21804417b85dd82055078ea123b6"
BEGIN=0x1fc710
# Captured original terminal RET at 0x1fc735.
END=0x1fc736
CODE=0x100000
DATA=0x200000
STACK=0x300000
RETURN=0x400000
OBJ=DATA+0x100
ARRAY=DATA+0x2000
LEN=32
SAVED=[0x1111122233334444,0x5555566677778888,0x99999aaabbbbcccc,0xddddeeeeffffaaaa]
SAVED_R12=0x0123456789ABCDEF


def x64_reference(blob,index,limit,addend,seed):
    machine=Uc(UC_ARCH_X86,UC_MODE_64)
    for base,size in ((CODE,0x1000),(DATA,0x10000),(STACK,0x10000),(RETURN,0x1000)):
        machine.mem_map(base,size)
    machine.mem_write(CODE,blob)
    machine.mem_write(OBJ+0x100,struct.pack("<Q",ARRAY))
    machine.mem_write(OBJ+8,struct.pack("<I",limit))
    machine.mem_write(ARRAY,struct.pack("<32I",*seed))
    rsp=STACK+0x8000
    for n,value in enumerate(SAVED):
        machine.mem_write(rsp+0x28+8*n,struct.pack("<Q",value))
    machine.mem_write(rsp+0x48,struct.pack("<Q",RETURN))
    machine.mem_write(rsp+0x58,struct.pack("<Q",SAVED_R12))
    machine.reg_write(UC_X86_REG_RIP,CODE)
    machine.reg_write(UC_X86_REG_RSP,rsp)
    machine.reg_write(UC_X86_REG_RBX,OBJ)
    machine.reg_write(UC_X86_REG_R12,addend)
    machine.reg_write(UC_X86_REG_RDX,index)
    machine.emu_start(CODE,RETURN,timeout=2_000_000,count=500)
    flags=machine.reg_read(UC_X86_REG_EFLAGS)
    result={
        "values":struct.unpack("<32I",machine.mem_read(ARRAY,LEN*4)),
        "rax":machine.reg_read(UC_X86_REG_RAX),
        "rcx":machine.reg_read(UC_X86_REG_RCX),
        "rdx":machine.reg_read(UC_X86_REG_RDX),
        "rbx":machine.reg_read(UC_X86_REG_RBX),
        "r12":machine.reg_read(UC_X86_REG_R12),
        "r13":machine.reg_read(UC_X86_REG_R13),
        "rdi":machine.reg_read(UC_X86_REG_RDI),
        "rbp":machine.reg_read(UC_X86_REG_RBP),
        "rip":machine.reg_read(UC_X86_REG_RIP),
        "rsp":machine.reg_read(UC_X86_REG_RSP),
        "zf":(flags>>6)&1,"sf":(flags>>7)&1,
        "cf":flags&1,"of":(flags>>11)&1
    }
    if (result["rax"]!=0 or result["rip"]!=RETURN or result["rsp"]!=rsp+0x50
        or result["rdx"]!=limit or result["rbx"]!=SAVED[3]
        or result["r12"]!=SAVED_R12):
        raise RuntimeError("Unexpected original game x64 loop/epilogue behavior")
    return result


def make_runner(cases):
    lines=[]
    for ex in cases:
        fields=[ex["index"],ex["limit"],ex["addend"]]
        encode=lambda xs: ",".join("UINT32_C("+str(x)+")" for x in xs)
        lines.append(" {"+encode(fields)+", {"+encode(ex["seed"])+"}, {"+
                     encode(ex["result"]["values"])+"}},")
    return r'''#include <stdint.h>
#include "mx_cfg_vm.h"
int lifted_indexed_loop(mx_cfg_state*,mx_cfg_memory*);
typedef struct {
 uint32_t index,limit,addend;
 uint32_t seed[32],expected[32];
} example;
static const example cases[]={
'''+ "\n".join(lines)+r'''
};
static uint8_t data[0x10000];
static uint8_t gueststack[0x10000];
static void copy32(uint8_t *p,uint32_t n){
  for(unsigned i=0;i<4;i++)p[i]=(uint8_t)(n>>(i*8));
}
static void copy64(uint8_t *p,uint64_t n){
  for(unsigned i=0;i<8;i++)p[i]=(uint8_t)(n>>(i*8));
}
static uint32_t get32(uint8_t *p){
  uint32_t n=0;
  for(unsigned i=0;i<4;i++)n|=(uint32_t)p[i]<<(i*8);
  return n;
}
int smoke(void){
 mx_cfg_region regions[]={
    {UINT64_C(0x200000),data,sizeof(data)},
    {UINT64_C(0x300000),gueststack,sizeof(gueststack)}
 };
 mx_cfg_memory mem={regions,2};
 for(uint32_t k=0;k<sizeof(cases)/sizeof(cases[0]);k++){
   const example *t=&cases[k];
   copy64(data+0x100+0x100,UINT64_C(0x202000));
   copy32(data+0x100+8,t->limit);
   for(uint32_t j=0;j<32;j++)copy32(data+0x2000+j*4,t->seed[j]);
   const uint64_t saved[4]={
      UINT64_C(0x1111122233334444),UINT64_C(0x5555566677778888),
      UINT64_C(0x99999aaabbbbcccc),UINT64_C(0xddddeeeeffffaaaa)
   };
   for(uint32_t j=0;j<4;j++)copy64(gueststack+0x8000+0x28+j*8,saved[j]);
   copy64(gueststack+0x8000+0x48,UINT64_C(0x400000));
   copy64(gueststack+0x8000+0x58,UINT64_C(0x0123456789abcdef));
   mx_cfg_state s={0};
   s.rsp=UINT64_C(0x308000);
   s.rbx=UINT64_C(0x200100);
   s.r12=t->addend;
   s.rdx=t->index;
   if(lifted_indexed_loop(&s,&mem)!=1)return 10;
   if(s.rax!=0 || s.rdx!=t->limit || s.rcx!=t->limit-1)return 11;
   if(s.rsp!=UINT64_C(0x308050) || s.rip!=UINT64_C(0x400000))return 12;
   if(s.r13!=saved[0] || s.rdi!=saved[1] || s.rbp!=saved[2] ||
      s.rbx!=saved[3] || s.r12!=UINT64_C(0x0123456789abcdef))return 13;
   if(s.zf!=1 || s.sf!=0 || s.cf!=0 || s.of!=0)return 14;
   for(uint32_t j=0;j<32;j++){
       if(get32(data+0x2000+j*4)!=t->expected[j])return 15;
   }
 }
 return 0;
}
#ifdef HOST_SMOKE
int main(void){return smoke();}
#endif
'''


def main():
    if len(sys.argv)!=3:raise SystemExit("usage: mxbikes_original_loop_differential.py game.exe reports")
    exe=Path(sys.argv[1])
    out=Path(sys.argv[2]);out.mkdir(parents=True,exist_ok=True)
    pe=PE(exe)
    if pe.inventory()["sha256"]!=EXPECTED:raise RuntimeError("Unexpected game executable revision")
    p,len_p=pe.directory(3)
    unwind={a:b for a,b,u in struct.iter_unpack("<III",pe.read_rva(p,len_p))}
    if unwind.get(BEGIN)!=END:
        raise RuntimeError(f"Original unwind bound mismatch for {BEGIN:#x}: {unwind.get(BEGIN)}")
    blob=pe.read_rva(BEGIN,END-BEGIN)
    source,metadata=lift_indexed_loop(blob,BEGIN,max_iterations=128)
    rng=random.Random(0x1fc710)
    examples=[]
    for n in range(32):
        start=n%3
        limit=start+1+(n%6)
        delta=rng.getrandbits(32)
        seed=[rng.getrandbits(32) for _ in range(LEN)]
        ref=x64_reference(blob,start,limit,delta,seed)
        examples.append({"index":start,"limit":limit,"addend":delta,"seed":seed,"result":ref})
    with tempfile.TemporaryDirectory(prefix="private-mxbikes-indexed-loop-",dir=out.parent) as td:
        temp=Path(td)
        generated=temp/"derived-original-loop.c"
        smoke=temp/"comparison.c"
        generated.write_text(source)
        smoke.write_text(make_runner(examples))
        root=Path(__file__).resolve().parents[1]/"arm64-lab"/"runtime"
        host=temp/"native-host"
        cmd=["cc","-O2","-std=c11","-Wall","-Wextra","-Werror","-DHOST_SMOKE",
             f"-I{root}",str(generated),str(smoke),"-o",str(host)]
        compiled=subprocess.run(cmd,text=True,capture_output=True)
        if compiled.returncode:raise RuntimeError("Host code error: "+compiled.stderr[-2400:])
        subprocess.run([str(host)],check=True)
        aarch64=temp/"original-indexed-loop-aarch64.elf"
        cmd=["clang","--target=aarch64-unknown-linux-gnu","-fuse-ld=lld","-nostdlib",
             "-static","-ffreestanding","-fno-stack-protector","-fno-builtin",
             "-O2","-std=c11",f"-I{root}","-Wl,-e,smoke",
             "-Wl,--build-id=none","-Wl,-z,max-page-size=4096",
             str(generated),str(smoke),"-o",str(aarch64)]
        compiled=subprocess.run(cmd,text=True,capture_output=True)
        if compiled.returncode:raise RuntimeError("ARM64 code error: "+compiled.stderr[-2400:])
        native_result=execute_arm64_elf(aarch64)
    report={
        "original_executable_sha256":EXPECTED,
        "original_rva":hex(BEGIN),"unwind_region_end":hex(END),
        "decoded_x64_instructions":metadata["decoded_instruction_count"],
        "original_backward_edges":1,
        "original_memory_operations":"indexed 32-bit guest array accumulation",
        "win64_saved_register_epilogue_validated":True,
        "differential_cases":len(examples),
        "host_match_count":len(examples),"aarch64_match_count":len(examples),
        "aarch64_original_loop_effects_executed":native_result["return_to_sentinel"],
        "original_game_booted":False,"native_ios_execution":False,
        "limitations":[
            "One pattern-specific original x64 loop region translated, NOT general binary lifting",
            "Original region starts after apparent prologue, not a proved complete callable function",
            "Bounded loop input range (index 0..2, limit <=8), with synthetic guest memory",
            "No OS/CRT/graphics/Steam code translated or executed on ARM64"
        ]
    }
    (out/"original-indexed-loop.json").write_text(json.dumps(report,indent=2)+"\n")
    lines=[
        "# Original MX Bikes indexed backward-loop ARM64 differential","",
        f"- Original x64 code interval: **{hex(BEGIN)}–{hex(END)}**",
        f"- Original instructions translated: **{metadata['decoded_instruction_count']}**",
        "- Original backward conditional branch, signed flags and memory indexing: exercised",
        "- Win64 saved-register epilogue and stack restoration: verified",
        f"- Original x64 vs native C vs generated AArch64: **{len(examples)}/{len(examples)} bitwise test matches**",
        "- Commercial original bytes and derived code: kept private",
        "",
        "**Original loop region, not a complete callable function or bootable native iOS game.**",""
    ]
    text="\n".join(lines)
    (out/"original-indexed-loop.md").write_text(text)
    print(text)

if __name__=="__main__":main()
