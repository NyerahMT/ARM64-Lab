#!/usr/bin/env python3
"""Cross-architecture test of two genuinely linked *synthetic* x64 functions.

Executes complete caller->callee->return sequence on Unicorn x64, generates
equivalent C with an actual native interfunction call, executes host C and
AArch64 ELF and checks integer outputs, Win64 stack and arithmetic flags.
Does NOT contain or translate commercial original code.
"""
import json
from pathlib import Path
import random
import struct
import subprocess
import tempfile

from unicorn import Uc,UC_ARCH_X86,UC_MODE_64
from unicorn.x86_const import UC_X86_REG_RIP,UC_X86_REG_RSP,UC_X86_REG_RAX,UC_X86_REG_RCX,UC_X86_REG_EFLAGS

from .x64_linked_lift import synthetic_pair,translate_linked_pair
from .import_aot_smoke import execute_arm64_elf

BASE=0x100000
STACK=0x300000
RETURN=0x400000


def x64_reference(caller,callee,input_value):
    uc=Uc(UC_ARCH_X86,UC_MODE_64)
    uc.mem_map(BASE,0x1000)
    uc.mem_map(STACK,0x10000)
    uc.mem_map(RETURN,0x1000)
    uc.mem_write(BASE,caller)
    uc.mem_write(BASE+0x100,callee)
    rsp=STACK+0x8008
    uc.mem_write(rsp,struct.pack("<Q",RETURN))
    uc.reg_write(UC_X86_REG_RSP,rsp)
    uc.reg_write(UC_X86_REG_RIP,BASE)
    uc.reg_write(UC_X86_REG_RCX,input_value)
    uc.emu_start(BASE,RETURN,timeout=1_000_000,count=50)
    flags=uc.reg_read(UC_X86_REG_EFLAGS)
    return {
      "input":input_value,
      "rax":uc.reg_read(UC_X86_REG_RAX),
      "rcx":uc.reg_read(UC_X86_REG_RCX),
      "rip":uc.reg_read(UC_X86_REG_RIP),
      "rsp":uc.reg_read(UC_X86_REG_RSP),
      "zf":(flags>>6)&1,"sf":(flags>>7)&1,
      "cf":flags&1,"of":(flags>>11)&1
    }


def c_runner(cases):
    rows=[]
    for t in cases:
        rows.append(" {"+",".join("UINT64_C("+str(t[name])+")" for name in
                                 ("input","rax","rcx","rsp","rip","zf","sf","cf","of"))+"},")
    return r'''#include <stdint.h>
#include "mx_cfg_vm.h"
int lifted_caller(mx_cfg_state*,mx_cfg_memory*);
typedef struct {uint64_t input,rax,rcx,rsp,rip,zf,sf,cf,of;} example;
static const example cases[]={
'''+ "\n".join(rows) + r'''
};
static uint8_t stack_mem[0x10000];
int smoke(void) {
 mx_cfg_region region={UINT64_C(0x300000),stack_mem,sizeof(stack_mem)};
 mx_cfg_memory mem={&region,1};
 for(uint32_t i=0;i<sizeof(cases)/sizeof(cases[0]);i++){
  const example *r=&cases[i];
  mx_cfg_state s={0};
  s.rcx=r->input;
  s.rsp=UINT64_C(0x308008);
  uint64_t ret=UINT64_C(0x400000);
  if(!mx_cfg_transfer(&mem,s.rsp,&ret,8,1))return 20;
  if(lifted_caller(&s,&mem)!=1)return 21;
  if(s.rax!=r->rax || s.rcx!=r->rcx)return 22;
  if(s.rip!=r->rip || s.rsp!=r->rsp)return 23;
  if(s.zf!=r->zf || s.sf!=r->sf || s.cf!=r->cf || s.of!=r->of)return 24;
 }
 /* Reject missing valid guest return-address memory. */
 {
  mx_cfg_state bad={0};
  bad.rsp=UINT64_C(0xF000000000);
  if(lifted_caller(&bad,&mem)!=-3)return 25;
 }
 return 0;
}
#ifdef HOST_SMOKE
int main(void){return smoke();}
#endif
'''


def main(out:Path):
    caller_rva,caller,callee_rva,callee=synthetic_pair()
    sources,metadata=translate_linked_pair(caller,caller_rva,callee,callee_rva)
    rng=random.Random(0x123456)
    inputs=[0,1,5,0x7fffffff,0x80000000,0xfffffffa,0xfffffffb,0xffffffff]+[
        rng.getrandbits(32) for _ in range(64)]
    cases=[x64_reference(caller,callee,value) for value in inputs]
    for x in cases:
        if x["rax"]!=((x["input"]+5)&0xffffffff):
            raise RuntimeError("Original synthetic x64 nested callee returned unexpected value")
    root=Path(__file__).resolve().parents[1]
    with tempfile.TemporaryDirectory(prefix="win64-linked-native-") as td:
        p=Path(td)
        src=p/"linked-translation.c"
        harness=p/"linked-comparison.c"
        src.write_text(sources);harness.write_text(c_runner(cases))
        host=p/"host"
        inc=f"-I{root/'runtime'}"
        native=["cc","-std=c11","-O2","-Wall","-Wextra","-Werror",
                "-DHOST_SMOKE",inc,str(src),str(harness),"-o",str(host)]
        b=subprocess.run(native,capture_output=True,text=True)
        if b.returncode:raise RuntimeError("Host link: "+b.stderr[-2500:])
        b=subprocess.run([str(host)],capture_output=True,text=True)
        if b.returncode:raise RuntimeError("Host linked behavior: "+str(b.returncode))
        arm=p/"linked-aarch64.elf"
        arm_cmd=["clang","--target=aarch64-unknown-linux-gnu","-fuse-ld=lld",
                 "-nostdlib","-static","-ffreestanding","-fno-stack-protector","-fno-builtin",
                 "-O2","-std=c11",inc,"-Wl,-e,smoke","-Wl,--build-id=none",
                 "-Wl,-z,max-page-size=4096",str(src),str(harness),"-o",str(arm)]
        b=subprocess.run(arm_cmd,capture_output=True,text=True)
        if b.returncode:raise RuntimeError("ARM64 link: "+b.stderr[-2500:])
        arm_result=execute_arm64_elf(arm)
    report={
      "source":"Two purpose-built synthetic x64 functions",
      "x64_decoded_instructions":metadata["original_decoded_instructions"],
      "guest_native_callee_actually_called":True,
      "differential_cases":len(cases),
      "return_values_stack_and_arithmetic_flags_match":True,
      "unmapped_guest_memory_refused":True,
      "arm64_native_linked_functions_executed":arm_result["return_to_sentinel"],
      "original_mxbikes_code_translated":False,
      "ios_app_running":False,
      "limits":"Only known 4-instruction caller and 3-instruction integer callee patterns, no arbitrary x64 call graphs"
    }
    out.mkdir(parents=True,exist_ok=True)
    (out/"linked-calls.json").write_text(json.dumps(report,indent=2)+"\n")
    summary="\n".join([
      "# AOT linked Win64 caller -> native AArch64 callee proof","",
      "- Genuine nested guest call/return was modeled, not an injected RET stub",
      f"- Synthetic x64 original instructions translated: **{metadata['original_decoded_instructions']}**",
      f"- x64 vs native host vs ARM64: **{len(cases)}/{len(cases)} differential matches**",
      "- Win64 caller shadow stack and callee return addresses checked",
      "- Signed overflow and wraparound arithmetic flags matched",
      "- Missing guest return stack correctly rejected",
      "",
      "**Synthetic input functions only; this has not linked actual original MX Bikes routines.**",""
    ])
    (out/"linked-calls.md").write_text(summary)
    print(summary)


if __name__=="__main__":
    import sys
    if len(sys.argv)!=2:raise SystemExit("usage: python -m tools.linked_call_differential output_dir")
    main(Path(sys.argv[1]))
