#!/usr/bin/env python3
"""Run the original eight-instruction CRT shared wrapper on x64 and ARM64.

The direct child callee is an injected deterministic RET stub; its authentic
body is NOT executed. The wrapper itself is original executable machine code.
Everything game-derived stays in ephemeral PRIVATE GitHub Actions memory.
"""
from pathlib import Path
import hashlib
import json
import struct
import subprocess
import sys
import tempfile

from unicorn import Uc,UC_ARCH_X86,UC_MODE_64,UC_HOOK_CODE
from unicorn.x86_const import (
    UC_X86_REG_RAX,UC_X86_REG_RBX,UC_X86_REG_RCX,
    UC_X86_REG_RDI,UC_X86_REG_RSI,UC_X86_REG_R11,
    UC_X86_REG_RSP,UC_X86_REG_RIP,UC_X86_REG_EFLAGS
)
from capstone.x86 import X86_OP_IMM
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/"arm64-lab"))
from tools.pe_probe import PE
from tools.import_aot_smoke import execute_arm64_elf
from mxbikes_crt_exception_callback_differential import (
    SHA,BASE,STOP,STACK,SP,WIN,REGS,cases,disassembler,
    inspect,unwind_ranges
)
ENTRY=0x2ab7e4
CALLEE=0x2ab734
LENGTH=0x17

def original(pe,case):
    cpu=Uc(UC_ARCH_X86,UC_MODE_64)
    code=pe.read_rva(ENTRY,LENGTH)
    ins=list(disassembler().disasm(code,ENTRY))
    if (len(ins)!=8 or [x.mnemonic for x in ins]!=
        ["sub","call","neg","sbb","neg","dec","add","ret"] or
        ins[1].operands[0].type!=X86_OP_IMM or
        ins[1].operands[0].imm!=CALLEE):
        raise RuntimeError("Original shared wrapper has an unexpected shape")
    if not any(a==ENTRY and b==ENTRY+LENGTH for a,b in unwind_ranges(pe)):
        raise RuntimeError("Original shared CRT helper unwind boundary moved")
    cpu.mem_map((BASE+ENTRY)&~4095,4096)
    cpu.mem_map(STACK,0x10000)
    cpu.mem_write(BASE+ENTRY,code)
    cpu.mem_write(BASE+CALLEE,b"\xc3")
    cpu.mem_write(SP,struct.pack("<Q",STOP))
    for name,reg in REGS:cpu.reg_write(reg,case[name])
    cpu.reg_write(UC_X86_REG_RSP,SP)
    cpu.reg_write(UC_X86_REG_RIP,BASE+ENTRY)
    cpu.reg_write(UC_X86_REG_EFLAGS,0x202|(case["zf"]<<6))
    pcs={BASE+x.address for x in ins}
    seen={"instructions":0,"child":0}
    def hook(emu,pc,size,context):
        if pc==BASE+CALLEE:
            seen["child"]+=1
            if (emu.reg_read(UC_X86_REG_RSP)!=SP-0x30 or
                emu.reg_read(UC_X86_REG_RCX)!=case["rcx"]):
                raise RuntimeError("Original shared helper Win64 direct-call ABI changed")
            emu.reg_write(UC_X86_REG_RAX,case["result"])
        elif pc in pcs:
            seen["instructions"]+=1
        else:
            raise RuntimeError("Execution escaped bounded shared helper")
    cpu.hook_add(UC_HOOK_CODE,hook)
    cpu.emu_start(BASE+ENTRY,STOP,timeout=2000000,count=24)
    if (seen!={"instructions":8,"child":1} or
        cpu.reg_read(UC_X86_REG_RIP)!=STOP or
        cpu.reg_read(UC_X86_REG_RSP)!=SP+8):
        raise RuntimeError("Original shared helper did not complete exact path")
    result={name:cpu.reg_read(reg) for name,reg in REGS}
    result["rsp"]=cpu.reg_read(UC_X86_REG_RSP)
    result["rip"]=cpu.reg_read(UC_X86_REG_RIP)
    result["zf"]=int(bool(cpu.reg_read(UC_X86_REG_EFLAGS)&64))
    result["stack"]=bytes(cpu.mem_read(WIN,256))
    return result

HARNESS=r"""
#include <stdint.h>
#include "mx_crt_shared_helper.h"
#define WINDOW UINT64_C(WINDOW_ADDR)
#define SP UINT64_C(SP_ADDR)
#define PC UINT64_C(PC_ADDR)
typedef struct {
 uint64_t rax,rbx,rcx,rdi,rsi,r11,child,zf;
 uint64_t e_rax,e_rbx,e_rcx,e_rdi,e_rsi,e_r11;
 uint64_t e_rsp,e_rip,e_zf;
 uint8_t e_stack[256];
} fixture;
static const fixture data[]={__CASES__};
static uint8_t guest_stack[256];
static unsigned invoked;
static int fake_child(void *p,uint64_t arg,uint64_t *out){
  fixture *f=(fixture*)p;
  invoked++;
  if(arg!=f->rcx)return 0;
  *out=f->child;return 1;
}
int smoke(void) {
  mx_cfg_region range={WINDOW,guest_stack,256};
  mx_cfg_memory mem={&range,1};
  for(unsigned k=0;k<sizeof(data)/sizeof(data[0]);k++){
    const fixture *f=&data[k];
    for(unsigned j=0;j<256;j++){guest_stack[j]=0;}
    const uint64_t caller=UINT64_C(CALLER_ADDR);
    if(!mx_cfg_transfer(&mem,SP,(void*)&caller,8,1))return 3;
    mx_crt_state s={0};
    s.rip=PC;s.rsp=SP;s.rax=f->rax;s.rbx=f->rbx;
    s.rcx=f->rcx;s.rdi=f->rdi;s.rsi=f->rsi;s.r11=f->r11;
    s.zf=(uint8_t)f->zf;
    invoked=0;
    if(mx_crt_shared_helper8(&s,&mem,PC,fake_child,(void*)f)
       !=MX_CRT_RETURNED||invoked!=1)return 10+k;
    if(s.rax!=f->e_rax||s.rbx!=f->e_rbx||s.rcx!=f->e_rcx||
       s.rdi!=f->e_rdi||s.rsi!=f->e_rsi||s.r11!=f->e_r11||
       s.rsp!=f->e_rsp||s.rip!=f->e_rip||s.zf!=f->e_zf)
       return 50+k;
    for(unsigned j=0;j<256;j++)
      if(guest_stack[j]!=f->e_stack[j])return 100+k;
  }
  return 0;
}
#ifdef HOST
int main(void){return smoke();}
#endif
"""

def encoded(rows):
    parts=[]
    for f,e in rows:
        initial=[f[k] for k in ("rax","rbx","rcx","rdi","rsi","r11","result","zf")]
        expected=[e[k] for k in ("rax","rbx","rcx","rdi","rsi","r11","rsp","rip","zf")]
        raw="{"+",".join(str(x) for x in e["stack"])+"}"
        parts.append(" {"+",".join("UINT64_C("+str(v)+")" for v in initial+expected)+","+raw+"},")
    return "\n".join(parts)

def checked(command):
    p=subprocess.run(command,capture_output=True,text=True)
    if p.returncode:
        raise RuntimeError("Original shared helper differential failed ("+
                           str(p.returncode)+"): "+(p.stderr or p.stdout)[-3300:])

def run(exe,output):
    pe=PE(exe)
    if hashlib.sha256(pe.b).hexdigest()!=SHA:
        raise RuntimeError("Original executable hash mismatch")
    _,_,meta=inspect(pe)
    rows=[(c,original(pe,c)) for c in cases()]
    if len(rows)!=16 or meta["helper_instruction_count"]!=8:
        raise RuntimeError("Shared original wrapper inventory mismatch")
    with tempfile.TemporaryDirectory(prefix="mx-private-shared-helper-") as t:
        root=Path(t);source=root/"private-wrapper.c"
        source.write_text(HARNESS.replace("WINDOW_ADDR",str(WIN))
                          .replace("SP_ADDR",str(SP))
                          .replace("PC_ADDR",str(BASE+ENTRY))
                          .replace("CALLER_ADDR",str(STOP))
                          .replace("__CASES__",encoded(rows)))
        inc=ROOT/"arm64-lab"/"runtime"
        flags=["-std=c11","-O2","-Wall","-Wextra","-Werror","-I"+str(inc)]
        host=root/"host"
        checked(["cc",*flags,"-DHOST",str(source),"-o",str(host)])
        checked([str(host)])
        arm=root/"wrapper-aarch64.elf"
        checked(["clang","--target=aarch64-unknown-linux-gnu","-fuse-ld=lld",
                 "-nostdlib","-static","-ffreestanding","-fno-builtin",
                 "-fno-stack-protector",*flags,"-Wl,-e,smoke",
                 "-Wl,-z,max-page-size=4096","-Wl,--build-id=none",
                 str(source),"-o",str(arm)])
        native=execute_arm64_elf(arm,instruction_budget=650000,timeout_us=9000000)
    output.mkdir(parents=True,exist_ok=True)
    result={"original_shared_helper_rva":hex(ENTRY),"original_child_rva":hex(CALLEE),
            "real_original_x64_wrapper_instructions_executed":8,
            "synthetic_direct_callee":True,"real_direct_callee_executed":False,
            "original_x64_vs_host_C_vs_AArch64_passed":len(rows),
            "arm64_elf_exit":native["arm64_smoke_exit"],
            "original_callback_arrays_executed":False,
            "game_or_ios_booted":False}
    (output/"crt-shared-helper-arm64.json").write_text(json.dumps(result,indent=2)+"\n")
    summary="\n".join(["# MX Bikes shared CRT helper cross-architecture differential","",
        "- Original 8-instruction wrapper (RVA 0x2AB7E4): **16/16 original x64 / native C / AArch64 comparisons passed**",
        "- Both zero and nonzero results from its original direct callee call boundary tested",
        "- Guest registers, Win64 argument, nested CALL return slot and 256-byte stack matched",
        "- ARM64 ELF exit: **"+str(native["arm64_smoke_exit"])+"**","",
        "**The underlying callee RVA 0x2AB734 is synthetic, NOT executed. No full initializer, graphics, engine or iOS boot.**",""])
    (output/"crt-shared-helper-arm64.md").write_text(summary)
    print(summary)

if __name__=="__main__":
    if len(sys.argv)!=3:raise SystemExit("usage: script.py /private/original.exe report-dir")
    run(Path(sys.argv[1]),Path(sys.argv[2]))
