#!/usr/bin/env python3
"""Bounded original CRT callback differential plus shared-helper dependency probe.

Original MX Bikes code stays in ephemeral private CI. The six-instruction
exception-filter callback is executed as original x64 and compared against a
freestanding C/ARM64 implementation. The shared CRT helper is *only* decoded
and dependency-inventoried, never claimed to run or to be translated.
"""
from pathlib import Path
from collections import Counter
import hashlib
import json
import struct
import subprocess
import sys
import tempfile

from capstone import Cs, CS_ARCH_X86, CS_MODE_64
from capstone.x86 import X86_OP_MEM
from unicorn import Uc, UC_ARCH_X86, UC_MODE_64, UC_HOOK_CODE
from unicorn.x86_const import (
    UC_X86_REG_RAX, UC_X86_REG_RBX, UC_X86_REG_RCX,
    UC_X86_REG_RDI, UC_X86_REG_RSI, UC_X86_REG_R11,
    UC_X86_REG_RSP, UC_X86_REG_RIP, UC_X86_REG_EFLAGS,
)
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/"arm64-lab"))
from tools.pe_probe import PE
from tools.import_aot_smoke import execute_arm64_elf
from mxbikes_first_callee_emu import import_slots

SHA="4ae7de3854b4d0a18271679fb57a1f2fdf0b21804417b85dd82055078ea123b6"
BASE=0x140000000
CALLBACK=0x2ab714
CALLBACK_END=0x2ab72c
HELPER=0x2ab7e4
STOP=0x500000100
STUB=0x600000000
STACK=0x700000000
SP=STACK+0xfe08
WIN=SP-128

def disassembler():
    m=Cs(CS_ARCH_X86,CS_MODE_64)
    m.detail=True
    return m

def unwind_ranges(pe):
    address,size=pe.directory(3)
    if not address or size%12:raise RuntimeError("Invalid PE unwind directory")
    return [(a,b) for a,b,_ in struct.iter_unpack("<III",pe.read_rva(address,size))
            if 0<a<b]

def inspect(pe):
    uw=unwind_ranges(pe)
    if not any(a==CALLBACK and b==CALLBACK_END for a,b in uw):
        raise RuntimeError("Exception-filter callback's original unwind span moved")
    inst=list(disassembler().disasm(pe.read_rva(CALLBACK,24),CALLBACK))
    if len(inst)!=6 or [x.mnemonic for x in inst]!=[
        "sub","lea","call","xor","add","ret"]:
        raise RuntimeError("Original callback instruction shape changed")
    if [x.address for x in inst]!=[
        CALLBACK, CALLBACK+4,CALLBACK+11,CALLBACK+17,
        CALLBACK+19,CALLBACK+23]:
        raise RuntimeError("Original callback boundaries changed")
    lea=inst[1].operands[1]
    imp=inst[2].operands[0]
    if (lea.type!=X86_OP_MEM or imp.type!=X86_OP_MEM or
        inst[1].reg_name(lea.mem.base)!="rip" or
        inst[2].reg_name(imp.mem.base)!="rip" or
        lea.mem.index or imp.mem.index):
        raise RuntimeError("Unexpected RIP-relative callback/API operands")
    handler=inst[1].address+inst[1].size+lea.mem.disp
    slot=inst[2].address+inst[2].size+imp.mem.disp
    if (handler,slot)!=(0x2ab6d0,0x3210e8):
        raise RuntimeError("Original handler address or import IAT moved")
    imports={rva:(dll.lower(),name) for rva,dll,name in import_slots(pe)}
    if imports.get(slot)!=("kernel32.dll","SetUnhandledExceptionFilter"):
        raise RuntimeError("Original Win32 exception filter IAT identity changed")

    intervals=[(a,b) for a,b in uw if a<=HELPER<b]
    if len(intervals)!=1 or intervals[0][0]!=HELPER:
        raise RuntimeError("Shared helper is not a unique unwind-bounded entry")
    a,b=intervals[0]
    if b-a>2048:raise RuntimeError("Shared CRT helper needs a larger bounded survey")
    helper_inst=list(disassembler().disasm(pe.read_rva(a,b-a),a))
    if not helper_inst or sum(x.size for x in helper_inst)!=(b-a):
        raise RuntimeError("Shared CRT helper not completely decodable")
    targets=[]
    for x in helper_inst:
        if x.mnemonic in ("call","jmp","je","jne","ja","jb"):
            targets.append({"kind":x.mnemonic,"relative_rva":hex(x.address),
                            "operand_type":int(x.operands[0].type) if x.operands else 0})
    print("PRIVATE SHARED HELPER SUMMARY "+json.dumps({
        "rva":hex(HELPER),"instruction_count":len(helper_inst),
        "bounded_bytes":b-a,"mnemonics":dict(Counter(x.mnemonic for x in helper_inst)),
        "branches":targets},sort_keys=True))
    for x in helper_inst[:40]:
        print(" PRIVATE HELPER FORM "+hex(x.address)+" "+x.mnemonic+" "+x.op_str)
    return handler,slot,{"helper_rva":hex(HELPER),"helper_instruction_count":len(helper_inst),
                         "helper_bytes":b-a,"helper_calls_and_branches":len(targets),
                         "helper_statically_inventoried_only":True}

def cases():
    for i in range(16):
        yield {"rax":0x99880000+i*17,"rbx":0x123456780000+i*11,
               "rcx":0x77880000+i*43,"rdi":0x112233440000+i*37,
               "rsi":0x556677880000+i*21,"r11":0x9999aabb0000+i*13,
               "result":((0,1,0xffffffff,0x12345678)[i%4]),"zf":i%2}

REGS=(("rax",UC_X86_REG_RAX),("rbx",UC_X86_REG_RBX),
      ("rcx",UC_X86_REG_RCX),("rdi",UC_X86_REG_RDI),
      ("rsi",UC_X86_REG_RSI),("r11",UC_X86_REG_R11))

def reference_original(pe,handler,slot,case):
    emu=Uc(UC_ARCH_X86,UC_MODE_64)
    for page in {(BASE+CALLBACK)&~4095,(BASE+slot)&~4095}:
        emu.mem_map(page,4096)
    emu.mem_map(STUB,4096)
    emu.mem_map(STACK,0x10000)
    emu.mem_write(BASE+CALLBACK,pe.read_rva(CALLBACK,24))
    emu.mem_write(BASE+slot,struct.pack("<Q",STUB))
    emu.mem_write(STUB,b"\xc3")
    emu.mem_write(SP,struct.pack("<Q",STOP))
    for name,reg in REGS:emu.reg_write(reg,case[name])
    emu.reg_write(UC_X86_REG_RSP,SP)
    emu.reg_write(UC_X86_REG_RIP,BASE+CALLBACK)
    emu.reg_write(UC_X86_REG_EFLAGS,0x202|(case["zf"]<<6))
    seen={"calls":0,"instructions":0}
    valid={BASE+ins.address for ins in
           disassembler().disasm(pe.read_rva(CALLBACK,24),CALLBACK)}
    def hook(cpu,pc,size,ctx):
        if pc==STUB:
            seen["calls"]+=1
            if (cpu.reg_read(UC_X86_REG_RSP)!=SP-0x30 or
                cpu.reg_read(UC_X86_REG_RCX)!=BASE+handler):
                raise RuntimeError("Original Win64 SetUnhandledExceptionFilter ABI mismatch")
            cpu.reg_write(UC_X86_REG_RAX,case["result"])
        elif pc in valid:
            seen["instructions"]+=1
        else:
            raise RuntimeError("Original callback escaped bounded machine code")
    emu.hook_add(UC_HOOK_CODE,hook)
    emu.emu_start(BASE+CALLBACK,STOP,timeout=2_000_000,count=16)
    if (seen["calls"]!=1 or seen["instructions"]!=6 or
        emu.reg_read(UC_X86_REG_RIP)!=STOP or
        emu.reg_read(UC_X86_REG_RSP)!=SP+8):
        raise RuntimeError("Original six-instruction callback did not return")
    out={n:emu.reg_read(r) for n,r in REGS}
    out["rsp"]=emu.reg_read(UC_X86_REG_RSP)
    out["rip"]=emu.reg_read(UC_X86_REG_RIP)
    out["zf"]=int(bool(emu.reg_read(UC_X86_REG_EFLAGS)&64))
    out["stack"]=bytes(emu.mem_read(WIN,256))
    return out

SMOKE=r"""
#include <stdint.h>
#include "mx_crt_exception_callback.h"
#define WINDOW UINT64_C(WINDOW_ADDR)
#define SP UINT64_C(SP_ADDR)
#define PC UINT64_C(PC_ADDR)
#define HANDLER UINT64_C(HANDLER_ADDR)
typedef struct {
 uint64_t rax,rbx,rcx,rdi,rsi,r11,api_result,zf;
 uint64_t exp_rax,exp_rbx,exp_rcx,exp_rdi,exp_rsi,exp_r11;
 uint64_t exp_rsp,exp_rip,exp_zf;
 uint8_t exp_stack[256];
} fixture;
static const fixture data[]={__CASES__};
static uint8_t guest_stack[256];
static unsigned seen;
static int synthetic(void *ptr,uint64_t filter,uint64_t *old) {
  unsigned *count=(unsigned*)ptr;
  (*count)++;seen++;
  if(filter!=HANDLER)return 0;
  *old=UINT64_C(0xffff000012345678);
  return 1;
}
int smoke(void) {
  mx_cfg_region range={WINDOW,guest_stack,256};
  mx_cfg_memory m={&range,1};
  for(unsigned k=0;k<sizeof(data)/sizeof(data[0]);k++){
    const fixture *f=&data[k];
    for(unsigned j=0;j<256;j++)guest_stack[j]=0;
    seen=0;unsigned local_seen=0;
    const uint64_t caller=UINT64_C(CALLER_ADDR);
    if(!mx_cfg_transfer(&m,SP,(void*)&caller,8,1))return 2;
    mx_crt_state s={0};
    s.rax=f->rax;s.rbx=f->rbx;s.rcx=f->rcx;
    s.rdi=f->rdi;s.rsi=f->rsi;s.r11=f->r11;
    s.rsp=SP;s.rip=PC;s.zf=(uint8_t)f->zf;
    if(mx_crt_exception_callback6(&s,&m,PC,HANDLER,synthetic,&local_seen)
        !=MX_CRT_RETURNED)return 10+k;
    if(local_seen!=1||seen!=1||s.imports!=1||s.instructions!=6||
       s.rax!=f->exp_rax||s.rbx!=f->exp_rbx||s.rcx!=f->exp_rcx||
       s.rdi!=f->exp_rdi||s.rsi!=f->exp_rsi||s.r11!=f->exp_r11||
       s.rsp!=f->exp_rsp||s.rip!=f->exp_rip||s.zf!=f->exp_zf)
       return 50+k;
    for(unsigned j=0;j<256;j++)
       if(guest_stack[j]!=f->exp_stack[j])return 90+k;
  }
  return 0;
}
#ifdef HOST
int main(void){return smoke();}
#endif
"""

def encode(pairs):
    parts=[]
    for case,out in pairs:
        initial=[case[k] for k in ("rax","rbx","rcx","rdi","rsi","r11","result","zf")]
        expected=[out[k] for k in ("rax","rbx","rcx","rdi","rsi","r11","rsp","rip","zf")]
        stack="{"+",".join(str(c) for c in out["stack"])+"}"
        parts.append(" {"+",".join("UINT64_C("+str(v)+")" for v in initial+expected)+","+stack+"},")
    return "\n".join(parts)

def checked(args):
    result=subprocess.run(args,capture_output=True,text=True)
    if result.returncode:
        raise RuntimeError("Original callback cross-arch check failed (exit "+
                           str(result.returncode)+"): "+(result.stderr or result.stdout)[-2600:])

def run(exe,report):
    pe=PE(exe)
    if hashlib.sha256(pe.b).hexdigest()!=SHA:
        raise RuntimeError("Unexpected original MX Bikes executable revision")
    handler,slot,helper=inspect(pe)
    pairs=[(case,reference_original(pe,handler,slot,case)) for case in cases()]
    if len(pairs)!=16:raise RuntimeError("Exception callback fixture count changed")
    with tempfile.TemporaryDirectory(prefix="private-mx-exception-callback-") as t:
        root=Path(t)
        source=root/"private-smoke.c"
        source.write_text(SMOKE.replace("WINDOW_ADDR",str(WIN))
                          .replace("SP_ADDR",str(SP))
                          .replace("PC_ADDR",str(BASE+CALLBACK))
                          .replace("HANDLER_ADDR",str(BASE+handler))
                          .replace("CALLER_ADDR",str(STOP))
                          .replace("__CASES__",encode(pairs)))
        inc=ROOT/"arm64-lab"/"runtime"
        common=["-std=c11","-O2","-Wall","-Wextra","-Werror","-I"+str(inc)]
        host=root/"host"
        checked(["cc",*common,"-DHOST",str(source),"-o",str(host)])
        checked([str(host)])
        arm=root/"aarch64-smoke.elf"
        checked(["clang","--target=aarch64-unknown-linux-gnu","-fuse-ld=lld",
                 "-nostdlib","-static","-ffreestanding","-fno-builtin",
                 "-fno-stack-protector",*common,"-Wl,-e,smoke",
                 "-Wl,-z,max-page-size=4096","-Wl,--build-id=none",
                 str(source),"-o",str(arm)])
        result=execute_arm64_elf(arm,instruction_budget=650000,timeout_us=9000000)
    report.mkdir(parents=True,exist_ok=True)
    meta={"original_callback_rva":hex(CALLBACK),
          "callback_machine_instructions_executed":6,
          "original_x64_vs_host_C_vs_AArch64_passed":len(pairs),
          "synthetic_kernel32_hook":True,"real_windows_api_executed":False,
          "actual_initializer_arrays_executed":False,
          "arm64_elf_exit":result["arm64_smoke_exit"], **helper}
    (report/"crt-exception-callback-arm64.json").write_text(json.dumps(meta,indent=2)+"\n")
    summary="\n".join([
        "# MX Bikes real CRT callback proof and shared-helper survey","",
        "- SetUnhandledExceptionFilter callback: **16/16 original x64 / host C / AArch64 comparisons**",
        "- Six original instructions executed on x64; host and ARM64 model preserved guest argument, stack and return-state effects",
        "- Shared helper "+hex(HELPER)+": **"+str(helper["helper_instruction_count"])+" statically decoded instructions**, not executed",
        "- ARM64 ELF return: **"+str(result["arm64_smoke_exit"])+"**","",
        "**Kernel32 is synthetic; remaining initializer callbacks, real helper execution, engine, graphics and iOS remain unverified.**",""])
    (report/"crt-exception-callback-arm64.md").write_text(summary)
    print(summary)

if __name__=="__main__":
    if len(sys.argv)!=3:raise SystemExit("usage: script.py /private/game.exe report-dir")
    run(Path(sys.argv[1]),Path(sys.argv[2]))
