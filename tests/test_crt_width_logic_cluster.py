"""Synthetic 16-bit x64 loads, extension, SETNE and logic vs native AArch64.

All fixture instructions are independently authored; no program under test
outside this repository contributes binary code to this test.
"""
from pathlib import Path
import shutil
import struct
import subprocess
import tempfile
import unittest

from unicorn import Uc, UC_ARCH_X86, UC_MODE_64, UC_HOOK_CODE
from unicorn.x86_const import (
    UC_X86_REG_RAX, UC_X86_REG_R8, UC_X86_REG_R9,
    UC_X86_REG_R11, UC_X86_REG_RCX, UC_X86_REG_RDI,
    UC_X86_REG_RSP, UC_X86_REG_RIP, UC_X86_REG_EFLAGS,
)
from tools.crt_import_cluster_lift import lift_crt_import_cluster
from tools.import_aot_smoke import execute_arm64_elf

ROOT = Path(__file__).resolve().parents[1]
BASE = 0x140000000
RVA = 0x1000
STACK = 0x700000000
SP = STACK + 0xfe08
EXIT = 0x500000100
STUB = 0x600000000
ARG_BASE = 0x700020000
VALUES = (0, 1, 2, 0xff, 0x100, 0x101, 0x201, 0xff01, 0xffff)
ASM = r"""
.intel_syntax noprefix
.section .text
.globl wide_entry
wide_entry:
  sub rsp, 0x28
  movsxd r11, dword ptr [rip+signed_value]
  movzx eax, word ptr [rdi+0x18]
  test eax, eax
  setne al
  mov r9d, eax
  xor r8d, r8d
  or r8d, 2
  cmp word ptr [rip+compare_word], ax
  jbe at_least
  or r8d, 4
at_least:
  cmp ax, word ptr [rip+compare_word]
  jne not_equal
  or r8d, 8
not_equal:
  mov rcx, r9
  call QWORD PTR [rip+decode_slot]
  add rsp, 0x28
  ret
.globl wide_end
wide_end:
.org 0x200
decode_slot: .quad 0
.org 0x300
signed_value: .long -4
compare_word: .word 0x101
"""

def assemble(tmp):
    src=tmp/"fixture.S";obj=tmp/"fixture.o";binfile=tmp/"fixture.bin"
    src.write_text(ASM)
    subprocess.run(["as","--64",str(src),"-o",str(obj)],check=True)
    subprocess.run(["objcopy","-O","binary","-j",".text",str(obj),
                    str(binfile)],check=True)
    lines=subprocess.run(["nm","-a",str(obj)],check=True,
                         text=True,capture_output=True).stdout.splitlines()
    symbols={}
    for line in lines:
        parts=line.split()
        if len(parts)==3:
            try:symbols[parts[2]]=int(parts[0],16)
            except ValueError:pass
    assert symbols["wide_entry"]==0
    return binfile.read_bytes(),symbols

def reference(blob,symbols,value):
    cpu=Uc(UC_ARCH_X86,UC_MODE_64)
    for addr,size in ((BASE,0x10000),(STUB,4096),
                      (STACK,0x10000),(ARG_BASE,4096)):
        cpu.mem_map(addr,size)
    cpu.mem_write(BASE+RVA,blob)
    cpu.mem_write(BASE+RVA+symbols["decode_slot"],struct.pack("<Q",STUB))
    cpu.mem_write(STUB,b"\xc3")
    cpu.mem_write(SP,struct.pack("<Q",EXIT))
    cpu.mem_write(ARG_BASE+0x18,struct.pack("<H",value))
    cpu.reg_write(UC_X86_REG_RDI,ARG_BASE)
    cpu.reg_write(UC_X86_REG_RSP,SP)
    cpu.reg_write(UC_X86_REG_RIP,BASE+RVA)
    seen=[]
    def imported(emu,pc,size,ctx):
        if pc!=STUB:return
        if emu.reg_read(UC_X86_REG_RSP)!=SP-0x30:
            raise RuntimeError("Imported Win64 stack alignment changed")
        seen.append(emu.reg_read(UC_X86_REG_RCX))
        emu.reg_write(UC_X86_REG_RAX,0x12345678)
    cpu.hook_add(UC_HOOK_CODE,imported)
    cpu.emu_start(BASE+RVA,EXIT,timeout=2000000,count=80)
    if len(seen)!=1 or cpu.reg_read(UC_X86_REG_RIP)!=EXIT:
        raise RuntimeError("Synthetic x64 fixture did not return")
    regs=(UC_X86_REG_RAX,UC_X86_REG_RCX,UC_X86_REG_R8,
          UC_X86_REG_R9,UC_X86_REG_R11,UC_X86_REG_RDI,
          UC_X86_REG_RSP,UC_X86_REG_RIP)
    bits=cpu.reg_read(UC_X86_REG_EFLAGS)
    return (
        tuple(cpu.reg_read(reg) for reg in regs)+
        (int(bool(bits&64)),int(bool(bits&128)),int(bool(bits&1))),
        bytes(cpu.mem_read(SP-64,128)),
    )

PROGRAM=r"""
#include <stdint.h>
#include "mx_crt_cluster_guest.h"
#define SP UINT64_C(__SP__)
#define WIN UINT64_C(__WIN__)
#define PC UINT64_C(__PC__)
#define EXIT UINT64_C(__EXIT__)
#define GLOBAL UINT64_C(__GLOBAL__)
#define ARG UINT64_C(__ARG__)
typedef struct {
 uint64_t value, expected[11];
 uint8_t stack[128];
} sample;
static const sample fixtures[]={__FIXTURES__};
static uint8_t stack_mem[128],global_mem[8],arg_mem[64];
typedef struct {unsigned called;} context;
static int imported(void*arg,mx_crt_service_id id,
                    mx_crt_cluster_state*s,mx_cfg_memory*m,uint64_t rsp) {
 (void)m;
 context*c=(context*)arg;
 if(!c||id!=MX_CRT_SERVICE_DECODE_POINTER||
    rsp!=SP-0x30U||rsp!=s->rsp-8U)return 0;
 c->called++;
 s->rax=UINT64_C(0x12345678);
 return 1;
}
int smoke(void){
 mx_cfg_region ranges[3]={
   {WIN,stack_mem,128},{GLOBAL,global_mem,8},{ARG,arg_mem,64}
 };
 mx_cfg_memory mem={ranges,3};
 for(unsigned k=0;k<sizeof(fixtures)/sizeof(fixtures[0]);k++){
  const sample*f=&fixtures[k];
  for(unsigned j=0;j<128;j++)stack_mem[j]=0;
  for(unsigned j=0;j<64;j++)arg_mem[j]=0;
  global_mem[0]=252U;global_mem[1]=255U;
  global_mem[2]=255U;global_mem[3]=255U;
  global_mem[4]=1U;global_mem[5]=1U;
  arg_mem[24]=(uint8_t)(f->value&255U);
  arg_mem[25]=(uint8_t)((f->value>>8U)&255U);
  uint64_t original_exit=EXIT;
  if(!mx_cfg_transfer(&mem,SP,&original_exit,8,1))return 2;
  mx_crt_cluster_state s={0};
  s.rdi=ARG;s.rsp=SP;s.rip=PC;
  context ctx={0};
  if(lifted_crt_import_cluster(&s,&mem,imported,&ctx)!=
     MX_CRT_CLUSTER_RETURNED || ctx.called!=1 || s.imports!=1)
      return 10+k;
  uint64_t actual[11]={
    s.rax,s.rcx,s.r8,s.r9,s.r11,s.rdi,
    s.rsp,s.rip,s.zf,s.sf,s.cf
  };
  for(unsigned j=0;j<11;j++)
    if(actual[j]!=f->expected[j])return 50+k;
  for(unsigned j=0;j<128;j++)
    if(stack_mem[j]!=f->stack[j])return 100+k;
 }
 return 0;
}
#ifdef HOST
int main(void){return smoke();}
#endif
"""

def fixtures_to_c(fixtures):
    rows=[]
    for value,(expected,stack) in fixtures:
        e=",".join(f"UINT64_C({x})" for x in expected)
        b=",".join(str(x) for x in stack)
        rows.append("{"+f"UINT64_C({value})"+",{"+e+"},{"+b+"}}")
    return ",\n".join(rows)

class X64WidthLogicTests(unittest.TestCase):
    def test_synthetic_width_extension_and_condition_codes(self):
        if any(not shutil.which(x) for x in ("as","objcopy","nm","cc","clang")):
            self.skipTest("Assembler and compilers unavailable")
        with tempfile.TemporaryDirectory() as td:
            root=Path(td)
            blob,symbols=assemble(root)
            generated,meta=lift_crt_import_cluster(
                blob[:symbols["wide_end"]],RVA,
                {RVA+symbols["decode_slot"]:("msvcr90.dll","_decode_pointer")},
                {},BASE
            )
            self.assertEqual(meta["import_calls"],1)
            fixtures=[(x,reference(blob,symbols,x)) for x in VALUES]
            src=root/"generated.c"
            src.write_text(generated)
            runner=root/"runner.c"
            runner.write_text(
                PROGRAM.replace("__SP__",str(SP))
                .replace("__WIN__",str(SP-64))
                .replace("__PC__",str(BASE+RVA))
                .replace("__EXIT__",str(EXIT))
                .replace("__GLOBAL__",str(BASE+RVA+symbols["signed_value"]))
                .replace("__ARG__",str(ARG_BASE))
                .replace("__FIXTURES__",fixtures_to_c(fixtures))
            )
            flags=["-O2","-std=c11","-Wall","-Wextra","-Werror",
                   "-I"+str(ROOT/"runtime")]
            host=root/"host"
            subprocess.run(["cc",*flags,"-DHOST",str(src),str(runner),
                            "-o",str(host)],check=True)
            subprocess.run([str(host)],check=True)
            arm=root/"arm64.elf"
            subprocess.run(["clang","--target=aarch64-unknown-linux-gnu",
                "-fuse-ld=lld","-nostdlib","-static","-ffreestanding",
                "-fno-stack-protector","-fno-builtin",*flags,
                "-Wl,-e,smoke","-Wl,-z,max-page-size=4096",
                "-Wl,--build-id=none",str(src),str(runner),"-o",str(arm)],
                check=True)
            result=execute_arm64_elf(arm,instruction_budget=450000,
                                     timeout_us=6500000)
            self.assertEqual(result["arm64_smoke_exit"],0)

if __name__=="__main__":
    unittest.main()
