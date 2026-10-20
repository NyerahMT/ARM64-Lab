"""Synthetic x64 TEST/JNS and CMP/JBE / Win64 R9 vs native AArch64.

These independently authored instructions are NOT taken from a commercial
binary. Imported calls remain explicit deterministic test callbacks.
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
    UC_X86_REG_RCX, UC_X86_REG_RSP, UC_X86_REG_RIP, UC_X86_REG_EFLAGS,
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
INPUTS = (
    0, 1, 3, 4, 0xffffffff, 0x100000000,
    0x7fffffffffffffff, 0x8000000000000000, 0xffffffffffffffff,
)
ASM = r"""
.intel_syntax noprefix
.section .text
.globl condition_entry
condition_entry:
  sub rsp, 0x28
  mov r9, rcx
  test r9, r9
  jns nonnegative
  mov r8d, 0x33
  jmp done_branch
nonnegative:
  cmp r9d, 3
  jbe small
  mov r8d, 0x22
  jmp done_branch
small:
  mov r8d, 0x11
done_branch:
  mov rcx, r9
  call QWORD PTR [rip+decode_slot]
  add rsp, 0x28
  ret
.globl condition_end
condition_end:
.org 0x200
decode_slot: .quad 0
"""

def assemble(temp):
    asm=temp/"fixture.S"
    obj=temp/"fixture.o"
    out=temp/"fixture.bin"
    asm.write_text(ASM)
    subprocess.run(["as","--64",str(asm),"-o",str(obj)],check=True)
    subprocess.run(["objcopy","-O","binary","-j",".text",str(obj),str(out)],
                   check=True)
    lines=subprocess.run(["nm","-a",str(obj)],check=True,capture_output=True,
                         text=True).stdout.splitlines()
    names={}
    for line in lines:
        parts=line.split()
        if len(parts)==3:
            try:names[parts[2]]=int(parts[0],16)
            except ValueError:pass
    assert names["condition_entry"]==0
    return out.read_bytes(),names

def expected_tag(number):
    if number&(1<<63):return 0x33
    if number&0xffffffff<=3:return 0x11
    return 0x22

def reference(blob,names,number):
    cpu=Uc(UC_ARCH_X86,UC_MODE_64)
    cpu.mem_map(BASE,0x10000)
    cpu.mem_map(STUB,0x1000)
    cpu.mem_map(STACK,0x10000)
    cpu.mem_write(BASE+RVA,blob)
    cpu.mem_write(BASE+RVA+names["decode_slot"],struct.pack("<Q",STUB))
    cpu.mem_write(STUB,b"\xc3")
    cpu.mem_write(SP,struct.pack("<Q",EXIT))
    cpu.reg_write(UC_X86_REG_RSP,SP)
    cpu.reg_write(UC_X86_REG_RCX,number)
    cpu.reg_write(UC_X86_REG_R8,0x99887766)
    cpu.reg_write(UC_X86_REG_R9,0x88776655)
    cpu.reg_write(UC_X86_REG_RIP,BASE+RVA)
    visited=[]
    def hook(emu,pc,size,user):
        if pc==STUB:
            assert emu.reg_read(UC_X86_REG_RSP)==SP-0x30
            assert emu.reg_read(UC_X86_REG_RCX)==number
            assert emu.reg_read(UC_X86_REG_R8)==expected_tag(number)
            visited.append(pc)
            emu.reg_write(UC_X86_REG_RAX,0x1234abcd)
    cpu.hook_add(UC_HOOK_CODE,hook)
    cpu.emu_start(BASE+RVA,EXIT,timeout=2000000,count=80)
    assert visited==[STUB]
    assert cpu.reg_read(UC_X86_REG_RIP)==EXIT
    return (
        cpu.reg_read(UC_X86_REG_RAX),
        cpu.reg_read(UC_X86_REG_RCX),
        cpu.reg_read(UC_X86_REG_R8),
        cpu.reg_read(UC_X86_REG_R9),
        cpu.reg_read(UC_X86_REG_RSP),
        cpu.reg_read(UC_X86_REG_RIP),
        int(bool(cpu.reg_read(UC_X86_REG_EFLAGS)&64)),
        int(bool(cpu.reg_read(UC_X86_REG_EFLAGS)&128)),
        int(bool(cpu.reg_read(UC_X86_REG_EFLAGS)&1)),
        bytes(cpu.mem_read(SP-64,128)),
    )

PROGRAM = r"""
#include <stdint.h>
#include "mx_crt_cluster_guest.h"
#define SP UINT64_C(__SP__)
#define WIN UINT64_C(__WIN__)
#define PC UINT64_C(__PC__)
#define EXIT UINT64_C(__EXIT__)
typedef struct {
 uint64_t initial, expected[9];
 uint8_t stack[128];
} sample;
static const sample samples[]={__SAMPLES__};
static uint8_t guest_stack[128];
typedef struct {uint64_t expected_initial, expected_tag;unsigned calls;} ctx;
static int imported(void*context,mx_crt_service_id id,
                    mx_crt_cluster_state*s,mx_cfg_memory*m,uint64_t callee_rsp){
 (void)m;
 ctx *p=(ctx*)context;
 if(id!=MX_CRT_SERVICE_DECODE_POINTER || !p ||
    callee_rsp!=SP-0x30U || s->rsp-8U!=callee_rsp ||
    s->rcx!=p->expected_initial || s->r8!=p->expected_tag)return 0;
 p->calls++;
 s->rax=UINT64_C(0x1234abcd);
 return 1;
}
int smoke(void){
 mx_cfg_region region={WIN,guest_stack,128};
 mx_cfg_memory mem={&region,1};
 for(unsigned k=0;k<sizeof(samples)/sizeof(samples[0]);k++){
   const sample*f=&samples[k];
   for(unsigned j=0;j<128;j++)guest_stack[j]=0;
   uint64_t ret=EXIT;
   if(!mx_cfg_transfer(&mem,SP,&ret,8,1))return 3;
   mx_crt_cluster_state s={0};
   s.rcx=f->initial;s.r8=UINT64_C(0x99887766);
   s.r9=UINT64_C(0x88776655);s.rsp=SP;s.rip=PC;
   ctx c={f->initial,((f->initial>>63U)!=0U?0x33U:
                    ((uint32_t)f->initial<=3U?0x11U:0x22U)),0};
   int status=lifted_crt_import_cluster(&s,&mem,imported,&c);
   if(status!=MX_CRT_CLUSTER_RETURNED||c.calls!=1||s.imports!=1)return 10+k;
   uint64_t got[9]={s.rax,s.rcx,s.r8,s.r9,s.rsp,s.rip,s.zf,s.sf,s.cf};
   for(unsigned j=0;j<9;j++){
     if(got[j]!=f->expected[j])return 50+k;
   }
   for(unsigned j=0;j<128;j++){
     if(guest_stack[j]!=f->stack[j])return 100+k;
   }
 }
 return 0;
}
#ifdef HOST
int main(void){return smoke();}
#endif
"""

def fixture_source(items):
    chunks=[]
    for number,out in items:
        expect=out[:9]
        initial="UINT64_C("+str(number)+")"
        fields=",".join("UINT64_C("+str(x)+")" for x in expect)
        raw=",".join(str(x) for x in out[9])
        chunks.append("{"+initial+",{"+fields+"},{"+raw+"}}")
    return ",\n".join(chunks)

class X64ConditionClusterTests(unittest.TestCase):
    def test_real_x64_synthetic_branch_paths_match_executed_aarch64(self):
        required=("as","objcopy","nm","cc","clang")
        if any(not shutil.which(x) for x in required):
            self.skipTest("Assembler/compilers unavailable")
        with tempfile.TemporaryDirectory() as td:
            root=Path(td)
            blob,symbols=assemble(root)
            native,meta=lift_crt_import_cluster(
                blob[:symbols["condition_end"]],RVA,
                {RVA+symbols["decode_slot"]:
                 ("msvcr90.dll","_decode_pointer")},{},BASE
            )
            self.assertEqual(meta["import_calls"],1)
            self.assertEqual(meta["verified_internal_branches"],4)
            expected=[(x,reference(blob,symbols,x)) for x in INPUTS]
            source=root/"native.c"
            source.write_text(native)
            runner=root/"runner.c"
            runner.write_text(PROGRAM.replace("__SP__",str(SP))
                  .replace("__WIN__",str(SP-64))
                  .replace("__PC__",str(BASE+RVA))
                  .replace("__EXIT__",str(EXIT))
                  .replace("__SAMPLES__",fixture_source(expected)))
            flags=["-O2","-std=c11","-Wall","-Wextra","-Werror",
                   "-I"+str(ROOT/"runtime")]
            host=root/"host"
            subprocess.run(["cc",*flags,"-DHOST",str(source),str(runner),
                            "-o",str(host)],check=True)
            subprocess.run([str(host)],check=True)
            elf=root/"arm64.elf"
            subprocess.run(["clang","--target=aarch64-unknown-linux-gnu",
                "-fuse-ld=lld","-nostdlib","-static","-ffreestanding",
                "-fno-stack-protector","-fno-builtin",*flags,
                "-Wl,-e,smoke","-Wl,-z,max-page-size=4096",
                "-Wl,--build-id=none",
                str(source),str(runner),"-o",str(elf)],check=True)
            report=execute_arm64_elf(elf,instruction_budget=320000,
                                     timeout_us=5500000)
            self.assertEqual(report["arm64_smoke_exit"],0)

if __name__=="__main__":
    unittest.main()
