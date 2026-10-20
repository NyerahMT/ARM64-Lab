"""Synthetic Win64 register ADD/SUB + carry-branch full x64/host/ARM64 test.

No commercially derived code or data. Uses Capstone/Unicorn/x64 assembler to
prove actual register arithmetic and status-flag semantics with native ARM64.
"""
from pathlib import Path
import shutil
import struct
import subprocess
import tempfile
import unittest

from unicorn import Uc, UC_ARCH_X86, UC_MODE_64, UC_HOOK_CODE
from unicorn.x86_const import (
    UC_X86_REG_RAX, UC_X86_REG_RCX, UC_X86_REG_R8,
    UC_X86_REG_R9, UC_X86_REG_RSP, UC_X86_REG_RIP,
    UC_X86_REG_EFLAGS,
)
from tools.crt_import_cluster_lift import lift_crt_import_cluster
from tools.import_aot_smoke import execute_arm64_elf

ROOT = Path(__file__).resolve().parents[1]
BASE = 0x140000000
RVA = 0x1000
STACK = 0x700000000
SP = STACK+0xfe08
END = 0x500000100
STUB = 0x600000000
PAIRS = (
    (1,2), (0,0), (0xffffffffffffffff,1),
    (0xffffffffffffffff,0xffffffffffffffff),
    (0x8000000000000000,0x8000000000000000),
    (0xabcdefabcdefabcd,0x123456789abcdef0),
    (0xffffffff,2),(0x100000000,0xffffffff),
)
ASM = r"""
.intel_syntax noprefix
.section .text
.globl arithmetic_entry
arithmetic_entry:
  sub rsp,0x28
  mov r8,rcx
  add r8,r9
  jb overflow
  mov eax,0x11
  jmp normalized
overflow:
  mov eax,0x22
normalized:
  sub eax,3
  mov rcx,r8
  call QWORD PTR [rip+decode_slot]
  add rsp,0x28
  ret
.globl arithmetic_end
arithmetic_end:
.org 0x100
decode_slot: .quad 0
"""

def assembled(work):
    source=work/"arith.S";obj=work/"arith.o";raw=work/"arith.bin"
    source.write_text(ASM)
    subprocess.run(["as","--64",str(source),"-o",str(obj)],check=True)
    subprocess.run(["objcopy","-O","binary","-j",".text",str(obj),
                    str(raw)],check=True)
    sym={}
    stdout=subprocess.run(["nm","-a",str(obj)],capture_output=True,
                          text=True,check=True).stdout
    for line in stdout.splitlines():
        parts=line.split()
        if len(parts)==3:
            try:sym[parts[2]]=int(parts[0],16)
            except ValueError:pass
    return raw.read_bytes(),sym

def reference(blob,sym,a,b):
    uc=Uc(UC_ARCH_X86,UC_MODE_64)
    for region,size in ((BASE,0x10000),(STACK,0x10000),(STUB,4096)):
        uc.mem_map(region,size)
    uc.mem_write(BASE+RVA,blob)
    uc.mem_write(BASE+RVA+sym["decode_slot"],struct.pack("<Q",STUB))
    uc.mem_write(STUB,b"\xc3")
    uc.mem_write(SP,struct.pack("<Q",END))
    uc.reg_write(UC_X86_REG_RCX,a)
    uc.reg_write(UC_X86_REG_R9,b)
    uc.reg_write(UC_X86_REG_RSP,SP)
    uc.reg_write(UC_X86_REG_RIP,BASE+RVA)
    observations=[]
    def observe(cpu,pc,size,ctx):
        if pc!=STUB:return
        if cpu.reg_read(UC_X86_REG_RSP)!=SP-0x30:
            raise RuntimeError("Synthetic x64 caller stack changed")
        observations.append((cpu.reg_read(UC_X86_REG_RAX),
                             cpu.reg_read(UC_X86_REG_RCX)))
        cpu.reg_write(UC_X86_REG_RAX,0x55667788)
    uc.hook_add(UC_HOOK_CODE,observe)
    uc.emu_start(BASE+RVA,END,timeout=2500000,count=100)
    if len(observations)!=1 or uc.reg_read(UC_X86_REG_RIP)!=END:
        raise RuntimeError("Synthetic arithmetic x64 execution diverged")
    regs=(UC_X86_REG_RAX,UC_X86_REG_RCX,UC_X86_REG_R8,
          UC_X86_REG_R9,UC_X86_REG_RSP,UC_X86_REG_RIP)
    flags=uc.reg_read(UC_X86_REG_EFLAGS)
    return (
        tuple(uc.reg_read(k) for k in regs) +
        tuple(int(bool(flags&flag)) for flag in (64,128,1)),
        observations[0],
        bytes(uc.mem_read(SP-64,128))
    )

C_SOURCE=r"""
#include <stdint.h>
#include "mx_crt_cluster_guest.h"
#define SP UINT64_C(__SP__)
#define WIN UINT64_C(__WIN__)
#define PC UINT64_C(__PC__)
#define END UINT64_C(__END__)
typedef struct {
 uint64_t a,b,expected[9],service_rax,service_rcx;
 uint8_t stack[128];
} fixture;
static const fixture fixtures[]={__FIXTURES__};
static uint8_t guest_stack[128];
typedef struct {const fixture *f;unsigned calls;} import_context;
static int on_import(void*opaque,mx_crt_service_id service,
                     mx_crt_cluster_state *s,mx_cfg_memory *m,
                     uint64_t rsp) {
 (void)m;
 import_context *ctx=(import_context*)opaque;
 if(!ctx||service!=MX_CRT_SERVICE_DECODE_POINTER||
    rsp!=SP-0x30U||ctx->calls||
    s->rax!=ctx->f->service_rax||
    s->rcx!=ctx->f->service_rcx)return 0;
 ctx->calls++;
 s->rax=UINT64_C(0x55667788);
 return 1;
}
int smoke(void){
 mx_cfg_region region={WIN,guest_stack,128};
 mx_cfg_memory memory={&region,1};
 for(unsigned k=0;k<sizeof(fixtures)/sizeof(fixtures[0]);k++) {
   const fixture *f=&fixtures[k];
   for(unsigned i=0;i<128;i++)guest_stack[i]=0;
   uint64_t original_return=END;
   if(!mx_cfg_transfer(&memory,SP,&original_return,8,1))return 1;
   mx_crt_cluster_state state={0};
   state.rcx=f->a;state.r9=f->b;state.rsp=SP;state.rip=PC;
   import_context context={f,0};
   if(lifted_crt_import_cluster(&state,&memory,on_import,&context)!=
       MX_CRT_CLUSTER_RETURNED || context.calls!=1U)return 10+k;
   const uint64_t actual[9]={
       state.rax,state.rcx,state.r8,state.r9,state.rsp,state.rip,
       state.zf,state.sf,state.cf
   };
   for(unsigned i=0;i<9;i++)
       if(actual[i]!=f->expected[i])return 40+k;
   for(unsigned i=0;i<128;i++)
       if(guest_stack[i]!=f->stack[i])return 80+k;
 }
 return 0;
}
#ifdef HOST
int main(void){return smoke();}
#endif
"""

def cfixtures(items):
    result=[]
    for (a,b),(registers,call_state,stack) in items:
        values=",".join("UINT64_C("+str(n)+")" for n in registers)
        raw=",".join(str(x) for x in stack)
        result.append("{UINT64_C("+str(a)+"),UINT64_C("+str(b)+"),{"+
                      values+"},UINT64_C("+str(call_state[0])+"),UINT64_C("+
                      str(call_state[1])+"),{"+raw+"}}")
    return ",\n".join(result)

class ArithmeticClusterTests(unittest.TestCase):
    def test_register_carry_and_native_differential(self):
        if any(shutil.which(x) is None for x in ("as","objcopy","nm","cc","clang")):
            self.skipTest("Assembler and host/native compiler unavailable")
        with tempfile.TemporaryDirectory() as td:
            work=Path(td)
            blob,sym=assembled(work)
            generated,meta=lift_crt_import_cluster(
                blob[:sym["arithmetic_end"]],RVA,
                {RVA+sym["decode_slot"]:("msvcr90.dll","_decode_pointer")},
                {},BASE
            )
            self.assertEqual(meta["import_calls"],1)
            fixtures=[(pair,reference(blob,sym,*pair)) for pair in PAIRS]
            src=work/"translated.c";src.write_text(generated)
            harness=work/"harness.c"
            harness.write_text(
                C_SOURCE.replace("__SP__",str(SP))
                .replace("__WIN__",str(SP-64))
                .replace("__PC__",str(BASE+RVA))
                .replace("__END__",str(END))
                .replace("__FIXTURES__",cfixtures(fixtures))
            )
            opts=["-std=c11","-O2","-Wall","-Wextra","-Werror",
                  "-I"+str(ROOT/"runtime")]
            exe=work/"host"
            subprocess.run(["cc",*opts,"-DHOST",str(src),str(harness),
                            "-o",str(exe)],check=True)
            subprocess.run([str(exe)],check=True)
            arm=work/"arm.elf"
            subprocess.run([
                "clang","--target=aarch64-unknown-linux-gnu",
                "-fuse-ld=lld","-nostdlib","-static","-ffreestanding",
                "-fno-builtin","-fno-stack-protector",
                *opts,"-Wl,-e,smoke","-Wl,-z,max-page-size=4096",
                "-Wl,--build-id=none",str(src),str(harness),"-o",str(arm)
            ],check=True)
            result=execute_arm64_elf(arm,instruction_budget=470000,
                                     timeout_us=6500000)
            self.assertEqual(result["arm64_smoke_exit"],0)

if __name__=="__main__":
    unittest.main()
