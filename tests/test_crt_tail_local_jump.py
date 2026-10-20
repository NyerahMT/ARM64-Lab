"""Synthetic x64 tail JMP to a separately compiled native callee.

Independently authored pair of Win64 routines. Original x64 Unicorn vs native
host C vs executed AArch64 compare entire bounded guest state. Terminal
tailcall DOES NOT push another return address.
"""
from pathlib import Path
import shutil
import struct
import subprocess
import tempfile
import unittest

from unicorn import Uc,UC_ARCH_X86,UC_MODE_64,UC_HOOK_CODE
from unicorn.x86_const import (
    UC_X86_REG_RAX,UC_X86_REG_RCX,UC_X86_REG_R9,UC_X86_REG_RSP,
    UC_X86_REG_RIP,UC_X86_REG_EFLAGS,
)
from tools.crt_import_cluster_lift import (
    lift_crt_import_cluster, UnsupportedCluster,
)
from tools.import_aot_smoke import execute_arm64_elf

ROOT=Path(__file__).resolve().parents[1]
BASE=0x140000000
RVA=0x1000
STACK=0x700000000
SP=STACK+0xfe08
END=0x500000100
STUB=0x600000000
CASES=(0,1,42,0xffffffff,0x123456789abcdef0)
ASM=r"""
.intel_syntax noprefix
.section .text
.globl entry
entry:
  sub rsp,0x28
  mov r9,rcx
  call QWORD PTR [rip+before_slot]
  add rsp,0x28
  jmp target
.globl entry_end
entry_end:
.globl target
target:
  sub rsp,0x28
  mov rcx,r9
  call QWORD PTR [rip+after_slot]
  add rsp,0x28
  ret
.globl target_end
target_end:
.org 0x200
before_slot: .quad 0
after_slot: .quad 0
"""

def assemble(work):
    f=work/"fixture.S";o=work/"fixture.o";out=work/"fixture.bin"
    f.write_text(ASM)
    subprocess.run(["as","--64",str(f),"-o",str(o)],check=True)
    subprocess.run(["objcopy","-O","binary","-j",".text",str(o),str(out)],check=True)
    syms={}
    stdout=subprocess.run(["nm","-a",str(o)],capture_output=True,
                          text=True,check=True).stdout
    for line in stdout.splitlines():
        pieces=line.split()
        if len(pieces)==3:
            try:syms[pieces[2]]=int(pieces[0],16)
            except ValueError:pass
    return out.read_bytes(),syms

def original(blob,sym,value):
    uc=Uc(UC_ARCH_X86,UC_MODE_64)
    for addr,size in ((BASE,0x10000),(STACK,0x10000),(STUB,4096)):
        uc.mem_map(addr,size)
    uc.mem_write(BASE+RVA,blob)
    for name,addr in (("before_slot",STUB),("after_slot",STUB+16)):
        uc.mem_write(BASE+RVA+sym[name],struct.pack("<Q",addr))
        uc.mem_write(addr,b"\xc3")
    uc.mem_write(SP,struct.pack("<Q",END))
    uc.reg_write(UC_X86_REG_RCX,value)
    uc.reg_write(UC_X86_REG_RSP,SP)
    uc.reg_write(UC_X86_REG_RIP,BASE+RVA)
    trace=[]
    def intercept(cpu,pc,size,opaque):
        if pc not in (STUB,STUB+16):return
        if cpu.reg_read(UC_X86_REG_RSP)!=SP-0x30:
            raise RuntimeError("Original import stack layout changed")
        if pc==STUB:
            if cpu.reg_read(UC_X86_REG_RCX)!=value:
                raise RuntimeError("Original first import args changed")
            cpu.reg_write(UC_X86_REG_RAX,0xdeadbeef)
            trace.append(1)
        else:
            if cpu.reg_read(UC_X86_REG_RCX)!=value:
                raise RuntimeError("Original tail target args changed")
            cpu.reg_write(UC_X86_REG_RAX,0x12345678)
            trace.append(2)
    uc.hook_add(UC_HOOK_CODE,intercept)
    uc.emu_start(BASE+RVA,END,timeout=2000000,count=90)
    if trace!=[1,2] or uc.reg_read(UC_X86_REG_RIP)!=END:
        raise RuntimeError("Original synthetic tail path did not complete")
    flags=uc.reg_read(UC_X86_REG_EFLAGS)
    expected=[
        uc.reg_read(UC_X86_REG_RAX),uc.reg_read(UC_X86_REG_RCX),
        uc.reg_read(UC_X86_REG_R9),uc.reg_read(UC_X86_REG_RSP),
        uc.reg_read(UC_X86_REG_RIP),
        int(bool(flags&64)),int(bool(flags&128)),int(bool(flags&1)),
    ]
    return expected,bytes(uc.mem_read(SP-64,128))

C=r"""
#include <stdint.h>
#include "mx_crt_cluster_guest.h"
#define SP UINT64_C(__SP__)
#define WIN UINT64_C(__WIN__)
#define END UINT64_C(__END__)
#define ENTRY UINT64_C(__ENTRY__)
#define TARGET UINT64_C(__TARGET__)
typedef struct {
  uint64_t input,expected[8];
  uint8_t stack[128];
} fixture;
static const fixture fixtures[]={__FIXTURES__};
static uint8_t guest_stack[128];
typedef struct {uint64_t input;unsigned calls,direct;} callback_ctx;
int native_entry(mx_crt_cluster_state*,mx_cfg_memory*,
                 mx_crt_cluster_import_fn,mx_crt_cluster_direct_fn,void*);
int native_target(mx_crt_cluster_state*,mx_cfg_memory*,
                  mx_crt_cluster_import_fn,void*);
static int importer(void*opaque,mx_crt_service_id id,
                    mx_crt_cluster_state*s,mx_cfg_memory*m,uint64_t rsp) {
 (void)m;
 callback_ctx*ctx=(callback_ctx*)opaque;
 if(!ctx||rsp!=SP-0x30U||s->rcx!=ctx->input)return 0;
 if(ctx->calls==0&&id==MX_CRT_SERVICE_DECODE_POINTER){
   s->rax=UINT64_C(0xdeadbeef);
 }else if(ctx->calls==1&&id==MX_CRT_SERVICE_ONEXIT){
   s->rax=UINT64_C(0x12345678);
 }else{return 0;}
 ctx->calls++;
 return 1;
}
static int native_direct(void*opaque,uint64_t destination,
                         mx_crt_cluster_state*s,mx_cfg_memory*m){
 callback_ctx *ctx=(callback_ctx*)opaque;
 if(!ctx||destination!=TARGET||s->rip!=TARGET||s->rsp!=SP||
    s->local_depth!=1U)return MX_CRT_CLUSTER_IMPORT_UNSUPPORTED;
 ctx->direct++;
 return native_target(s,m,importer,opaque);
}
int smoke(void){
 mx_cfg_region region={WIN,guest_stack,128};
 mx_cfg_memory mem={&region,1};
 for(unsigned k=0;k<sizeof(fixtures)/sizeof(fixtures[0]);k++){
   const fixture*f=&fixtures[k];
   for(unsigned i=0;i<128;i++)guest_stack[i]=0;
   uint64_t return_pc=END;
   if(!mx_cfg_transfer(&mem,SP,&return_pc,8,1))return 1;
   mx_crt_cluster_state state={0};
   state.rcx=f->input;state.rsp=SP;state.rip=ENTRY;
   callback_ctx ctx={f->input,0,0};
   if(native_entry(&state,&mem,importer,native_direct,&ctx)!=
       MX_CRT_CLUSTER_RETURNED ||
       state.local_calls!=1U||state.local_depth!=0U||
       state.imports!=2U||ctx.calls!=2U||ctx.direct!=1U)
       return 10+k;
   const uint64_t actual[]={
     state.rax,state.rcx,state.r9,state.rsp,state.rip,
     state.zf,state.sf,state.cf,
   };
   for(unsigned i=0;i<8;i++)
     if(actual[i]!=f->expected[i])return 50+k;
   for(unsigned i=0;i<128;i++)
     if(guest_stack[i]!=f->stack[i])return 100+k;
 }
 for(unsigned i=0;i<128;i++)guest_stack[i]=0;
 uint64_t return_pc=END;
 if(!mx_cfg_transfer(&mem,SP,&return_pc,8,1))return 180;
 mx_crt_cluster_state blocked={0};
 blocked.rcx=5U;blocked.rsp=SP;blocked.rip=ENTRY;
 callback_ctx blocked_context={5U,0U,0U};
 if(native_entry(&blocked,&mem,importer,0,&blocked_context)!=
    MX_CRT_CLUSTER_IMPORT_UNSUPPORTED ||
    blocked_context.direct!=0U)return 190;
 return 0;
}
#ifdef HOST
int main(void){return smoke();}
#endif
"""

def cfixtures(values):
    chunks=[]
    for value,(registers,stack) in values:
        exp=",".join("UINT64_C("+str(n)+")" for n in registers)
        raw=",".join(str(b) for b in stack)
        chunks.append("{UINT64_C("+str(value)+"),{"+exp+"},{"+raw+"}}")
    return ",\n".join(chunks)

class TailJumpDifferentialTests(unittest.TestCase):
    def test_authentic_synthetic_x64_tailcall_vs_native_aarch64(self):
        if any(shutil.which(x) is None for x in ("as","objcopy","nm","cc","clang")):
            self.skipTest("Assembler or compiler unavailable")
        with tempfile.TemporaryDirectory() as td:
            work=Path(td)
            blob,sym=assemble(work)
            target_rva=RVA+sym["target"]
            iat={
                RVA+sym["before_slot"]:("msvcr90.dll","_decode_pointer"),
                RVA+sym["after_slot"]:("msvcr90.dll","_onexit"),
            }
            entry_blob=blob[:sym["entry_end"]]
            target_blob=blob[sym["target"]:sym["target_end"]]
            with self.assertRaises(UnsupportedCluster):
                lift_crt_import_cluster(entry_blob,RVA,iat,{},BASE)
            compiled_entry,meta=lift_crt_import_cluster(
                entry_blob,RVA,iat,{},BASE,
                local_targets={target_rva},function_name="native_entry")
            compiled_target,other=lift_crt_import_cluster(
                target_blob,target_rva,iat,{},BASE,
                function_name="native_target")
            self.assertEqual(meta["verified_terminal_tail_jumps"],1)
            self.assertEqual(other["verified_terminal_tail_jumps"],0)
            cases=[(x,original(blob,sym,x)) for x in CASES]
            body=work/"native.c"
            body.write_text(compiled_entry+"\n"+compiled_target)
            test=work/"smoke.c"
            test.write_text(C.replace("__SP__",str(SP))
                .replace("__WIN__",str(SP-64))
                .replace("__END__",str(END))
                .replace("__ENTRY__",str(BASE+RVA))
                .replace("__TARGET__",str(BASE+target_rva))
                .replace("__FIXTURES__",cfixtures(cases)))
            options=["-std=c11","-O2","-Wall","-Wextra","-Werror",
                     "-I"+str(ROOT/"runtime")]
            host=work/"host"
            subprocess.run(["cc",*options,"-DHOST",str(body),str(test),
                            "-o",str(host)],check=True)
            subprocess.run([str(host)],check=True)
            elf=work/"arm64.elf"
            subprocess.run(["clang","--target=aarch64-unknown-linux-gnu",
                "-fuse-ld=lld","-nostdlib","-static","-ffreestanding",
                "-fno-builtin","-fno-stack-protector",
                *options,"-Wl,-e,smoke","-Wl,-z,max-page-size=4096",
                "-Wl,--build-id=none",str(body),str(test),"-o",str(elf)
            ],check=True)
            outcome=execute_arm64_elf(elf,instruction_budget=500000,
                                      timeout_us=7000000)
            self.assertEqual(outcome["arm64_smoke_exit"],0)

if __name__=="__main__":
    unittest.main()
