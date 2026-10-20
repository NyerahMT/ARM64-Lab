"""Independently authored nested x64 CALL cluster vs native host/AArch64.

Both parent and child x64 function bodies are synthetic, not extracted from
commercial software. The native parent dispatches to a separately compiled
native child, preserving guest stack, registers, and returned program counter.
"""
from pathlib import Path
import shutil
import struct
import subprocess
import tempfile
import unittest

from unicorn import Uc, UC_ARCH_X86, UC_MODE_64, UC_HOOK_CODE
from unicorn.x86_const import (
    UC_X86_REG_RAX, UC_X86_REG_R8, UC_X86_REG_R9, UC_X86_REG_RCX,
    UC_X86_REG_RSP, UC_X86_REG_RIP, UC_X86_REG_EFLAGS,
)
from tools.crt_import_cluster_lift import lift_crt_import_cluster,UnsupportedCluster
from tools.import_aot_smoke import execute_arm64_elf

ROOT=Path(__file__).resolve().parents[1]
BASE=0x140000000
RVA=0x1000
STACK=0x700000000
SP=STACK+0xfe08
WIN=SP-128
EXIT=0x500000100
STUB=0x600000000
INPUTS=((0x1234567890,0),
        (0x1234567891,1),
        (0x1234567892,0xffffffffffffffff),
        (0x1234567893,5),
        (0x1234567894,0x8000000000000000))
ASM=r"""
.intel_syntax noprefix
.section .text
.globl synthetic_parent
synthetic_parent:
  sub rsp,0x28
  mov r9,rcx
  call synthetic_child
  test eax,eax
  jns nonnegative
  mov r8d,9
  jmp after
nonnegative:
  mov r8d,7
after:
  mov rcx,r9
  call QWORD PTR [rip+decode_slot]
  add rsp,0x28
  ret
.globl synthetic_parent_end
synthetic_parent_end:
synthetic_child:
  sub rsp,0x28
  mov rcx,r9
  call QWORD PTR [rip+onexit_slot]
  add rsp,0x28
  ret
synthetic_child_end:
.org 0x200
decode_slot: .quad 0
onexit_slot: .quad 0
"""

def assembly(work):
    source=work/"nested.S"; obj=work/"nested.o"; raw=work/"nested.bin"
    source.write_text(ASM)
    subprocess.run(["as","--64",str(source),"-o",str(obj)],check=True)
    subprocess.run(["objcopy","-O","binary","-j",".text",
                    str(obj),str(raw)],check=True)
    output=subprocess.run(["nm","-a",str(obj)],capture_output=True,
                          text=True,check=True).stdout
    names={}
    for item in output.splitlines():
        parts=item.split()
        if len(parts)==3:
            try:names[parts[2]]=int(parts[0],16)
            except ValueError:pass
    assert names["synthetic_parent"]==0
    return raw.read_bytes(),names

def x64_reference(blob,names,rcx,child_response):
    uc=Uc(UC_ARCH_X86,UC_MODE_64)
    uc.mem_map(BASE,0x10000)
    uc.mem_map(STACK,0x10000)
    uc.mem_map(STUB,0x1000)
    uc.mem_write(BASE+RVA,blob)
    uc.mem_write(BASE+RVA+names["onexit_slot"],struct.pack("<Q",STUB))
    uc.mem_write(BASE+RVA+names["decode_slot"],struct.pack("<Q",STUB+16))
    uc.mem_write(STUB,b"\xc3")
    uc.mem_write(STUB+16,b"\xc3")
    uc.mem_write(SP,struct.pack("<Q",EXIT))
    uc.reg_write(UC_X86_REG_RCX,rcx)
    uc.reg_write(UC_X86_REG_RSP,SP)
    uc.reg_write(UC_X86_REG_RIP,BASE+RVA)
    calls=[]
    def hook(cpu,pc,size,arg):
        if pc not in (STUB,STUB+16):return
        rsp=cpu.reg_read(UC_X86_REG_RSP)
        if pc==STUB:
            if rsp!=SP-0x60 or cpu.reg_read(UC_X86_REG_RCX)!=rcx:
                raise RuntimeError("Synthetic nested Win64 import ABI changed")
            calls.append(1)
            cpu.reg_write(UC_X86_REG_RAX,child_response)
        else:
            if rsp!=SP-0x30 or cpu.reg_read(UC_X86_REG_RCX)!=rcx:
                raise RuntimeError("Synthetic parent Win64 import ABI changed")
            calls.append(2)
            cpu.reg_write(UC_X86_REG_RAX,0x222)
    uc.hook_add(UC_HOOK_CODE,hook)
    uc.emu_start(BASE+RVA,EXIT,timeout=2000000,count=120)
    if calls!=[1,2] or uc.reg_read(UC_X86_REG_RIP)!=EXIT:
        raise RuntimeError("Original synthetic nested execution did not return")
    regs=(UC_X86_REG_RAX,UC_X86_REG_RCX,UC_X86_REG_R8,
          UC_X86_REG_R9,UC_X86_REG_RSP,UC_X86_REG_RIP)
    flags=uc.reg_read(UC_X86_REG_EFLAGS)
    expected=tuple(uc.reg_read(x) for x in regs)+(
        int(bool(flags&64)),int(bool(flags&128)),int(bool(flags&1)),
    )
    stack=bytes(uc.mem_read(WIN,160))
    return expected,stack

NATIVE=r"""
#include <stdint.h>
#include "mx_crt_cluster_guest.h"
#define SP UINT64_C(__SP__)
#define WIN UINT64_C(__WIN__)
#define EXIT UINT64_C(__EXIT__)
#define PARENT UINT64_C(__PARENT__)
#define CHILD UINT64_C(__CHILD__)
typedef struct {
 uint64_t rcx, onexit_result, expected[9];
 uint8_t stack[160];
} sample;
static const sample cases[]={__CASES__};
static uint8_t guest_stack[160];
typedef struct {
 uint64_t rcx,result;
 uint32_t import_calls,direct_calls;
} state_context;
int lifted_nested_child(mx_crt_cluster_state*s,mx_cfg_memory*m,
                       mx_crt_cluster_import_fn callback,void*context);
int lifted_nested_parent(mx_crt_cluster_state*s,mx_cfg_memory*m,
                       mx_crt_cluster_import_fn callback,
                       mx_crt_cluster_direct_fn direct,void*context);
static int call_import(void*context,mx_crt_service_id id,
                       mx_crt_cluster_state*s,mx_cfg_memory*m,
                       uint64_t callee_rsp){
 (void)m;
 state_context*ctx=(state_context*)context;
 if(!ctx||s->rcx!=ctx->rcx)return 0;
 if(id==MX_CRT_SERVICE_ONEXIT && callee_rsp==SP-0x60U &&
    ctx->import_calls==0U){
    ctx->import_calls++;s->rax=ctx->result;return 1;
 }
 if(id==MX_CRT_SERVICE_DECODE_POINTER && callee_rsp==SP-0x30U &&
    ctx->import_calls==1U){
    ctx->import_calls++;s->rax=UINT64_C(0x222);return 1;
 }
 return 0;
}
static int call_nested(void*context,uint64_t target,
                       mx_crt_cluster_state*s,mx_cfg_memory*m){
 state_context*ctx=(state_context*)context;
 if(!ctx||target!=CHILD||s->rip!=CHILD||s->rsp!=SP-0x30U||
    s->local_depth!=1U)return MX_CRT_CLUSTER_IMPORT_UNSUPPORTED;
 ctx->direct_calls++;
 return lifted_nested_child(s,m,call_import,context);
}
int smoke(void){
 mx_cfg_region stack={WIN,guest_stack,160};
 mx_cfg_memory memory={&stack,1};
 for(unsigned k=0;k<sizeof(cases)/sizeof(cases[0]);k++){
    const sample*f=&cases[k];
    for(unsigned j=0;j<160;j++)guest_stack[j]=0;
    uint64_t ret=EXIT;
    if(!mx_cfg_transfer(&memory,SP,&ret,8,1))return 1;
    mx_crt_cluster_state s={0};
    s.rip=PARENT;s.rsp=SP;s.rcx=f->rcx;
    state_context context={f->rcx,f->onexit_result,0U,0U};
    int outcome=lifted_nested_parent(&s,&memory,call_import,
                                     call_nested,&context);
    if(outcome!=MX_CRT_CLUSTER_RETURNED||
       context.import_calls!=2U||context.direct_calls!=1U||
       s.local_calls!=1U||s.imports!=2U||s.local_depth!=0U)
       return 10+k;
    const uint64_t actual[]={
       s.rax,s.rcx,s.r8,s.r9,s.rsp,s.rip,s.zf,s.sf,s.cf
    };
    for(unsigned n=0;n<9;n++){
      if(actual[n]!=f->expected[n])return 50+k;
    }
    for(unsigned n=0;n<160;n++){
      if(guest_stack[n]!=f->stack[n])return 100+k;
    }
 }
 /* An unresolved direct call cannot be silently treated as successful. */
 for(unsigned j=0;j<160;j++)guest_stack[j]=0;
 uint64_t ret=EXIT;
 if(!mx_cfg_transfer(&memory,SP,&ret,8,1))return 200;
 mx_crt_cluster_state blocked={0};
 blocked.rip=PARENT;blocked.rsp=SP;blocked.rcx=UINT64_C(0x123);
 state_context context={UINT64_C(0x123),0,0,0};
 if(lifted_nested_parent(&blocked,&memory,call_import,0,&context)!=
    MX_CRT_CLUSTER_IMPORT_UNSUPPORTED || context.direct_calls!=0U)
    return 201;
 return 0;
}
#ifdef HOST
int main(void){return smoke();}
#endif
"""

def fixture_array(data):
    rows=[]
    for (rcx,return_value),(exp,stack) in data:
        before="UINT64_C("+str(rcx)+"),UINT64_C("+str(return_value)+")"
        expected=",".join("UINT64_C("+str(n)+")" for n in exp)
        raw=",".join(str(b) for b in stack)
        rows.append("{"+before+",{"+expected+"},{"+raw+"}}")
    return ",\n".join(rows)

class NestedX64CallsTests(unittest.TestCase):
    def test_fail_closed_and_native_nested_function_parity(self):
        if any(not shutil.which(x) for x in ("as","objcopy","nm","cc","clang")):
            self.skipTest("Compiler/assembler unavailable")
        with tempfile.TemporaryDirectory() as td:
            work=Path(td)
            blob,names=assembly(work)
            child_target=RVA+names["synthetic_child"]
            imports={
                RVA+names["onexit_slot"]:("msvcr90.dll","_onexit"),
                RVA+names["decode_slot"]:("msvcr90.dll","_decode_pointer"),
            }
            parent_blob=blob[:names["synthetic_parent_end"]]
            child_blob=blob[names["synthetic_child"]:names["synthetic_child_end"]]
            with self.assertRaises(UnsupportedCluster):
                lift_crt_import_cluster(parent_blob,RVA,imports,{},BASE)
            child,child_meta=lift_crt_import_cluster(
                child_blob,child_target,imports,{},BASE,
                function_name="lifted_nested_child"
            )
            parent,parent_meta=lift_crt_import_cluster(
                parent_blob,RVA,imports,{},BASE,
                local_targets={child_target},
                function_name="lifted_nested_parent"
            )
            self.assertEqual(parent_meta["local_call_sites"],1)
            self.assertEqual(parent_meta["import_calls"],1)
            self.assertEqual(child_meta["import_calls"],1)
            self.assertEqual(child_meta["local_call_sites"],0)
            fixtures=[(x,x64_reference(blob,names,*x)) for x in INPUTS]
            source=work/"generated.c";source.write_text(parent+"\n"+child)
            smoke=work/"smoke.c"
            smoke.write_text(
                NATIVE.replace("__SP__",str(SP))
                .replace("__WIN__",str(WIN))
                .replace("__EXIT__",str(EXIT))
                .replace("__PARENT__",str(BASE+RVA))
                .replace("__CHILD__",str(BASE+child_target))
                .replace("__CASES__",fixture_array(fixtures))
            )
            flags=["-O2","-std=c11","-Wall","-Wextra","-Werror",
                   "-I"+str(ROOT/"runtime")]
            host=work/"host"
            subprocess.run(["cc",*flags,"-DHOST",str(source),str(smoke),
                            "-o",str(host)],check=True)
            subprocess.run([str(host)],check=True)
            arm=work/"arm64.elf"
            subprocess.run(["clang","--target=aarch64-unknown-linux-gnu",
                "-fuse-ld=lld","-nostdlib","-static","-ffreestanding",
                "-fno-stack-protector","-fno-builtin",*flags,
                "-Wl,-e,smoke","-Wl,-z,max-page-size=4096",
                "-Wl,--build-id=none",str(source),str(smoke),"-o",str(arm)],
                check=True)
            report=execute_arm64_elf(arm,instruction_budget=650000,
                                     timeout_us=8000000)
            self.assertEqual(report["arm64_smoke_exit"],0)

if __name__=="__main__":
    unittest.main()
