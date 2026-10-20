"""Fully synthetic x64 CRT cluster => generated C / executed ARM64 differential.

Purpose-written x86-64 assembly models early and registration paths; it is
NOT from the original MX Bikes executable. The original-game private CI must
independently validate the same translator on authentic original bytes.
"""
from pathlib import Path
from collections import Counter
import shutil
import struct
import subprocess
import tempfile
import unittest

from capstone import Cs, CS_ARCH_X86, CS_MODE_64
from unicorn import Uc, UC_ARCH_X86, UC_MODE_64, UC_HOOK_CODE
from unicorn.x86_const import (
    UC_X86_REG_RAX, UC_X86_REG_RBX, UC_X86_REG_RCX,
    UC_X86_REG_RDX, UC_X86_REG_R8, UC_X86_REG_RDI,
    UC_X86_REG_RSI, UC_X86_REG_R11,
    UC_X86_REG_RSP, UC_X86_REG_RIP, UC_X86_REG_EFLAGS,
)

from tools.crt_import_cluster_lift import lift_crt_import_cluster, UnsupportedCluster
from tools.import_aot_smoke import execute_arm64_elf

ROOT=Path(__file__).resolve().parents[1]
BASE=0x140000000
START=0x1000
STACK=0x700000000
SP=STACK+0xfe08
WIN=SP-128
STOP=0x500000100
STUB=0x600000000
REGS={
    "rax":UC_X86_REG_RAX, "rbx":UC_X86_REG_RBX,
    "rcx":UC_X86_REG_RCX, "rdx":UC_X86_REG_RDX,
    "r8":UC_X86_REG_R8, "rdi":UC_X86_REG_RDI,
    "rsi":UC_X86_REG_RSI, "r11":UC_X86_REG_R11,
}
SYMBOLS={
    "decode_slot":"_decode_pointer","onexit_slot":"_onexit",
    "encode_slot":"_encode_pointer","lock_slot":"_lock",
    "dll_slot":"__dllonexit","unlock_slot":"_unlock"
}
ASM=r"""
.intel_syntax noprefix
.section .text
.globl synthetic_crt_entry
synthetic_crt_entry:
  push rbx
  sub rsp,0x20
  mov rbx,rcx
  mov rcx,QWORD PTR [rip+g0]
  call QWORD PTR [rip+decode_slot]
  cmp rax,-1
  jne registration_path
  mov rcx,rbx
  call QWORD PTR [rip+onexit_slot]
  jmp done
registration_path:
  mov ecx,8
  call lock_thunk
  nop
  mov rcx,QWORD PTR [rip+g0]
  call QWORD PTR [rip+decode_slot]
  mov QWORD PTR [rsp+0x38],rax
  mov rcx,QWORD PTR [rip+g1]
  call QWORD PTR [rip+decode_slot]
  mov QWORD PTR [rsp+0x40],rax
  mov rcx,rbx
  call QWORD PTR [rip+encode_slot]
  mov rcx,rax
  lea r8,QWORD PTR [rsp+0x40]
  lea rdx,QWORD PTR [rsp+0x38]
  call dll_thunk
  mov rbx,rax
  mov rcx,QWORD PTR [rsp+0x38]
  call QWORD PTR [rip+encode_slot]
  mov QWORD PTR [rip+g0],rax
  mov rcx,QWORD PTR [rsp+0x40]
  call QWORD PTR [rip+encode_slot]
  mov QWORD PTR [rip+g1],rax
  mov ecx,8
  call unlock_thunk
  mov rax,rbx
done:
  add rsp,0x20
  pop rbx
  ret
.globl synthetic_crt_end
synthetic_crt_end:
.org 0x300
lock_thunk:
  jmp QWORD PTR [rip+lock_slot]
dll_thunk:
  jmp QWORD PTR [rip+dll_slot]
unlock_thunk:
  jmp QWORD PTR [rip+unlock_slot]
.org 0x400
decode_slot: .quad 0
onexit_slot: .quad 0
encode_slot: .quad 0
lock_slot: .quad 0
dll_slot: .quad 0
unlock_slot: .quad 0
.org 0x500
g0: .quad 0
g1: .quad 0
"""

def assemble(temp):
    source=temp/"fixture.S"
    obj=temp/"fixture.o"
    binary=temp/"fixture.bin"
    source.write_text(ASM)
    subprocess.run(["as","--64",str(source),"-o",str(obj)],check=True)
    subprocess.run(["objcopy","-O","binary","-j",".text",str(obj),str(binary)],
                   check=True)
    symbol_output=subprocess.run(["nm","-a",str(obj)],capture_output=True,
                                 text=True,check=True).stdout
    symbols={}
    for line in symbol_output.splitlines():
        cells=line.split()
        if len(cells)==3:
            try:
                symbols[cells[2]]=int(cells[0],16)
            except ValueError:
                pass
    assert symbols["synthetic_crt_entry"]==0
    blob=binary.read_bytes()
    end=symbols["synthetic_crt_end"]
    iat={START+symbols[k]:("msvcr90.dll",v) for k,v in SYMBOLS.items()}
    thunks={START+symbols[k]:blob[symbols[k]:symbols[k]+6]
            for k in ("lock_thunk","dll_thunk","unlock_thunk")}
    return blob,blob[:end],iat,thunks,{k:BASE+START+v for k,v in symbols.items()}

def fixtures():
    for i in range(8):
        short=i<4
        yield {
            "short":short, "rax":0xaabbcc00+i*17,
            "rbx":0xff000000+i*19,"rcx":0x140008000+i*16,
            "rdx":0x22440000+i*23,"r8":0x33550000+i*29,
            "rdi":0x44660000+i*31,"rsi":0x55770000+i*37,
            "r11":0x66880000+i*41,"zf":i%2,
            "g0":0x77aa00+i*3,"g1":0x88bb00+i*7,
            "decode":[0xffffffffffffffff if short else 0x70001000+i*16,
                      0x70002000+i*16,0x70003000+i*16],
            "encode":[0x140009000+i,0x14000a000+i,0x14000b000+i],
            "onexit":0 if i%2 else 0x14000c000+i,
            "dll":0 if i%3==1 else 0x14000d000+i,
            "update":i%2==0,
            "updated0":0x70004000+i*16,
            "updated1":0x70005000+i*16,
        }

def reference_original(blob,symbols,case):
    cpu=Uc(UC_ARCH_X86,UC_MODE_64)
    cpu.mem_map(BASE,0x10000)
    cpu.mem_map(STUB,4096)
    cpu.mem_map(STACK,0x10000)
    cpu.mem_write(BASE+START,blob)
    for index,(slot,name) in enumerate(SYMBOLS.items()):
        stub=STUB+index*16
        cpu.mem_write(symbols[slot],struct.pack("<Q",stub))
        cpu.mem_write(stub,b"\xc3")
    cpu.mem_write(symbols["g0"],struct.pack("<Q",case["g0"]))
    cpu.mem_write(symbols["g1"],struct.pack("<Q",case["g1"]))
    cpu.mem_write(SP,struct.pack("<Q",STOP))
    for name,reg in REGS.items():cpu.reg_write(reg,case[name])
    cpu.reg_write(UC_X86_REG_RSP,SP)
    cpu.reg_write(UC_X86_REG_RIP,BASE+START)
    cpu.reg_write(UC_X86_REG_EFLAGS,0x202|(case["zf"]<<6))
    stub_names={STUB+index*16:name
                for index,name in enumerate(SYMBOLS.values())}
    numbers=Counter()
    trace=[]
    def hook(emu,pc,size,ctx):
        if pc not in stub_names:
            return
        name=stub_names[pc]
        n=numbers[name]
        numbers[name]+=1
        if emu.reg_read(UC_X86_REG_RSP)!=SP-0x30:
            raise RuntimeError("Win64 x64 synthetic import ABI mismatch")
        trace.append(name)
        if name=="_decode_pointer":
            value=case["decode"][n]
        elif name=="_encode_pointer":
            value=case["encode"][n]
        elif name=="_onexit":
            value=case["onexit"]
        elif name=="__dllonexit":
            value=case["dll"]
            if case["update"]:
                emu.mem_write(emu.reg_read(UC_X86_REG_RDX),
                              struct.pack("<Q",case["updated0"]))
                emu.mem_write(emu.reg_read(UC_X86_REG_R8),
                              struct.pack("<Q",case["updated1"]))
        elif name in ("_lock","_unlock"):
            if emu.reg_read(UC_X86_REG_RCX)!=8:
                raise RuntimeError("Synthetic CRT lock selector invalid")
            return
        else:raise RuntimeError("Unknown test callback")
        emu.reg_write(UC_X86_REG_RAX,value)
    cpu.hook_add(UC_HOOK_CODE,hook)
    cpu.emu_start(BASE+START,STOP,timeout=2_000_000,count=150)
    if cpu.reg_read(UC_X86_REG_RIP)!=STOP or cpu.reg_read(UC_X86_REG_RSP)!=SP+8:
        raise RuntimeError("Synthetic original x64 did not return")
    expected=(["_decode_pointer","_onexit"] if case["short"] else
              ["_decode_pointer","_lock","_decode_pointer","_decode_pointer",
               "_encode_pointer","__dllonexit","_encode_pointer",
               "_encode_pointer","_unlock"])
    if trace!=expected:
        raise RuntimeError("Synthetic original path changed")
    out={name:cpu.reg_read(reg) for name,reg in REGS.items()}
    out.update({
        "rsp":cpu.reg_read(UC_X86_REG_RSP),
        "rip":cpu.reg_read(UC_X86_REG_RIP),
        "zf":int(bool(cpu.reg_read(UC_X86_REG_EFLAGS)&64)),
        "g0":struct.unpack("<Q",bytes(cpu.mem_read(symbols["g0"],8)))[0],
        "g1":struct.unpack("<Q",bytes(cpu.mem_read(symbols["g1"],8)))[0],
        "stack":bytes(cpu.mem_read(WIN,256)),
        "trace":trace,
    })
    return out

HARNESS=r"""
#include <stdint.h>
#include "mx_crt_cluster_guest.h"
#define SP UINT64_C(REPLACE_SP)
#define WIN UINT64_C(REPLACE_WIN)
#define BASE_G UINT64_C(REPLACE_G0)
#define ENTRY UINT64_C(REPLACE_ENTRY)
#define STOP UINT64_C(REPLACE_STOP)
typedef struct {
 uint64_t in[11], out[13], decoder[3], encoder[3], onexit, dll;
 uint64_t update,updated0,updated1,trace_len;
 uint64_t trace[10];
 uint8_t stack[256];
} fixture;
static const fixture fixtures[]={REPLACE_CASES};
static uint8_t stack_bytes[256],global_bytes[16];
typedef struct {
 const fixture*f; unsigned decoder_n,encoder_n,trace_len;
 uint64_t trace[10];
} context;
static int hook(void *p,mx_crt_service_id id,
                mx_crt_cluster_state *s,mx_cfg_memory*m,uint64_t callee_rsp) {
 context*c=(context*)p;
 if(callee_rsp!=s->rsp-8U||callee_rsp!=SP-0x30U||
    c->trace_len>=10U)return 0;
 c->trace[c->trace_len++]=(uint64_t)id;
 switch(id){
 case MX_CRT_SERVICE_DECODE_POINTER:
    if(c->decoder_n>=3U)return 0;
    s->rax=c->f->decoder[c->decoder_n++];return 1;
 case MX_CRT_SERVICE_ENCODE_POINTER:
    if(c->encoder_n>=3U)return 0;
    s->rax=c->f->encoder[c->encoder_n++];return 1;
 case MX_CRT_SERVICE_ONEXIT: s->rax=c->f->onexit;return 1;
 case MX_CRT_SERVICE_DLLONEXIT:
    if(c->f->update) {
       uint64_t a=c->f->updated0,b=c->f->updated1;
       if(!mx_cfg_transfer(m,s->rdx,&a,8,1)||
          !mx_cfg_transfer(m,s->r8,&b,8,1))return 0;
    }
    s->rax=c->f->dll;return 1;
 case MX_CRT_SERVICE_LOCK:
 case MX_CRT_SERVICE_UNLOCK: return s->rcx==8U;
 default:return 0;
 }
}
static int copy64(mx_cfg_memory*m,uint64_t a,uint64_t v){
 return mx_cfg_transfer(m,a,&v,8,1);
}
int smoke(void) {
 mx_cfg_region ranges[2]={{WIN,stack_bytes,256},{BASE_G,global_bytes,16}};
 mx_cfg_memory mem={ranges,2};
 for(unsigned k=0;k<sizeof(fixtures)/sizeof(fixtures[0]);k++){
    const fixture*f=&fixtures[k];
    for(unsigned j=0;j<256;j++)stack_bytes[j]=0;
    for(unsigned j=0;j<16;j++)global_bytes[j]=0;
    if(!copy64(&mem,SP,STOP)||!copy64(&mem,BASE_G,f->in[9])||
       !copy64(&mem,BASE_G+8U,f->in[10]))return 10+k;
    mx_crt_cluster_state s={0};
    s.rax=f->in[0];s.rbx=f->in[1];s.rcx=f->in[2];
    s.rdx=f->in[3];s.r8=f->in[4];s.rdi=f->in[5];
    s.rsi=f->in[6];s.r11=f->in[7];s.zf=(uint8_t)f->in[8];
    s.rsp=SP;s.rip=ENTRY;
    context ctx={0};ctx.f=f;
    if(lifted_crt_import_cluster(&s,&mem,hook,&ctx)!=
       MX_CRT_CLUSTER_RETURNED)return 40+k;
    const uint64_t actual[]={
       s.rax,s.rbx,s.rcx,s.rdx,s.r8,s.rdi,s.rsi,s.r11,
       s.rsp,s.rip,s.zf,
    };
    for(unsigned j=0;j<11;j++)
       if(actual[j]!=f->out[j])return 80+k;
    uint64_t g0=0,g1=0;
    if(!mx_cfg_transfer(&mem,BASE_G,&g0,8,0)||
       !mx_cfg_transfer(&mem,BASE_G+8U,&g1,8,0)||
       g0!=f->out[11]||g1!=f->out[12])return 120+k;
    if(ctx.trace_len!=f->trace_len||s.imports!=f->trace_len)
       return 160+k;
    for(unsigned j=0;j<ctx.trace_len;j++)
       if(ctx.trace[j]!=f->trace[j])return 200+k;
    for(unsigned j=0;j<256;j++)
       if(stack_bytes[j]!=f->stack[j])return 240+k;
 }
 return 0;
}
#ifdef HOST
int main(void){return smoke();}
#endif
"""

SERVICE_ID={
    "_encode_pointer":1,"_decode_pointer":2,"_onexit":3,
    "__dllonexit":4,"_lock":5,"_unlock":6
}
INPUT=("rax","rbx","rcx","rdx","r8","rdi","rsi","r11","zf","g0","g1")
OUTPUT=("rax","rbx","rcx","rdx","r8","rdi","rsi","r11",
        "rsp","rip","zf","g0","g1")

def carray(values):
    return "{"+",".join(f"UINT64_C({x})" for x in values)+"}"

def encode(rows):
    result=[]
    for case,ref in rows:
        trace=[SERVICE_ID[s] for s in ref["trace"]]
        trace.extend([0]*(10-len(trace)))
        parts=[
            carray([case[x] for x in INPUT]),
            carray([ref[x] for x in OUTPUT]),
            carray(case["decode"]),carray(case["encode"]),
            "UINT64_C("+str(case["onexit"])+")",
            "UINT64_C("+str(case["dll"])+")",
            "UINT64_C("+str(int(case["update"]))+")",
            "UINT64_C("+str(case["updated0"])+")",
            "UINT64_C("+str(case["updated1"])+")",
            "UINT64_C("+str(len(ref["trace"]))+")",
            carray(trace),
            "{"+",".join(str(x) for x in ref["stack"])+"}",
        ]
        result.append("{"+",".join(parts)+"}")
    return ",\n".join(result)

class CRTClusterLiftTests(unittest.TestCase):
    def test_synthetic_full_branch_cluster_x64_host_arm64(self):
        required=("as","objcopy","nm","cc","clang")
        if any(shutil.which(x) is None for x in required):
            self.skipTest("Required assembler/host and ARM64 compiler missing")
        with tempfile.TemporaryDirectory() as td:
            work=Path(td)
            blob,code,iat,thunks,symbols=assemble(work)
            generated,meta=lift_crt_import_cluster(code,START,iat,thunks,BASE)
            self.assertGreaterEqual(meta["decoded_instructions"],25)
            self.assertEqual(meta["import_calls"],10)
            self.assertEqual(len(meta["unique_import_services"]),6)
            rows=[(case,reference_original(blob,symbols,case))
                  for case in fixtures()]
            source=work/"generated.c"
            source.write_text(generated)
            program=HARNESS
            for marker,value in (
                ("REPLACE_SP",SP),("REPLACE_WIN",WIN),
                ("REPLACE_G0",symbols["g0"]),
                ("REPLACE_ENTRY",BASE+START),
                ("REPLACE_STOP",STOP),
            ):
                program=program.replace(marker,str(value))
            program=program.replace("REPLACE_CASES",encode(rows))
            smoke=work/"smoke.c"
            smoke.write_text(program)
            flags=["-std=c11","-O2","-Wall","-Wextra","-Werror",
                   "-I"+str(ROOT/"runtime")]
            host=work/"host"
            subprocess.run(["cc",*flags,"-DHOST",str(source),str(smoke),
                            "-o",str(host)],check=True)
            subprocess.run([str(host)],check=True)
            elf=work/"arm64.elf"
            subprocess.run([
                "clang","--target=aarch64-unknown-linux-gnu",
                "-fuse-ld=lld","-nostdlib","-static","-ffreestanding",
                "-fno-stack-protector","-fno-builtin",*flags,
                "-Wl,-e,smoke","-Wl,-z,max-page-size=4096",
                "-Wl,--build-id=none",str(source),str(smoke),"-o",str(elf)
            ],check=True)
            out=execute_arm64_elf(elf,instruction_budget=550000,
                                   timeout_us=7000000)
            self.assertEqual(out["arm64_smoke_exit"],0)

    def test_reject_unknown_import_and_bad_thunks(self):
        with tempfile.TemporaryDirectory() as td:
            blob,code,iat,thunks,symbols=assemble(Path(td))
            bad=dict(iat)
            bad[next(iter(bad))]=("steam_api64.dll","SteamAPI_Init")
            with self.assertRaises(UnsupportedCluster):
                lift_crt_import_cluster(code,START,bad,thunks,BASE)
            with self.assertRaises(UnsupportedCluster):
                lift_crt_import_cluster(code,START,iat,{},BASE)
            tampered=dict(thunks)
            target=next(iter(tampered))
            tampered[target]=b"\x90"*6
            with self.assertRaises(UnsupportedCluster):
                lift_crt_import_cluster(code,START,iat,tampered,BASE)
            with self.assertRaises(UnsupportedCluster):
                lift_crt_import_cluster(code+b"\x90",START,iat,thunks,BASE)

if __name__=="__main__":
    unittest.main()
