#!/usr/bin/env python3
"""Private full-CRT CFG translation differential against original x64.

The pinned user-owned PE and generated commercial-code translation remain
ephemeral in a private GitHub Actions runner. Publish summary metadata only.
"""
from pathlib import Path
import hashlib
import json
import struct
import subprocess
import sys
import tempfile

from capstone import Cs,CS_ARCH_X86,CS_MODE_64
from unicorn import Uc,UC_ARCH_X86,UC_MODE_64,UC_HOOK_CODE,UC_HOOK_MEM_WRITE
from unicorn.x86_const import (
    UC_X86_REG_RAX,UC_X86_REG_RBX,UC_X86_REG_RCX,UC_X86_REG_RDI,
    UC_X86_REG_R11,UC_X86_REG_RSP,UC_X86_REG_RIP,UC_X86_REG_EFLAGS
)

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/"arm64-lab"))
from tools.pe_probe import PE
from tools.crt_cfg_lift import translate_crt_cfg
from tools.import_aot_smoke import execute_arm64_elf
from mxbikes_first_callee_emu import import_slots

SHA="4ae7de3854b4d0a18271679fb57a1f2fdf0b21804417b85dd82055078ea123b6"
BASE=0x140000000
ENTRY=0x2ab954
SIZE=179
COOKIE=0x3928a0
STACK=0x700000000
RSP0=STACK+0xff08
STUB_BASE=0x600000000
SENTINEL=0x12345678
API_NAMES=("GetSystemTimeAsFileTime","GetCurrentThreadId",
           "GetCurrentProcessId","GetTickCount","QueryPerformanceCounter")
SEEDS=[0,1,0x100000000,0x1111111111111111,0xabcdef98765432,
       0xffffffff00000000,0x2b992ddfa231,0x2b992ddfa232,
       0x2b992ddfa232,0x8000000000000001]
MASK=(1<<64)-1

def fixtures():
    for k,seed in enumerate(SEEDS):
        yield {
            "cookie":seed,"rbx":(0x123456789abcdef0+k*0x8123)&MASK,
            "rdi":(0xcafebabe12340000+k*0x1a11)&MASK,
            "mono_ns":2000000000000+k*419871200,
            "real_ns":1700000000000000000+k*790000000,
            "pid":0x1234+k,"tid":0x5678+k,
        }

def x64_reference(pe, instructions, iat, fixture, call_order):
    size=max(rva+max(vsize,rawsize) for _,vsize,rva,rawsize,_,_ in pe.sections)
    if size>128*1024*1024:raise RuntimeError("Oversized PE mapping")
    u=Uc(UC_ARCH_X86,UC_MODE_64)
    u.mem_map(BASE,(size+4095)&~4095)
    for _name,vsize,rva,rawsize,rawptr,flags in pe.sections:
        if rawsize:u.mem_write(BASE+rva,pe.b[rawptr:rawptr+rawsize])
    u.mem_map(STACK,0x10000)
    u.mem_map(STUB_BASE,0x1000)
    slots={(dll.lower(),name):rva for rva,(dll,name) in iat.items()}
    stubs={}
    for idx,name in enumerate(call_order):
        slot=slots[("kernel32.dll",name)]
        stub=STUB_BASE+0x20*idx
        u.mem_write(BASE+slot,struct.pack("<Q",stub))
        u.mem_write(stub,b"\xc3")
        stubs[stub]=(idx+1,name)
    u.mem_write(BASE+COOKIE,struct.pack("<Q",fixture["cookie"]))
    u.mem_write(BASE+COOKIE+8,struct.pack("<Q",0))
    u.mem_write(RSP0,struct.pack("<Q",SENTINEL))
    u.reg_write(UC_X86_REG_RIP,BASE+ENTRY)
    u.reg_write(UC_X86_REG_RSP,RSP0)
    for reg,key in ((UC_X86_REG_RBX,"rbx"),(UC_X86_REG_RDI,"rdi")):
        u.reg_write(reg,fixture[key])
    for reg in (UC_X86_REG_RAX,UC_X86_REG_RCX,UC_X86_REG_R11):
        u.reg_write(reg,0)
    address_map={BASE+i.address:n for n,i in enumerate(instructions)}
    seen={"visited":0,"count":0,"calls":0,"trace":0,"writes":0}
    def on_code(emu,pc,width,userdata):
        if pc in stubs:
            index,name=stubs[pc]
            if emu.reg_read(UC_X86_REG_RSP)%16 !=8:
                raise RuntimeError("Win64 imported callee stack alignment mismatch")
            seen["calls"]+=1
            seen["trace"]=seen["trace"]*8+index
            if name=="GetSystemTimeAsFileTime":
                ptr=emu.reg_read(UC_X86_REG_RCX)
                val=116444736000000000+fixture["real_ns"]//100
                emu.mem_write(ptr,struct.pack("<Q",val))
            elif name=="QueryPerformanceCounter":
                ptr=emu.reg_read(UC_X86_REG_RCX)
                emu.mem_write(ptr,struct.pack("<Q",fixture["mono_ns"]))
                emu.reg_write(UC_X86_REG_RAX,1)
            elif name=="GetTickCount":
                emu.reg_write(UC_X86_REG_RAX,(fixture["mono_ns"]//1000000)&0xffffffff)
            elif name=="GetCurrentProcessId":
                emu.reg_write(UC_X86_REG_RAX,fixture["pid"])
            elif name=="GetCurrentThreadId":
                emu.reg_write(UC_X86_REG_RAX,fixture["tid"])
            return
        index=address_map.get(pc)
        if index is None:raise RuntimeError("Original x64 escaped first callee")
        seen["visited"] |= 1 << index
        seen["count"]+=1
    def on_write(emu,access,addr,width,value,userdata):
        seen["writes"]+=1
    u.hook_add(UC_HOOK_CODE,on_code)
    u.hook_add(UC_HOOK_MEM_WRITE,on_write)
    u.emu_start(BASE+ENTRY,SENTINEL,timeout=2_000_000,count=128)
    if u.reg_read(UC_X86_REG_RIP)!=SENTINEL:
        raise RuntimeError("Original initializer did not return")
    outcome={key:seen[key] for key in seen}
    for name,reg in (("rax",UC_X86_REG_RAX),("rbx",UC_X86_REG_RBX),
                     ("rcx",UC_X86_REG_RCX),("rdi",UC_X86_REG_RDI),
                     ("r11",UC_X86_REG_R11),("rsp",UC_X86_REG_RSP),
                     ("rip",UC_X86_REG_RIP)):
        outcome[name]=u.reg_read(reg)
    outcome["zf"]=1 if u.reg_read(UC_X86_REG_EFLAGS)&64 else 0
    outcome["cookie_final"]=struct.unpack("<Q",u.mem_read(BASE+COOKIE,8))[0]
    outcome["complement_final"]=struct.unpack("<Q",u.mem_read(BASE+COOKIE+8,8))[0]
    outcome["stack_window"]=bytes(u.mem_read(RSP0-64,128))
    if outcome["rsp"]!=RSP0+8 or outcome["rbx"]!=fixture["rbx"] or outcome["rdi"]!=fixture["rdi"]:
        raise RuntimeError("Original x64 stack or callee-saved register violation")
    return outcome

def _emit_cases(items):
    rows=[]
    for f,ref in items:
        source=[f[k] for k in ("cookie","rbx","rdi","mono_ns","real_ns","pid","tid")]
        expected=[ref[k] for k in ("rax","rbx","rcx","rdi","r11","rsp",
                                  "rip","visited","trace","count","calls",
                                  "zf","cookie_final","complement_final")]
        allnumbers=[f"UINT64_C({v})" for v in source+expected]
        stack="{"+",".join(str(x) for x in ref["stack_window"])+"}"
        rows.append(" {"+",".join(allnumbers)+","+stack+"},")
    return "\n".join(rows)

C_HARNESS=r"""
#include <stdint.h>
#include "mx_crt_vm.h"

#define STACK_BASE UINT64_C(STACK_REGION_BASE)
#define IMAGE_COOKIE UINT64_C(COOKIE_VA)
#define ENTRY_ADDR UINT64_C(ENTRY_VA)
#define INITIAL_SP UINT64_C(INIT_SP)
#define SENTINEL UINT64_C(RETURN_PC)
typedef struct {
    uint64_t cookie,rbx,rdi,mono,real,pid,tid;
    uint64_t e_rax,e_rbx,e_rcx,e_rdi,e_r11,e_rsp,e_rip;
    uint64_t e_visited,e_trace,e_count,e_calls,e_zf,e_cookie,e_complement;
    uint8_t e_stack[128];
} fixture;
static const fixture cases[]={
__CASES__
};
static uint8_t stack_bytes[128];
static uint8_t cookie_bytes[16];
typedef struct {
    mx_cfg_memory *memory;
    uint64_t mono,real;
    uint32_t pid,tid;
} host;
static uint64_t mono_cb(void *p){return ((host*)p)->mono;}
static uint64_t real_cb(void *p){return ((host*)p)->real;}
static uint32_t pid_cb(void *p){return ((host*)p)->pid;}
static uint32_t tid_cb(void *p){return ((host*)p)->tid;}
static int write_cb(void *p,uint64_t addr,const uint8_t *bytes,uint32_t size){
    host *h=(host*)p;
    if(!bytes||size!=8)return 0;
    return mx_cfg_transfer(h->memory,addr,(void*)bytes,size,1);
}
static int write64(mx_cfg_memory *m,uint64_t a,uint64_t value){
    return mx_cfg_transfer(m,a,&value,8,1);
}
static int read64(mx_cfg_memory *m,uint64_t a,uint64_t *value){
    return mx_cfg_transfer(m,a,value,8,0);
}
int lifted_crt_run(mx_crt_state *,mx_cfg_memory *);
int lifted_crt_resume_import(mx_crt_state *,const mx_import_runtime *);

int smoke(void){
    mx_cfg_region regions[2]={
        {STACK_BASE,stack_bytes,sizeof(stack_bytes)},
        {IMAGE_COOKIE,cookie_bytes,sizeof(cookie_bytes)}
    };
    mx_cfg_memory mem={regions,2};
    for(unsigned i=0;i<sizeof(cases)/sizeof(cases[0]);i++){
        const fixture *f=&cases[i];
        volatile uint8_t *st=stack_bytes,*ck=cookie_bytes;
        for(unsigned j=0;j<128;j++)st[j]=0;
        for(unsigned j=0;j<16;j++)ck[j]=0;
        if(!write64(&mem,INITIAL_SP,SENTINEL))return 10;
        if(!write64(&mem,IMAGE_COOKIE,f->cookie))return 11;
        mx_crt_state s={0};
        s.rip=ENTRY_ADDR;s.rsp=INITIAL_SP;
        s.rbx=f->rbx;s.rdi=f->rdi;
        host h={&mem,f->mono,f->real,(uint32_t)f->pid,(uint32_t)f->tid};
        mx_clock_source clock={&h,mono_cb,real_cb,0};
        mx_import_runtime runtime={&clock,write_cb,&h,&h,pid_cb,tid_cb};
        int status=lifted_crt_run(&s,&mem);
        for(unsigned n=0;n<6 && status==MX_CRT_PAUSED_IMPORT;n++){
            if(lifted_crt_resume_import(&s,&runtime)!=1)return 20+i;
            status=lifted_crt_run(&s,&mem);
        }
        if(status!=MX_CRT_RETURNED || s.fault || s.pending_import)return 40+i;
        if(s.rax!=f->e_rax || s.rbx!=f->e_rbx || s.rcx!=f->e_rcx ||
           s.rdi!=f->e_rdi || s.r11!=f->e_r11)return 60+i;
        if(s.rsp!=f->e_rsp || s.rip!=f->e_rip || s.zf!=f->e_zf)return 80+i;
        if(s.visited!=f->e_visited || s.import_trace!=f->e_trace ||
           s.instructions!=f->e_count || s.imports!=f->e_calls)return 100+i;
        uint64_t cookie=0,comp=0;
        if(!read64(&mem,IMAGE_COOKIE,&cookie) ||
           !read64(&mem,IMAGE_COOKIE+8,&comp))return 120+i;
        if(cookie!=f->e_cookie || comp!=f->e_complement)return 140+i;
        for(unsigned j=0;j<128;j++){
            if(stack_bytes[j]!=f->e_stack[j])return 160+i;
        }
    }
    return 0;
}
#ifdef HOST_SMOKE
int main(void){return smoke();}
#endif
"""

def generated_test_c(samples):
    return (C_HARNESS.replace("STACK_REGION_BASE",str(RSP0-64))
            .replace("COOKIE_VA",str(BASE+COOKIE))
            .replace("ENTRY_VA",str(BASE+ENTRY))
            .replace("INIT_SP",str(RSP0))
            .replace("RETURN_PC",str(SENTINEL))
            .replace("__CASES__",_emit_cases(samples)))

def _checked(args):
    p=subprocess.run(args,text=True,capture_output=True)
    if p.returncode:
        raise RuntimeError("Native command failed ("+args[0]+"), exit="+str(p.returncode)+
                           ": "+(p.stderr or p.stdout)[-3500:])
    return p

def run(executable,output):
    pe=PE(executable)
    if hashlib.sha256(pe.b).hexdigest()!=SHA:
        raise RuntimeError("Wrong original game executable revision")
    if struct.unpack("<Q",pe.read_rva(COOKIE,8))[0]!=0x2b992ddfa232:
        raise RuntimeError("Pinned original security cookie changed")
    body=pe.read_rva(ENTRY,SIZE)
    md=Cs(CS_ARCH_X86,CS_MODE_64)
    original=list(md.disasm(body,ENTRY))
    if len(original)!=39 or sum(ins.size for ins in original)!=SIZE:
        raise RuntimeError("Incomplete pinned original initializer")
    iat={rva:(dll,name) for rva,dll,name in import_slots(pe)}
    generated,meta=translate_crt_cfg(body,ENTRY,iat,image_base=BASE)
    if (meta["decoded_instructions"],meta["blocks"],meta["direct_edges"],len(meta["imports"]))!=(39,9,9,5):
        raise RuntimeError("Translation CFG did not match verified original")
    call_order=[x["iat_symbol"] for x in meta["imports"]]
    if len(call_order)!=5 or set(call_order)!=set(API_NAMES):
        raise RuntimeError("Unexpected imported call set: "+repr(call_order))
    samples=[(f,x64_reference(pe,original,iat,f,call_order)) for f in fixtures()]
    if not all(r["calls"]==5 for f,r in samples if f["cookie"]==0x2b992ddfa232):
        raise RuntimeError("No original x64 import-branch reference coverage")
    if not all(r["calls"]==0 for f,r in samples if f["cookie"]!=0x2b992ddfa232):
        raise RuntimeError("No original x64 early-return reference coverage")
    with tempfile.TemporaryDirectory(prefix="mxbikes-private-crt-cfg-") as td:
        root=Path(td)
        source=root/"translated-original-crt.c"
        smoke=root/"crt-reference-smoke.c"
        source.write_text(generated)
        smoke.write_text(generated_test_c(samples))
        includes=ROOT/"arm64-lab"/"runtime"
        runtime=[includes/name for name in
                 ("mx_time_compat.c","mx_guest_imports.c","mx_import_registry.c")]
        host=root/"crt-host"
        _checked(["cc","-std=c11","-O2","-Wall","-Wextra","-Werror",
                  "-DHOST_SMOKE",f"-I{includes}",
                  str(source),str(smoke),*map(str,runtime),"-o",str(host)])
        _checked([str(host)])
        arm=root/"original-crt-aarch64.elf"
        _checked(["clang","--target=aarch64-unknown-linux-gnu","-fuse-ld=lld",
                  "-nostdlib","-static","-ffreestanding","-fno-stack-protector",
                  "-fno-builtin","-O2","-std=c11",f"-I{includes}",
                  "-Wl,-e,smoke","-Wl,-z,max-page-size=4096",
                  "-Wl,--build-id=none",str(source),str(smoke),
                  *map(str,runtime),"-o",str(arm)])
        result=execute_arm64_elf(arm)
    counts=[r["count"] for f,r in samples]
    report={
        "source":"Verified original user-supplied MX Bikes PE (private CI only)",
        "function_rva":hex(ENTRY),
        "original_instruction_count":39,
        "static_basic_blocks":meta["blocks"],
        "static_control_edges":meta["direct_edges"],
        "original_x64_reference_cases":len(samples),
        "native_host_differential_cases":len(samples),
        "arm64_differential_cases":len(samples),
        "import_branch_cases":sum(f["cookie"]==0x2b992ddfa232 for f,_ in samples),
        "early_return_cases":sum(f["cookie"]!=0x2b992ddfa232 for f,_ in samples),
        "observed_original_dynamic_instruction_counts":sorted(set(counts)),
        "five_kernel32_calls_with_native_host_callbacks":True,
        "import_trace_matches_original":True,
        "guest_register_memory_and_return_matches":True,
        "native_arm64_executed":result["return_to_sentinel"],
        "arm64_smoke_exit":result["arm64_smoke_exit"],
        "translator":"restricted Capstone instruction-to-C CFG, not full Remill",
        "original_engine_booted":False,
        "steam_api_initialized":False,
        "ios_app_built":False,
        "limitations":"One small Win64 CRT initializer with deterministic simulated host APIs; incomplete CPU flags, no Windows loader, original engine or iOS device.",
    }
    output.mkdir(parents=True,exist_ok=True)
    (output/"crt-cfg-arm64-differential.json").write_text(json.dumps(report,indent=2)+"\n")
    summary="\n".join([
        "# Original MX Bikes first CRT initializer — CFG translated and executed on ARM64","",
        "- Original full initializer: **39 statically decoded x64 instructions**",
        "- Recovered CFG: **9 basic blocks, 9 control-continuation edges**",
        "- Original x64 / generated C host / AArch64 Unicorn matches: **"+str(len(samples))+"/"+str(len(samples))+"**",
        "- Both cookie branches exercised, including all 5 original Kernel32 callsites",
        "- Native host-backend callback sequence, bounded guest memory, stack and registers compared",
        "- ARM64 smoke exit: **"+str(result["arm64_smoke_exit"])+"**","",
        "**Restricted Capstone x64-to-C translation executed as AArch64 ELF under Unicorn.**",
        "**No Remill full-function execution, Steam integration, iOS app or game boot.**",""
    ])
    (output/"crt-cfg-arm64-differential.md").write_text(summary)
    print(summary)

if __name__=="__main__":
    if len(sys.argv)!=3:
        raise SystemExit("usage: script.py /private/mxbikes.exe REPORT_DIR")
    run(Path(sys.argv[1]),Path(sys.argv[2]))
