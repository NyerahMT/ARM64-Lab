#!/usr/bin/env python3
"""Private differential: six original MX Bikes CRT GS/CMPXCHG instructions.

Emulates exact original x64 instruction bytes under deterministic single-thread
Unicorn, and generated guest-state C as host and AArch64 ELF. Stops before JE.
No original commercial bytes or derived source/object are uploaded.
"""
from pathlib import Path
import hashlib
import json
import struct
import subprocess
import sys
import tempfile

from unicorn import Uc, UC_ARCH_X86, UC_MODE_64, UC_HOOK_CODE
from unicorn.x86_const import (
    UC_X86_REG_RAX,UC_X86_REG_RBX,UC_X86_REG_RCX,UC_X86_REG_RDI,
    UC_X86_REG_RSI,UC_X86_REG_RSP,UC_X86_REG_RIP,UC_X86_REG_EFLAGS,
    UC_X86_REG_GS_BASE
)
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/"arm64-lab"))
from tools.pe_probe import PE
from tools.crt_gs_lock_lift import lift_crt_gs_lock_prefix
from tools.import_aot_smoke import execute_arm64_elf

SHA="4ae7de3854b4d0a18271679fb57a1f2fdf0b21804417b85dd82055078ea123b6"
BASE=0x140000000
ENTRY=0x2ab049
BOUNDARY=0x2ab064
END=0x2ab066
LOCK_TARGET=0xe4ada8
TEB=0x720000000
GUEST_RSP=0x70000ff08
MASK=0xffffffffffffffff

def cases():
    for k in range(12):
        yield {
            "initial_global":0 if k%2==0 else 0x123400+k*97,
            "thread_identity":(0x112233440000+k*0x317)&MASK,
            "rax":0x1020304000+k*3,
            "rbx":0x50708090+k*17,
            "rcx":0x12345566778+k*89,
            "rdi":0x789456123+k*11,
            "rsi":0x9988776655+k*5,
        }

def x64_original(code,values):
    emu=Uc(UC_ARCH_X86,UC_MODE_64)
    code_page=(BASE+ENTRY)&~0xfff
    global_address=BASE+LOCK_TARGET
    global_page=global_address&~0xfff
    if code_page==global_page:
        raise RuntimeError("Unexpected overlap in original PE sections")
    emu.mem_map(code_page,0x1000)
    emu.mem_map(global_page,0x1000)
    emu.mem_map(TEB,0x1000)
    emu.mem_write(BASE+ENTRY,code)
    emu.mem_write(TEB+0x30,struct.pack("<Q",TEB))
    emu.mem_write(TEB+0x8,struct.pack("<Q",values["thread_identity"]))
    emu.mem_write(global_address,struct.pack("<Q",values["initial_global"]))
    emu.reg_write(UC_X86_REG_GS_BASE,TEB)
    emu.reg_write(UC_X86_REG_RIP,BASE+ENTRY)
    emu.reg_write(UC_X86_REG_RSP,GUEST_RSP)
    for name,reg in (
        ("rax",UC_X86_REG_RAX),("rbx",UC_X86_REG_RBX),
        ("rcx",UC_X86_REG_RCX),("rdi",UC_X86_REG_RDI),
        ("rsi",UC_X86_REG_RSI)):
        emu.reg_write(reg,values[name])
    visited=[]
    allowed={BASE+p for p in (0x2ab049,0x2ab04a,0x2ab053,
                              0x2ab057,0x2ab059,0x2ab05b)}
    def traced(u,pc,size,ctx):
        if pc not in allowed:raise RuntimeError("x64 original GS/LOCK block escaped")
        visited.append(pc)
    emu.hook_add(UC_HOOK_CODE,traced)
    emu.emu_start(BASE+ENTRY,BASE+BOUNDARY,timeout=2_000_000,count=12)
    if len(visited)!=6 or len(set(visited))!=6:
        raise RuntimeError("Wrong original GS/CMPXCHG dynamic instruction count")
    out={}
    for name,reg in (
        ("rax",UC_X86_REG_RAX),("rbx",UC_X86_REG_RBX),
        ("rcx",UC_X86_REG_RCX),("rdi",UC_X86_REG_RDI),
        ("rsi",UC_X86_REG_RSI),("rsp",UC_X86_REG_RSP),
        ("rip",UC_X86_REG_RIP)):
        out[name]=emu.reg_read(reg)
    out["zf"]=int(bool(emu.reg_read(UC_X86_REG_EFLAGS)&64))
    out["global"]=struct.unpack("<Q",emu.mem_read(global_address,8))[0]
    expected_success=values["initial_global"]==0
    if (out["rip"]!=BASE+BOUNDARY or out["rsp"]!=GUEST_RSP or
        out["rbx"]!=values["rbx"] or out["rcx"]!=values["rcx"] or
        out["rdi"]!=values["thread_identity"] or out["rsi"]!=0 or
        out["zf"]!=int(expected_success) or
        out["rax"]!=(0 if expected_success else values["initial_global"]) or
        out["global"]!=(values["thread_identity"] if expected_success else values["initial_global"])):
        raise RuntimeError("Original x64 CMPXCHG register/global semantics unexpectedly differ")
    return out

NATIVE=r"""
#include <stdint.h>
#include "mx_crt_primitives.h"
#define GLOBAL UINT64_C(GLOBAL_VA)
#define TEBBASE UINT64_C(TEB_VA)
#define ENTRY UINT64_C(ENTRY_VA)
#define SP UINT64_C(SP_VA)
typedef struct {
    uint64_t initial_global,thread_identity,rax,rbx,rcx,rdi,rsi;
    uint64_t e_rax,e_rbx,e_rcx,e_rdi,e_rsi,e_rsp,e_rip,e_zf,e_global;
} test_case;
static const test_case inputs[]={
__CASES__
};
static uint8_t teb_mem[256];
static uint8_t shared[8];
int lifted_crt_gs_lock_prefix(mx_crt_state *,mx_cfg_memory *,uint64_t,int);
int smoke(void) {
    mx_cfg_region r[2]={{TEBBASE,teb_mem,sizeof(teb_mem)},
                        {GLOBAL,shared,sizeof(shared)}};
    mx_cfg_memory m={r,2};
    uint64_t tebptr=TEBBASE;
    for(unsigned i=0;i<sizeof(inputs)/sizeof(inputs[0]);i++){
        const test_case *f=&inputs[i];
        volatile uint8_t *teb=teb_mem,*global=shared;
        for(unsigned j=0;j<sizeof(teb_mem);j++)teb[j]=0;
        for(unsigned j=0;j<sizeof(shared);j++)global[j]=0;
        uint64_t initial=f->initial_global;
        if(!mx_cfg_transfer(&m,TEBBASE+UINT64_C(0x30),&tebptr,8,1) ||
           !mx_cfg_transfer(&m,TEBBASE+UINT64_C(8),(void*)&f->thread_identity,8,1) ||
           !mx_cfg_transfer(&m,GLOBAL,&initial,8,1))return 10+i;
        mx_crt_state s={0};
        s.rip=ENTRY;s.rsp=SP;s.rax=f->rax;s.rbx=f->rbx;
        s.rcx=f->rcx;s.rdi=f->rdi;s.rsi=f->rsi;
        if(lifted_crt_gs_lock_prefix(&s,&m,TEBBASE,1)!=MX_CRT_BRANCH_BOUNDARY ||
           s.fault)return 30+i;
        if(s.instructions!=6U || s.visited!=UINT64_C(63))return 50+i;
        if(s.rax!=f->e_rax || s.rbx!=f->e_rbx || s.rcx!=f->e_rcx ||
           s.rdi!=f->e_rdi || s.rsi!=f->e_rsi)return 70+i;
        if(s.rsp!=f->e_rsp || s.rip!=f->e_rip || s.zf!=f->e_zf)return 90+i;
        uint64_t result=0;
        if(!mx_cfg_transfer(&m,GLOBAL,&result,8,0) ||
           result!=f->e_global)return 110+i;
    }
    return 0;
}
#ifdef HOST
int main(void){return smoke();}
#endif
"""

def native_fixtures(pairs):
    rows=[]
    for f,e in pairs:
        keys=("initial_global","thread_identity","rax","rbx","rcx","rdi","rsi")
        x=[f[k] for k in keys]+[e[k] for k in
               ("rax","rbx","rcx","rdi","rsi","rsp","rip","zf","global")]
        rows.append(" {"+",".join("UINT64_C("+str(v)+")" for v in x)+"},")
    return "\n".join(rows)

def checked(argv):
    p=subprocess.run(argv,capture_output=True,text=True)
    if p.returncode:
        raise RuntimeError("x64/ARM64 native build or run failed, exit "+
                           str(p.returncode)+": "+(p.stderr or p.stdout)[-3000:])

def run(executable,outdir):
    pe=PE(executable)
    if hashlib.sha256(pe.b).hexdigest()!=SHA:
        raise RuntimeError("Unexpected original owned executable revision")
    code=pe.read_rva(ENTRY,END-ENTRY)
    c,meta=lift_crt_gs_lock_prefix(code,ENTRY,BASE)
    if (meta["original_instructions_executed"]!=6 or
        meta["stop_before_branch_rva"]!=hex(BOUNDARY) or
        meta["jump_target_rva"]!="0x2ab07f" or
        meta["fully_models_lock_atomicity"]):
        raise RuntimeError("GS/CMPXCHG original static control boundary changed")
    pairs=[(f,x64_original(code,f)) for f in cases()]
    with tempfile.TemporaryDirectory(prefix="mxbikes-gs-lock-") as td:
        root=Path(td)
        translated=root/"private-generated-second-crt-gs.c"
        harness=root/"private-gs-lock-harness.c"
        translated.write_text(c)
        harness.write_text(NATIVE.replace("GLOBAL_VA",str(BASE+LOCK_TARGET))
                           .replace("TEB_VA",str(TEB))
                           .replace("ENTRY_VA",str(BASE+ENTRY))
                           .replace("SP_VA",str(GUEST_RSP))
                           .replace("__CASES__",native_fixtures(pairs)))
        inc=ROOT/"arm64-lab"/"runtime"
        host=root/"gs-lock-host"
        checked(["cc","-std=c11","-O2","-Wall","-Wextra","-Werror",
                 "-DHOST","-I"+str(inc),str(translated),str(harness),"-o",str(host)])
        checked([str(host)])
        arm=root/"original-gs-lock-aarch64.elf"
        checked(["clang","--target=aarch64-unknown-linux-gnu","-fuse-ld=lld",
                 "-nostdlib","-static","-ffreestanding","-fno-stack-protector",
                 "-fno-builtin","-O2","-std=c11","-I"+str(inc),
                 "-Wl,-e,smoke","-Wl,-z,max-page-size=4096",
                 "-Wl,--build-id=none",str(translated),str(harness),"-o",str(arm)])
        result=execute_arm64_elf(arm)
    num=len(pairs)
    success=sum(f["initial_global"]==0 for f,e in pairs)
    report={
        "original_second_crt_rva":hex(ENTRY),
        "original_instructions_differential_verified":6,
        "arm64_matches_reference":num,
        "original_cmpxchg_success_cases":success,
        "original_cmpxchg_failure_cases":num-success,
        "compared":"guest registers, ZF, RIP/RSP, and compare-exchange global memory",
        "unexecuted_following_branch_rva":hex(BOUNDARY),
        "aarch64_unicorn_exit":result["arm64_smoke_exit"],
        "complete_second_crt_execution":False,
        "multi_thread_LOCK_atomicity":False,
        "any_win64_api_executed":False,
        "game_started":False,
        "limitations":"Only the next six x64 instructions before JE, using a single-threaded guest memory fixture. LOCK concurrency, branch taking, Win64 imports and whole CRT remain unimplemented."
    }
    outdir.mkdir(parents=True,exist_ok=True)
    (outdir/"next-crt-gs-lock-arm64.json").write_text(json.dumps(report,indent=2)+"\n")
    summary="\n".join([
        "# Original MX Bikes next CRT — GS/TEB and compare-exchange differential","",
        "- Six original x64 instructions per case: **translated and executed on ARM64**",
        "- Original x64 / native host / ARM64 differential cases: **"+str(num)+"/"+str(num)+"**",
        "- Compare-exchange success and failure paths: **"+str(success)+"/"+str(num-success)+"**",
        "- GS-relative memory, RAX/RBX/RCX/RDI/RSI, guest global, ZF, RSP/RIP: **matched**",
        "- ARM64 ELF test exit: **"+str(result["arm64_smoke_exit"])+"**",
        "- Stop BEFORE original conditional branch at "+hex(BOUNDARY),"",
        "**Only a bounded single-threaded GS/CMPXCHG instruction prefix; no full Windows LOCK atomicity or second-CRT game startup.**",""])
    (outdir/"next-crt-gs-lock-arm64.md").write_text(summary)
    print(summary)

if __name__=="__main__":
    if len(sys.argv)!=3:raise SystemExit("usage: script.py original.exe report-dir")
    run(Path(sys.argv[1]),Path(sys.argv[2]))
