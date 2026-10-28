#!/usr/bin/env python3
"""Private bounded *joined* original CRT prefix test, not a Windows game boot.

Compare 12 original x64 instructions (prologue + CALL + GS/LOCK region) against
compiled ARM64 from two strict native translators, with a deterministic
synthetic GetStartupInfoA guest-memory response. Stop before the first JE.
Commercial bytes and derived source/objects stay ephemeral and private.
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
    UC_X86_REG_RIP,UC_X86_REG_RSP,UC_X86_REG_RSI,UC_X86_REG_RDI,
    UC_X86_REG_RAX,UC_X86_REG_RBX,UC_X86_REG_RCX,UC_X86_REG_EFLAGS,
    UC_X86_REG_GS_BASE
)

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/"arm64-lab"))
from tools.pe_probe import PE
from tools.crt_entry_prefix_lift import lift_crt_entry_prefix
from tools.crt_gs_lock_lift import lift_crt_gs_lock_prefix
from tools.import_aot_smoke import execute_arm64_elf
from mxbikes_first_callee_emu import import_slots

SHA="4ae7de3854b4d0a18271679fb57a1f2fdf0b21804417b85dd82055078ea123b6"
BASE=0x140000000
ENTRY=0x2ab02c
IMPORTED_CALL=0x2ab043
AFTER_IMPORT=0x2ab049
STOP=0x2ab064
END=0x2ab066
GLOBAL=BASE+0xe4ada8
TEB=0x720000000
STACK=0x700000000
SP=STACK+0xff08
WIN=SP-256
STUB=0x600000000
RETURN=BASE+AFTER_IMPORT
STARTUPINFO_SIZE=104
ORIGINAL_PCS=tuple(BASE+x for x in
  (0x2ab02c,0x2ab031,0x2ab032,0x2ab039,0x2ab03e,
   0x2ab043,0x2ab049,0x2ab04a,0x2ab053,0x2ab057,0x2ab059,0x2ab05b))

def inputs():
    for k in range(12):
        yield {
            "rsi":0x12345600000 + k*0x111111,
            "rdi":0x33445500000 + k*0x12121,
            "rax":0x88abcdef000 + k*0x1003,
            "rbx":0x554433221100 + k*0x77,
            "rcx":0x122334455 + k*0x307,
            "thread":0x112233445566 + k*0x100,
            "global_initial":0 if k%2==0 else 1000+k*37,
        }

def reference_x64(code,slot,f):
    u=Uc(UC_ARCH_X86,UC_MODE_64)
    for page,size in (
        ((BASE+ENTRY)&~0xfff,0x1000),
        ((BASE+slot)&~0xfff,0x1000),
        (GLOBAL&~0xfff,0x1000),
        (STUB,0x1000),
        (TEB,0x1000),
        (STACK,0x20000)):
        u.mem_map(page,size)
    u.mem_write(BASE+ENTRY,code)
    u.mem_write(BASE+slot,struct.pack("<Q",STUB))
    u.mem_write(STUB,b"\xc3")
    u.mem_write(TEB+0x30,struct.pack("<Q",TEB))
    u.mem_write(TEB+0x08,struct.pack("<Q",f["thread"]))
    u.mem_write(GLOBAL,struct.pack("<Q",f["global_initial"]))
    u.reg_write(UC_X86_REG_GS_BASE,TEB)
    u.reg_write(UC_X86_REG_RIP,BASE+ENTRY)
    u.reg_write(UC_X86_REG_RSP,SP)
    for name,reg in (("rax",UC_X86_REG_RAX),("rbx",UC_X86_REG_RBX),
                     ("rcx",UC_X86_REG_RCX),("rdi",UC_X86_REG_RDI),
                     ("rsi",UC_X86_REG_RSI)):
        u.reg_write(reg,f[name])
    executed=[]
    api_calls=0
    def hook(emu,pc,length,ctx):
        nonlocal api_calls
        if pc==STUB:
            api_calls+=1
            if emu.reg_read(UC_X86_REG_RSP)%16!=8:
                raise RuntimeError("Original Win64 imported callee stack misaligned")
            ptr=emu.reg_read(UC_X86_REG_RCX)
            if not WIN<=ptr or ptr+STARTUPINFO_SIZE>WIN+512:
                raise RuntimeError("GetStartupInfoA destination escaped guest stack")
            payload=struct.pack("<I",STARTUPINFO_SIZE)+bytes(STARTUPINFO_SIZE-4)
            emu.mem_write(ptr,payload)
            return
        if pc not in ORIGINAL_PCS:
            raise RuntimeError("Original joined CRT path escaped approved x64 boundaries")
        executed.append(pc)
    u.hook_add(UC_HOOK_CODE,hook)
    u.emu_start(BASE+ENTRY,BASE+STOP,timeout=2_000_000,count=32)
    if api_calls!=1 or tuple(executed)!=ORIGINAL_PCS:
        raise RuntimeError("Original x64 joined CRT call/return/control sequence diverged")
    result={}
    for name,reg in (("rax",UC_X86_REG_RAX),("rbx",UC_X86_REG_RBX),
                     ("rcx",UC_X86_REG_RCX),("rdi",UC_X86_REG_RDI),
                     ("rsi",UC_X86_REG_RSI),("rsp",UC_X86_REG_RSP),
                     ("rip",UC_X86_REG_RIP)):
        result[name]=u.reg_read(reg)
    result["zf"]=int(bool(u.reg_read(UC_X86_REG_EFLAGS)&64))
    result["global"]=struct.unpack("<Q",u.mem_read(GLOBAL,8))[0]
    result["stack"]=bytes(u.mem_read(WIN,512))
    return result

HARNESS=r"""
#include <stdint.h>
#include "mx_crt_primitives.h"
#define WIN UINT64_C(STACK_WINDOW)
#define SP UINT64_C(STACK_POINTER)
#define ENTRY UINT64_C(GUEST_ENTRY)
#define AFTER UINT64_C(AFTER_API)
#define CALL_RETURN UINT64_C(GUEST_CALL_RETURN)
#define TEB UINT64_C(TEB_BASE)
#define GLOBAL UINT64_C(GLOBAL_ADDR)
typedef struct {
    uint64_t rsi,rdi,rax,rbx,rcx,thread,global_initial;
    uint64_t e_rax,e_rbx,e_rcx,e_rdi,e_rsi,e_rsp,e_rip,e_zf,e_global;
    uint8_t e_stack[512];
} fixture;
static const fixture data[]={
__CASES__
};
static uint8_t stack_window[512],teb_area[256],shared[8];
int lifted_crt_entry_prefix(mx_crt_state *,mx_cfg_memory *);
int lifted_crt_gs_lock_prefix(mx_crt_state *,mx_cfg_memory *,uint64_t,int);
int smoke(void) {
    mx_cfg_region r[3]={{WIN,stack_window,512},{TEB,teb_area,256},
                        {GLOBAL,shared,8}};
    mx_cfg_memory m={r,3};
    for(unsigned k=0;k<sizeof(data)/sizeof(data[0]);k++){
        const fixture *f=&data[k];
        volatile uint8_t *stack=stack_window,*teb=teb_area,*global=shared;
        for(unsigned j=0;j<512;j++)stack[j]=0;
        for(unsigned j=0;j<256;j++)teb[j]=0;
        for(unsigned j=0;j<8;j++)global[j]=0;
        uint64_t ptr=TEB;
        uint64_t initial=f->global_initial;
        if(!mx_cfg_transfer(&m,TEB+UINT64_C(0x30),&ptr,8,1) ||
           !mx_cfg_transfer(&m,TEB+UINT64_C(8),(void*)&f->thread,8,1) ||
           !mx_cfg_transfer(&m,GLOBAL,&initial,8,1))return 10+k;
        mx_crt_state s={0};
        s.rip=ENTRY;s.rsp=SP;s.rax=f->rax;s.rbx=f->rbx;
        s.rcx=f->rcx;s.rdi=f->rdi;s.rsi=f->rsi;
        if(lifted_crt_entry_prefix(&s,&m)!=MX_CRT_IMPORT_BOUNDARY)return 30+k;
        if(s.rip!=CALL_RETURN-6 || s.instructions!=5U || s.visited!=31U ||
           s.pending_import)return 40+k;

        /* Private deterministic replacement for Win64 CALL/GetStartupInfoA/RET.
         * Write the original guest CALL return PC then 104 bytes of synthetic
         * STARTUPINFOA. This does not implement host Windows semantics. */
        uint64_t return_pc=CALL_RETURN;
        if(!mx_cfg_transfer(&m,s.rsp-8U,&return_pc,8,1))return 50+k;
        for(unsigned j=0;j<13;j++){
            uint64_t word=(j==0 ? UINT64_C(104) : 0U);
            if(!mx_cfg_transfer(&m,s.rcx+8U*j,&word,8,1))return 60+k;
        }
        s.rip=AFTER;
        /* Reset only differential instrumentation, not guest machine state. */
        s.visited=0;s.instructions=0;
        if(lifted_crt_gs_lock_prefix(&s,&m,TEB,1)!=MX_CRT_BRANCH_BOUNDARY)return 80+k;
        if(s.instructions!=6U || s.visited!=63U || s.fault)return 100+k;
        if(s.rax!=f->e_rax || s.rbx!=f->e_rbx || s.rcx!=f->e_rcx ||
           s.rdi!=f->e_rdi || s.rsi!=f->e_rsi)return 120+k;
        if(s.rsp!=f->e_rsp || s.rip!=f->e_rip || s.zf!=f->e_zf)return 140+k;
        uint64_t value=0;
        if(!mx_cfg_transfer(&m,GLOBAL,&value,8,0) || value!=f->e_global)return 160+k;
        for(unsigned j=0;j<512;j++) {
            if(stack_window[j]!=f->e_stack[j])return 180+k;
        }
    }
    return 0;
}
#ifdef HOST
int main(void){return smoke();}
#endif
"""

def emit_cases(pairs):
    lines=[]
    for f,e in pairs:
        src=[f[k] for k in ("rsi","rdi","rax","rbx","rcx","thread","global_initial")]
        dst=[e[k] for k in ("rax","rbx","rcx","rdi","rsi","rsp","rip","zf","global")]
        contents="{"+",".join(str(x) for x in e["stack"])+"}"
        lines.append(" {"+",".join("UINT64_C("+str(v)+")" for v in src+dst)+","+contents+"},")
    return "\n".join(lines)

def checked(argv):
    proc=subprocess.run(argv,capture_output=True,text=True)
    if proc.returncode:
        raise RuntimeError("Native joined CRT failed (exit "+str(proc.returncode)+"): "+
                           (proc.stderr or proc.stdout)[-3200:])

def run(executable,out):
    pe=PE(executable)
    if hashlib.sha256(pe.b).hexdigest()!=SHA:
        raise RuntimeError("Pinned original executable SHA mismatch")
    iat={rva:(dll.lower(),name) for rva,dll,name in import_slots(pe)}
    c1,info1=lift_crt_entry_prefix(pe.read_rva(ENTRY,AFTER_IMPORT-ENTRY),ENTRY,iat,BASE)
    c2,info2=lift_crt_gs_lock_prefix(pe.read_rva(AFTER_IMPORT,END-AFTER_IMPORT),AFTER_IMPORT,BASE)
    if info1["stop_before_import_rva"]!=hex(IMPORTED_CALL) or info2["stop_before_branch_rva"]!=hex(STOP):
        raise RuntimeError("Unexpected verified original instruction continuity")
    import_site=pe.read_rva(IMPORTED_CALL,AFTER_IMPORT-IMPORTED_CALL)
    from capstone import Cs,CS_ARCH_X86,CS_MODE_64
    md=Cs(CS_ARCH_X86,CS_MODE_64);md.detail=True
    ins=list(md.disasm(import_site,IMPORTED_CALL))
    if len(ins)!=1 or ins[0].mnemonic!="call":
        raise RuntimeError("Original imported CALL did not decode")
    slot=ins[0].address+ins[0].size+ins[0].operands[0].mem.disp
    if iat.get(slot)!=("kernel32.dll","GetStartupInfoA"):
        raise RuntimeError("Unrecognized call IAT identity")
    original=pe.read_rva(ENTRY,END-ENTRY)
    pairs=[(f,reference_x64(original,slot,f)) for f in inputs()]
    with tempfile.TemporaryDirectory(prefix="original-joined-crt-") as tmp:
        root=Path(tmp)
        first=root/"private-first-prefix.c"
        second=root/"private-gs-lock-prefix.c"
        harness=root/"private-joined-guest-harness.c"
        first.write_text(c1)
        second.write_text(c2)
        harness.write_text(HARNESS.replace("STACK_WINDOW",str(WIN))
                     .replace("STACK_POINTER",str(SP))
                     .replace("GUEST_ENTRY",str(BASE+ENTRY))
                     .replace("AFTER_API",str(BASE+AFTER_IMPORT))
                     .replace("GUEST_CALL_RETURN",str(RETURN))
                     .replace("TEB_BASE",str(TEB))
                     .replace("GLOBAL_ADDR",str(GLOBAL))
                     .replace("__CASES__",emit_cases(pairs)))
        inc=ROOT/"arm64-lab"/"runtime"
        host=root/"guest-host"
        checked(["cc","-std=c11","-O2","-Wall","-Wextra","-Werror",
                 "-DHOST","-I"+str(inc),str(first),str(second),
                 str(harness),"-o",str(host)])
        checked([str(host)])
        arm=root/"guest-arm64.elf"
        checked(["clang","--target=aarch64-unknown-linux-gnu","-fuse-ld=lld",
                 "-nostdlib","-static","-ffreestanding","-fno-builtin",
                 "-fno-stack-protector","-O2","-std=c11","-I"+str(inc),
                 "-Wl,-e,smoke","-Wl,-z,max-page-size=4096",
                 "-Wl,--build-id=none",str(first),str(second),str(harness),
                 "-o",str(arm)])
        output=execute_arm64_elf(arm)
    out.mkdir(parents=True,exist_ok=True)
    report={
        "original_x64_instructions_in_joined_path":12,
        "full_second_crt_original_instruction_count":126,
        "original_x64_reference_cases":len(pairs),
        "native_arm64_matched_cases":len(pairs),
        "import_call_name":"kernel32.dll::GetStartupInfoA",
        "import_callback_kind":"deterministic synthetic 104-byte STARTUPINFOA",
        "gs_and_cmpxchg_success_cases":6,
        "gs_and_cmpxchg_failure_cases":6,
        "compared":"guest register subset, ZF, stack window 512 bytes, global compare-exchange and return-to-branch point",
        "stops_before_branch_rva":hex(STOP),
        "aarch64_smoke_exit":output["arm64_smoke_exit"],
        "windows_api_implemented":False,
        "real_game_booted":False,
        "ios_executed":False,
        "limitations":"Joined proof uses a synthetic GetStartupInfoA payload; two restricted lifts and one original call are not a general CRT runtime."
    }
    (out/"next-crt-joined-arm64.json").write_text(json.dumps(report,indent=2)+"\n")
    md=["# Original MX Bikes CRT startup — joined ARM64 execution through synthetic imported call","",
        "- Joined original x64 instructions across two translated prefixes and a Win64 imported CALL: **12**",
        "- Original x64 vs native host vs Unicorn AArch64 matches: **"+str(len(pairs))+"/"+str(len(pairs))+"**",
        "- Deterministic synthetic 104-byte GetStartupInfoA response, NOT Windows API implementation",
        "- Original GS/TEB access and single-thread compare-exchange outcomes: 6 successes, 6 failures",
        "- Stack bytes, supported registers, global writes, ZF and pre-branch RIP: **matched**",
        "- ARM64 ELF exit: **"+str(output["arm64_smoke_exit"])+"**","",
        "**Stops before JE. Only 12/126 original instructions covered; no genuine Windows API, Steam, engine or iOS.**",""]
    summary="\n".join(md)
    (out/"next-crt-joined-arm64.md").write_text(summary)
    print(summary)

if __name__=="__main__":
    if len(sys.argv)!=3:raise SystemExit("usage: script.py /private/original.exe report-dir")
    run(Path(sys.argv[1]),Path(sys.argv[2]))
