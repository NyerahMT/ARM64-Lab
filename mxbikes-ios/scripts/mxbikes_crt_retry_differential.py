#!/usr/bin/env python3
"""Private original x64 vs native ARM64 compare-exchange recovery CFG tests.

Runs three original-game lock-retry paths (acquired, owned, contended with
single deterministic Sleep callback) and checks guest effects. Game-derived
code/objects remain private temporary files. This is not a real Windows
scheduler, native LOCK atomicity, or end-to-end startup.
"""
import hashlib
import json
import struct
import subprocess
import sys
import tempfile
from pathlib import Path

from capstone import Cs, CS_ARCH_X86, CS_MODE_64
from unicorn import Uc, UC_ARCH_X86, UC_MODE_64, UC_HOOK_CODE
from unicorn.x86_const import (
    UC_X86_REG_RIP,UC_X86_REG_RSP,UC_X86_REG_RAX,UC_X86_REG_RCX,
    UC_X86_REG_RDI,UC_X86_REG_RSI,UC_X86_REG_EFLAGS
)

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/"arm64-lab"))
from tools.pe_probe import PE
from tools.crt_retry_lift import lift_crt_retry
from tools.import_aot_smoke import execute_arm64_elf
from mxbikes_first_callee_emu import import_slots

SHA="4ae7de3854b4d0a18271679fb57a1f2fdf0b21804417b85dd82055078ea123b6"
IMAGE=0x140000000
RETRY=0x2ab059
BRANCH=0x2ab064
AFTER=0x2ab07f
GUEST_GLOBAL=IMAGE+0xe4ada8
STACK=0x700000000
SP=STACK+0x80
SLEEP_STUB=0x600000000

def cases():
    for k in range(18):
        mode=k%3
        thread=0x112233440000+k*0x313
        occupied=0x7a001000+k*0x47
        yield {
            "mode":mode, "thread":thread,
            "initial_global":thread if mode in (0,1) else occupied,
            "rax":0 if mode==0 else (thread if mode==1 else occupied),
            "rsi":0x55667700+k*0x191,
            "rcx":0x11100100+k*0x11,
            "zf":1 if mode==0 else 0,
        }

def original_x64(code,slot,inst,f):
    cpu=Uc(UC_ARCH_X86,UC_MODE_64)
    pages={(IMAGE+RETRY)&~0xfff,(IMAGE+slot)&~0xfff,GUEST_GLOBAL&~0xfff}
    for pg in pages:cpu.mem_map(pg,0x1000)
    cpu.mem_map(STACK,0x1000)
    cpu.mem_map(SLEEP_STUB,0x1000)
    cpu.mem_write(IMAGE+RETRY,code)
    cpu.mem_write(IMAGE+slot,struct.pack("<Q",SLEEP_STUB))
    cpu.mem_write(SLEEP_STUB,b"\xc3")
    cpu.mem_write(GUEST_GLOBAL,struct.pack("<Q",f["initial_global"]))
    for reg,value in (
        (UC_X86_REG_RIP,IMAGE+BRANCH),
        (UC_X86_REG_RSP,SP),
        (UC_X86_REG_RAX,f["rax"]),
        (UC_X86_REG_RSI,f["rsi"]),
        (UC_X86_REG_RDI,f["thread"]),
        (UC_X86_REG_RCX,f["rcx"]),
        (UC_X86_REG_EFLAGS,0x202 | (f["zf"]<<6))
    ):cpu.reg_write(reg,value)
    seen={"steps":0,"bits":0,"sleep":0}
    addresses={IMAGE+i.address:num for num,i in enumerate(inst)}
    def code_hook(emu,pc,size,user_data):
        if pc==SLEEP_STUB:
            seen["sleep"]+=1
            if f["mode"]!=2 or seen["sleep"]!=1:
                raise RuntimeError("Unexpected original Sleep count or mode")
            if emu.reg_read(UC_X86_REG_RCX)!=1000:
                raise RuntimeError("Original Sleep duration diverged")
            if emu.reg_read(UC_X86_REG_RSP)%16!=8:
                raise RuntimeError("Original Sleep callee ABI stack alignment diverged")
            emu.mem_write(GUEST_GLOBAL,struct.pack("<Q",0))
            return
        if pc not in addresses:
            raise RuntimeError("Original x64 escaped decoded retry branch CFG")
        seen["steps"]+=1
        seen["bits"]|=1<<addresses[pc]
    cpu.hook_add(UC_HOOK_CODE,code_hook)
    cpu.emu_start(IMAGE+BRANCH,IMAGE+AFTER,timeout=2_000_000,count=80)
    output={
        "rax":cpu.reg_read(UC_X86_REG_RAX),
        "rdi":cpu.reg_read(UC_X86_REG_RDI),
        "rsi":cpu.reg_read(UC_X86_REG_RSI),
        "rcx":cpu.reg_read(UC_X86_REG_RCX),
        "rsp":cpu.reg_read(UC_X86_REG_RSP),
        "rip":cpu.reg_read(UC_X86_REG_RIP),
        "zf":1 if cpu.reg_read(UC_X86_REG_EFLAGS)&64 else 0,
        "global":struct.unpack("<Q",cpu.mem_read(GUEST_GLOBAL,8))[0],
        "sleep_return":struct.unpack("<Q",cpu.mem_read(SP-8,8))[0],
        "visited":seen["bits"],
        "steps":seen["steps"],
        "sleep":seen["sleep"],
    }
    if output["rip"]!=IMAGE+AFTER or output["rsp"]!=SP:
        raise RuntimeError("Original branch did not reach bounded continuation")
    if output["sleep"]!=(1 if f["mode"]==2 else 0):
        raise RuntimeError("Original branch Sleep count disagreed with fixture")
    if output["global"]!=f["thread"] or output["zf"]!=1:
        raise RuntimeError("Original CRT guest CAS global/flags disagree")
    return output

HARNESS=r"""
#include <stdint.h>
#include "mx_crt_primitives.h"
#define GLOBAL UINT64_C(GUEST_GLOBAL)
#define SP UINT64_C(GUEST_SP)
#define BRANCH UINT64_C(GUEST_BRANCH)
typedef struct {
    uint64_t mode,thread,initial_global,rax,rsi,rcx,zf;
    uint64_t expected_rax,expected_rdi,expected_rsi,expected_rcx;
    uint64_t expected_rsp,expected_rip,expected_zf,expected_global;
    uint64_t expected_sleep_return,expected_visited,expected_steps,expected_sleep;
} fixture;
static const fixture data[]={
__CASES__
};
static uint8_t global_bytes[8],stack_bytes[256];
typedef struct {mx_cfg_memory *mem;uint32_t calls;uint32_t release;} hook;
static int on_sleep(void *ptr,uint32_t milliseconds){
    hook *h=(hook*)ptr;
    if(milliseconds!=1000U)return 0;
    h->calls++;
    if(h->release) {
        uint64_t zero=0;
        return mx_cfg_transfer(h->mem,GLOBAL,&zero,8,1);
    }
    return 1;
}
int lifted_crt_lock_retry(mx_crt_state*,mx_cfg_memory*,
                          int(*)(void*,uint32_t),void*,int);
int smoke(void){
    mx_cfg_region regions[2]={
        {GLOBAL,global_bytes,sizeof(global_bytes)},
        {SP-UINT64_C(128),stack_bytes,sizeof(stack_bytes)}
    };
    mx_cfg_memory mem={regions,2};
    for(unsigned idx=0;idx<sizeof(data)/sizeof(data[0]);idx++){
        const fixture *f=&data[idx];
        volatile uint8_t *a=stack_bytes,*b=global_bytes;
        for(unsigned k=0;k<sizeof(stack_bytes);k++)a[k]=0;
        for(unsigned k=0;k<sizeof(global_bytes);k++)b[k]=0;
        uint64_t initial=f->initial_global;
        if(!mx_cfg_transfer(&mem,GLOBAL,&initial,8,1))return 10+idx;
        mx_crt_state s={0};
        s.rax=f->rax;
        s.rdi=f->thread;
        s.rsi=f->rsi;
        s.rcx=f->rcx;
        s.zf=(uint8_t)f->zf;
        s.rsp=SP;
        s.rip=BRANCH;
        hook sleeper={&mem,0,f->mode==2};
        if(lifted_crt_lock_retry(&s,&mem,on_sleep,&sleeper,1)!=MX_CRT_BRANCH_BOUNDARY)
            return 30+idx;
        if(s.fault || s.pending_import || s.imports!=sleeper.calls)return 50+idx;
        if(s.rax!=f->expected_rax || s.rdi!=f->expected_rdi ||
           s.rsi!=f->expected_rsi || s.rcx!=f->expected_rcx)return 70+idx;
        if(s.rsp!=f->expected_rsp || s.rip!=f->expected_rip ||
           s.zf!=f->expected_zf)return 90+idx;
        if(s.visited!=f->expected_visited ||
           s.instructions!=f->expected_steps ||
           s.imports!=f->expected_sleep)return 110+idx;
        uint64_t read_global=0,read_return=0;
        if(!mx_cfg_transfer(&mem,GLOBAL,&read_global,8,0) ||
           !mx_cfg_transfer(&mem,SP-8U,&read_return,8,0))return 130+idx;
        if(read_global!=f->expected_global ||
           read_return!=f->expected_sleep_return)return 150+idx;
    }
    return 0;
}
#ifdef HOST
int main(void){return smoke();}
#endif
"""

def input_cases(pairs):
    lines=[]
    for f,e in pairs:
        values=[f[k] for k in ("mode","thread","initial_global","rax","rsi","rcx","zf")]
        values += [e[k] for k in ("rax","rdi","rsi","rcx","rsp","rip","zf",
                                   "global","sleep_return","visited","steps","sleep")]
        lines.append(" {"+",".join("UINT64_C("+str(v)+")" for v in values)+"},")
    return "\n".join(lines)

def execute(args):
    proc=subprocess.run(args,capture_output=True,text=True)
    if proc.returncode:
        raise RuntimeError("native x64/ARM64 retry differential failure (exit "+
                           str(proc.returncode)+"): "+(proc.stderr or proc.stdout)[-3000:])

def run(exe,reports):
    pe=PE(exe)
    if hashlib.sha256(pe.b).hexdigest()!=SHA:
        raise RuntimeError("Private original executable SHA mismatch")
    retry=pe.read_rva(RETRY,BRANCH-RETRY)
    branch=pe.read_rva(BRANCH,AFTER-BRANCH)
    iat={rva:(dll.lower(),name) for rva,dll,name in import_slots(pe)}
    generated,meta=lift_crt_retry(retry,branch,RETRY,BRANCH,iat,IMAGE)
    if (meta["stop_before_rva"]!=hex(AFTER) or
        meta["static_instruction_count"]!=10 or
        meta["concurrent_lock_semantics"]):
        raise RuntimeError("Unexpected original retry CFG validation metadata")
    md=Cs(CS_ARCH_X86,CS_MODE_64)
    md.detail=True
    instructions=list(md.disasm(retry+branch,RETRY))
    if len(instructions)!=10:
        raise RuntimeError("Unexpected original retry source boundaries")
    slot=int(meta["validated_sleep_iat_slot"],16)
    pairs=[(case,original_x64(retry+branch,slot,instructions,case))
           for case in cases()]
    if len(pairs)!=18 or set(f["mode"] for f,e in pairs)!={0,1,2}:
        raise RuntimeError("Incomplete three-way ownership input matrix")
    with tempfile.TemporaryDirectory(prefix="mxbikes-lock-retry-private-") as td:
        root=Path(td)
        source=root/"translated-original-retry.c"
        test=root/"native-matrix.c"
        source.write_text(generated)
        test.write_text(HARNESS.replace("GUEST_GLOBAL",str(GUEST_GLOBAL))
                        .replace("GUEST_SP",str(SP))
                        .replace("GUEST_BRANCH",str(IMAGE+BRANCH))
                        .replace("__CASES__",input_cases(pairs)))
        includes=ROOT/"arm64-lab"/"runtime"
        host=root/"host"
        execute(["cc","-std=c11","-O2","-Wall","-Wextra","-Werror",
                 "-DHOST","-I"+str(includes),str(source),str(test),
                 "-o",str(host)])
        execute([str(host)])
        arm=root/"original-retry-arm64.elf"
        execute(["clang","--target=aarch64-unknown-linux-gnu","-fuse-ld=lld",
                 "-nostdlib","-static","-ffreestanding","-fno-builtin",
                 "-fno-stack-protector","-O2","-std=c11","-I"+str(includes),
                 "-Wl,-e,smoke","-Wl,-z,max-page-size=4096",
                 "-Wl,--build-id=none",str(source),str(test),"-o",str(arm)])
        arm_result=execute_arm64_elf(arm)
    reports.mkdir(parents=True,exist_ok=True)
    report={
        "original_game_sha_verified":True,
        "retry_cfg_original_static_instructions":10,
        "original_x64_vs_aarch64_cases":len(pairs),
        "test_modes":{"acquired":6,"recursive_owner":6,"contended_one_sleep_retry":6},
        "original_callsite":"kernel32.dll!Sleep",
        "sleep_is_deterministic_fixture":True,
        "lock_is_exclusive_single_thread":True,
        "real_windows_sleep_implemented":False,
        "arm64_exit":arm_result["arm64_smoke_exit"],
        "guest_machine_state_matched":True,
        "stops_before_original_rva":hex(AFTER),
        "full_second_CRT_executed":False,
        "iphone_game_running":False
    }
    (reports/"next-crt-retry-arm64.json").write_text(json.dumps(report,indent=2)+"\n")
    summary="\n".join([
        "# Original MX Bikes CRT lock ownership + retry differential","",
        "- Original ten-instruction branch/retry CFG recovered: **yes**",
        "- Original x64 / native host / ARM64 executions: **18/18 matched**",
        "- Acquired, recursive owner, one Sleep+retry cases: **6 / 6 / 6**",
        "- Callbacks are deterministic; NOT genuine Windows Sleep",
        "- Guest RAX/RDI/RSI/RCX, ZF, RSP/RIP, global/stack effects, path bitmap: **matched**",
        "- ARM64 ELF smoke exit: **"+str(arm_result["arm64_smoke_exit"])+"**","",
        "**Stops before the next CRT global-state instruction; not a full startup or iOS boot.**",""])
    (reports/"next-crt-retry-arm64.md").write_text(summary)
    print(summary)

if __name__=="__main__":
    if len(sys.argv)!=3:
        raise SystemExit("usage: script.py /private/mxbikes.exe REPORT_DIR")
    run(Path(sys.argv[1]),Path(sys.argv[2]))
