#!/usr/bin/env python3
"""Private original x64 vs AArch64 CRT post-init release and direct-call frontier.

Tests three ownership outcomes with exclusive guest state. A memory XCHG is
modeled in isolation, not a concurrent Windows process. No original bytes or
generated original-code outputs are uploaded.
"""
from pathlib import Path
import hashlib,json,struct,subprocess,sys,tempfile
from capstone import Cs,CS_ARCH_X86,CS_MODE_64
from unicorn import Uc,UC_ARCH_X86,UC_MODE_64,UC_HOOK_CODE
from unicorn.x86_const import (
    UC_X86_REG_RAX,UC_X86_REG_RBX,UC_X86_REG_RCX,UC_X86_REG_RDX,
    UC_X86_REG_RDI,UC_X86_REG_RSI,UC_X86_REG_RSP,UC_X86_REG_RIP,UC_X86_REG_EFLAGS
)

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/"arm64-lab"))
from tools.pe_probe import PE
from tools.crt_common_release_lift import lift_crt_common_release
from tools.import_aot_smoke import execute_arm64_elf

HASH="4ae7de3854b4d0a18271679fb57a1f2fdf0b21804417b85dd82055078ea123b6"
BASE=0x140000000
START=0x2ab0d3
END=0x2ab108
CALL=0x2ab0ec
TARGET=0x2ab942
STATE=BASE+0xe4ada0
OWNER=BASE+0xe4ada8
STACK=0x700000000
SP=STACK+0xff08
REGS=(("rax",UC_X86_REG_RAX),("rbx",UC_X86_REG_RBX),
      ("rcx",UC_X86_REG_RCX),("rdx",UC_X86_REG_RDX),
      ("rdi",UC_X86_REG_RDI),("rsi",UC_X86_REG_RSI),
      ("rsp",UC_X86_REG_RSP),("rip",UC_X86_REG_RIP))
KEYS=("rax","rbx","rcx","rdx","rdi","rsi","rsp","rip",
      "zf","state_after","owner_after","visited","instructions")

def cases():
    for i in range(21):
        mode=i%3
        yield {
            "mode":mode,
            "state":1 if mode==0 else 2,
            "owner":0x123456789000+i*0x97,
            "rax":0x987654320000+i*31,
            "rbx":0x334455660000+i*73,
            "rcx":0x555566660000+i*17,
            "rdx":0x777788880000+i*49,
            "rdi":0x888877770000+i*19,
            "rsi":1 if mode==1 else 0,
        }

def x64(code,instructions,f):
    cpu=Uc(UC_ARCH_X86,UC_MODE_64)
    cpu.mem_map((BASE+START)&~4095,4096)
    cpu.mem_map(STATE&~4095,4096)
    cpu.mem_map(STACK,0x10000)
    cpu.mem_write(BASE+START,code)
    cpu.mem_write(STATE,struct.pack("<I",f["state"]))
    cpu.mem_write(OWNER,struct.pack("<Q",f["owner"]))
    cpu.reg_write(UC_X86_REG_EFLAGS,0x202)
    for name,reg in REGS:
        cpu.reg_write(reg,(BASE+START) if name=="rip" else
                      SP if name=="rsp" else f[name])
    stop=CALL if f["state"]==1 else END
    index={BASE+ins.address:n for n,ins in enumerate(instructions)}
    observed={"visited":0,"instructions":0}
    def trace(u,pc,length,_):
        if pc not in index or pc==BASE+CALL:
            raise RuntimeError("Original x64 CRT exited bounded release CFG")
        observed["visited"]|=1<<index[pc]
        observed["instructions"]+=1
    cpu.hook_add(UC_HOOK_CODE,trace)
    cpu.emu_start(BASE+START,BASE+stop,timeout=2_000_000,count=24)
    result={name:cpu.reg_read(reg) for name,reg in REGS}
    result["zf"]=int(bool(cpu.reg_read(UC_X86_REG_EFLAGS)&64))
    result["state_after"]=struct.unpack("<I",cpu.mem_read(STATE,4))[0]
    result["owner_after"]=struct.unpack("<Q",cpu.mem_read(OWNER,8))[0]
    result.update(observed)
    if result["rip"]!=BASE+stop or result["rsp"]!=SP:
        raise RuntimeError("Original guest did not reach expected stop boundary")
    if f["mode"]==2 and (result["owner_after"]!=0 or result["rax"]!=f["owner"]):
        raise RuntimeError("Original unlock XCHG result differs from expected")
    if f["mode"]!=2 and result["owner_after"]!=f["owner"]:
        raise RuntimeError("Original recursive/direct path unexpectedly released lock")
    return result

C=r"""
#include <stdint.h>
#include "mx_crt_primitives.h"
#define ENTRY UINT64_C(ENTRY_VA)
#define GLOBAL_STATE UINT64_C(STATE_VA)
#define OWNER UINT64_C(OWNER_VA)
#define SP UINT64_C(SP_VA)
typedef struct {
    uint64_t mode,state,owner,rax,rbx,rcx,rdx,rdi,rsi;
    uint64_t e_rax,e_rbx,e_rcx,e_rdx,e_rdi,e_rsi,e_rsp,e_rip;
    uint64_t e_zf,e_state_after,e_owner_after,e_visited,e_instructions;
} fixture;
static const fixture fixtures[]={
__CASES__
};
static uint8_t state_bytes[4],owner_bytes[8];
int lifted_crt_common_release(mx_crt_state*,mx_cfg_memory*,uint64_t*,int);
int smoke(void){
    mx_cfg_region regions[2]={{GLOBAL_STATE,state_bytes,4},{OWNER,owner_bytes,8}};
    mx_cfg_memory m={regions,2};
    for(unsigned i=0;i<sizeof(fixtures)/sizeof(fixtures[0]);i++){
        const fixture *f=&fixtures[i];
        uint32_t state=(uint32_t)f->state;
        uint64_t owner=f->owner;
        if(!mx_cfg_transfer(&m,GLOBAL_STATE,&state,4,1) ||
           !mx_cfg_transfer(&m,OWNER,&owner,8,1))return 10+i;
        mx_crt_state s={0};
        s.rip=ENTRY;s.rsp=SP;s.rax=f->rax;s.rbx=f->rbx;
        s.rcx=f->rcx;s.rdi=f->rdi;s.rsi=f->rsi;
        uint64_t rdx=f->rdx;
        int status=lifted_crt_common_release(&s,&m,&rdx,1);
        int want=f->state==1U?5:MX_CRT_BRANCH_BOUNDARY;
        if(status!=want||s.fault||s.pending_import||s.imports)return 40+i;
        if(s.rax!=f->e_rax||s.rbx!=f->e_rbx||s.rcx!=f->e_rcx||
           rdx!=f->e_rdx||s.rdi!=f->e_rdi||s.rsi!=f->e_rsi)return 70+i;
        if(s.rsp!=f->e_rsp||s.rip!=f->e_rip||s.zf!=f->e_zf)return 100+i;
        if(s.visited!=f->e_visited||s.instructions!=f->e_instructions)
            return 130+i;
        uint32_t actual_state=0;
        uint64_t actual_owner=0;
        if(!mx_cfg_transfer(&m,GLOBAL_STATE,&actual_state,4,0)||
           !mx_cfg_transfer(&m,OWNER,&actual_owner,8,0))return 160+i;
        if(actual_state!=f->e_state_after||actual_owner!=f->e_owner_after)
            return 190+i;
    }
    return 0;
}
#ifdef HOST
int main(void){return smoke();}
#endif
"""

def serialized(fixtures):
    rows=[]
    for f,out in fixtures:
        vals=[f[k] for k in ("mode","state","owner","rax","rbx","rcx","rdx","rdi","rsi")]
        vals.extend(out[k] for k in KEYS)
        rows.append(" {"+",".join("UINT64_C("+str(v)+")" for v in vals)+"},")
    return "\n".join(rows)

def checked(command):
    p=subprocess.run(command,capture_output=True,text=True)
    if p.returncode:
        raise RuntimeError("CRT release differential failed exit "+
                           str(p.returncode)+": "+(p.stderr or p.stdout)[-3400:])

def run(executable,out):
    pe=PE(executable)
    if hashlib.sha256(pe.b).hexdigest()!=HASH:
        raise RuntimeError("Unrecognized original MX Bikes executable")
    original=pe.read_rva(START,END-START)
    translated,meta=lift_crt_common_release(original,START,BASE)
    if (meta["decoded_original_instructions"]!=11 or
        meta["direct_call_site_rva"]!=hex(CALL) or
        meta["direct_call_target_rva"]!=hex(TARGET) or
        meta["state_global_va"]!=hex(STATE) or
        meta["lock_owner_global_va"]!=hex(OWNER) or
        meta["release_join_rva"]!=hex(END) or meta["direct_call_executed"]):
        raise RuntimeError("Original release CFG or direct CRT callsite changed")
    decoder=Cs(CS_ARCH_X86,CS_MODE_64);decoder.detail=True
    ins=list(decoder.disasm(original,START))
    fixtures=[(f,x64(original,ins,f)) for f in cases()]
    with tempfile.TemporaryDirectory(prefix="private-crt-release-") as td:
        root=Path(td)
        code=root/"original-derived-release.c"
        harness=root/"compare.c"
        code.write_text(translated)
        harness.write_text(C.replace("ENTRY_VA",str(BASE+START))
                         .replace("STATE_VA",str(STATE))
                         .replace("OWNER_VA",str(OWNER))
                         .replace("SP_VA",str(SP))
                         .replace("__CASES__",serialized(fixtures)))
        inc=ROOT/"arm64-lab"/"runtime"
        host=root/"host"
        checked(["cc","-std=c11","-O2","-Wall","-Wextra","-Werror",
                 "-DHOST","-I"+str(inc),str(code),str(harness),"-o",str(host)])
        checked([str(host)])
        arm=root/"original-release-arm64.elf"
        checked(["clang","--target=aarch64-unknown-linux-gnu","-fuse-ld=lld",
                 "-nostdlib","-static","-ffreestanding","-fno-stack-protector",
                 "-fno-builtin","-O2","-std=c11","-I"+str(inc),
                 "-Wl,-e,smoke","-Wl,-z,max-page-size=4096",
                 "-Wl,--build-id=none",str(code),str(harness),"-o",str(arm)])
        result=execute_arm64_elf(arm,instruction_budget=650000,timeout_us=9000000)
    out.mkdir(parents=True,exist_ok=True)
    report={
        "source_original_sha_pinned":True,
        "static_original_instructions":11,
        "x64_arm64_cases":len(fixtures),
        "grouped_paths":{"direct_call_stop":7,"recursive_owner_lock_retained":7,
                          "nonrecursive_owner_lock_released":7},
        "direct_callee_identified_not_executed":True,
        "exclusive_single_thread_xchg_only":True,
        "native_arm64_exit":result["arm64_smoke_exit"],
        "full_game_booted":False
    }
    (out/"next-crt-common-release-arm64.json").write_text(json.dumps(report,indent=2)+"\n")
    summary="\n".join([
        "# MX Bikes original CRT common-state / lock-release ARM64 differential","",
        "- Original 11-instruction region: **analyzed and translated**",
        "- Original x64 / native host / ARM64: **21/21 comparisons matched**",
        "- Seven each: direct-call boundary, recursive lock retention, XCHG unlock",
        "- Original direct CRT call was NOT executed",
        "- RAX/RBX/RCX/RDX/RDI/RSI, guest flags, globals and control flow compared",
        "- ARM64 ELF exit: **"+str(result["arm64_smoke_exit"])+"**","",
        "**Single-thread guest memory only; no full CRT or iOS startup.**",""])
    (out/"next-crt-common-release-arm64.md").write_text(summary)
    print(summary)

if __name__=="__main__":
    if len(sys.argv)!=3:raise SystemExit("usage: script.py original.exe reports")
    run(Path(sys.argv[1]),Path(sys.argv[2]))
