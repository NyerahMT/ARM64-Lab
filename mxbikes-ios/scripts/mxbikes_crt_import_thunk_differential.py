#!/usr/bin/env python3
"""Original MX Bikes CRT CALL -> imported JMP thunk -> injected RET differential.

The two *returning* MSVCR90 imported thunks are run as real original x64
instructions in private Unicorn, and compared with the bounded C bridge
compiled on host and AArch64 Unicorn. Callback results are SYNTHETIC: this
does not implement _initterm/_initterm_e callback-array execution or Win32.
Neither original game code nor derived C/ELF leaves private ephemeral CI.
"""
from pathlib import Path
import hashlib,json,struct,subprocess,sys,tempfile

from capstone import Cs,CS_ARCH_X86,CS_MODE_64
from capstone.x86 import X86_OP_IMM,X86_OP_MEM
from unicorn import Uc,UC_ARCH_X86,UC_MODE_64,UC_HOOK_CODE
from unicorn.x86_const import (UC_X86_REG_RIP,UC_X86_REG_RSP,
    UC_X86_REG_RAX,UC_X86_REG_RBX,UC_X86_REG_RCX,UC_X86_REG_RDX,
    UC_X86_REG_RDI,UC_X86_REG_RSI,UC_X86_REG_EFLAGS)

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/"arm64-lab"))
from tools.pe_probe import PE
from tools.import_aot_smoke import execute_arm64_elf
from mxbikes_first_callee_emu import import_slots

SHA="4ae7de3854b4d0a18271679fb57a1f2fdf0b21804417b85dd82055078ea123b6"
BASE=0x140000000
STACK=0x700000000
SP=STACK+0xfe60
WINDOW=SP-128
STUB=0x600000000
CALLS=(
    (0x2ab0b6,0x2ab948,"msvcr90.dll","_initterm_e",1),
    (0x2ab0ec,0x2ab942,"msvcr90.dll","_initterm",2),
)
REGISTERS=(("rax",UC_X86_REG_RAX),("rbx",UC_X86_REG_RBX),
           ("rcx",UC_X86_REG_RCX),("rdx",UC_X86_REG_RDX),
           ("rdi",UC_X86_REG_RDI),("rsi",UC_X86_REG_RSI),
           ("rsp",UC_X86_REG_RSP),("rip",UC_X86_REG_RIP))
KEYS=("rax","rbx","rcx","rdx","rdi","rsi","rsp","rip","zf")

def decode_calls(pe):
    md=Cs(CS_ARCH_X86,CS_MODE_64);md.detail=True
    mapped={rva:(dll.lower(),name) for rva,dll,name in import_slots(pe)}
    found=[]
    for site,target,dll,fn,kind in CALLS:
        call=list(md.disasm(pe.read_rva(site,5),site))
        thunk=list(md.disasm(pe.read_rva(target,6),target))
        if (len(call)!=1 or call[0].size!=5 or call[0].mnemonic!="call"
            or len(call[0].operands)!=1 or call[0].operands[0].type!=X86_OP_IMM
            or call[0].operands[0].imm!=target or
            len(thunk)!=1 or thunk[0].size!=6 or thunk[0].mnemonic!="jmp"
            or len(thunk[0].operands)!=1 or thunk[0].operands[0].type!=X86_OP_MEM
            or thunk[0].reg_name(thunk[0].operands[0].mem.base)!="rip"
            or thunk[0].operands[0].mem.index):
            raise RuntimeError("Original x64 CALL/JMP thunk no longer has pinned shape")
        slot=target+6+thunk[0].operands[0].mem.disp
        if mapped.get(slot)!=(dll,fn):
            raise RuntimeError("CRT imported thunk does not resolve to required symbol")
        found.append({"call_rva":site,"thunk_rva":target,"iat_rva":slot,
                      "dll":dll,"symbol":fn,"kind":kind,
                      "original_call":pe.read_rva(site,5),
                      "original_thunk":pe.read_rva(target,6)})
    return found

def cases():
    for call_index in range(2):
        for n in range(16):
            status=(0,1,2,255,0x7fffffff,0x80000000,0xffffffff,42)[n%8]
            yield {"call_index":call_index,"status":status,
                   "rax":0x12340000abcf+n*9877+call_index*991,
                   "rbx":0x223344556677+n*139,
                   "rcx":0x140321000+n*64,
                   "rdx":0x140322000+n*56,
                   "rdi":0x998877665500+n*19,
                   "rsi":0x554433221100+n*31,
                   "zf":n%2}

def reference_original(spec,f):
    cpu=Uc(UC_ARCH_X86,UC_MODE_64)
    site=BASE+spec["call_rva"]
    thunk=BASE+spec["thunk_rva"]
    slot=BASE+spec["iat_rva"]
    for page in {site&~0xfff,thunk&~0xfff,slot&~0xfff}:
        cpu.mem_map(page,0x1000)
    cpu.mem_map(STACK,0x20000)
    cpu.mem_map(STUB,0x1000)
    cpu.mem_write(site,spec["original_call"])
    cpu.mem_write(thunk,spec["original_thunk"])
    cpu.mem_write(slot,struct.pack("<Q",STUB))
    cpu.mem_write(STUB,b"\xc3")
    cpu.reg_write(UC_X86_REG_RSP,SP)
    cpu.reg_write(UC_X86_REG_RIP,site)
    cpu.reg_write(UC_X86_REG_EFLAGS,0x202 | (f["zf"]<<6))
    for name,reg in REGISTERS:
        if name not in ("rsp","rip"):
            cpu.reg_write(reg,f[name])
    seen=[]
    callee={"count":0,"first":None,"second":None}
    def on_code(emu,pc,size,_):
        if pc==STUB:
            callee["count"]+=1
            if (emu.reg_read(UC_X86_REG_RSP)!=SP-8 or
                emu.reg_read(UC_X86_REG_RSP)%16!=8):
                raise RuntimeError("Original guest Win64 callee stack shape changed")
            callee["first"]=emu.reg_read(UC_X86_REG_RCX)
            callee["second"]=emu.reg_read(UC_X86_REG_RDX)
            if spec["kind"]==1:
                # Deterministic synthetic _initterm_e return in EAX.
                emu.reg_write(UC_X86_REG_RAX,f["status"])
        elif pc not in (site,thunk):
            raise RuntimeError("Original x64 CRT import thunk escaped approved paths")
        seen.append(pc)
    cpu.hook_add(UC_HOOK_CODE,on_code)
    cpu.emu_start(site,site+5,timeout=2_000_000,count=8)
    if seen!=[site,thunk,STUB] or callee["count"]!=1:
        raise RuntimeError("Expected original CALL -> IAT JMP -> stub RET sequence")
    expected={}
    for name,reg in REGISTERS:
        expected[name]=cpu.reg_read(reg)
    expected["zf"]=int(bool(cpu.reg_read(UC_X86_REG_EFLAGS)&64))
    expected["stack"]=bytes(cpu.mem_read(WINDOW,256))
    expected["callback_first"]=callee["first"]
    expected["callback_second"]=callee["second"]
    if (expected["rip"]!=site+5 or expected["rsp"]!=SP or
        expected["zf"]!=f["zf"] or
        expected["rax"]!=(f["status"] if spec["kind"]==1 else f["rax"])):
        raise RuntimeError("Original synthetic CRT thunk reference mismatch")
    return expected

SMOKE=r"""
#include <stdint.h>
#include "mx_crt_init_imports.h"
#define WINDOW UINT64_C(WINDOW_ADDR)
#define SP UINT64_C(SP_ADDR)
typedef struct {
    uint64_t kind,site,ret,status,rax,rbx,rcx,rdx,rdi,rsi,zf;
    uint64_t e_rax,e_rbx,e_rcx,e_rdx,e_rdi,e_rsi,e_rsp,e_rip,e_zf;
    uint64_t e_cb_first,e_cb_second;
    uint8_t e_stack[256];
} fixture;
static const fixture input[]={
__CASES__
};
static uint8_t guest_stack[256];
typedef struct {
    uint32_t calls,expected_kind,status;
    uint64_t first,second;
} callback;
static int synthetic(void*ptr,uint32_t kind,uint64_t first,uint64_t second,
                     uint32_t*result){
    callback*c=(callback*)ptr;
    c->calls++;
    c->first=first;c->second=second;
    if(kind!=c->expected_kind)return 0;
    *result=c->status;
    return 1;
}
int smoke(void){
    mx_cfg_region region={WINDOW,guest_stack,256};
    mx_cfg_memory m={&region,1};
    for(unsigned i=0;i<sizeof(input)/sizeof(input[0]);i++){
        const fixture*f=&input[i];
        volatile uint8_t*stack=guest_stack;
        for(unsigned j=0;j<256;j++)stack[j]=0;
        mx_crt_state s={0};
        s.rip=f->site;s.rsp=SP;s.rax=f->rax;s.rcx=f->rcx;
        s.rdi=f->rdi;s.rsi=f->rsi;s.zf=(uint8_t)f->zf;
        uint64_t rbx=f->rbx;
        uint64_t rdx=f->rdx;
        callback cb={0,(uint32_t)f->kind,(uint32_t)f->status,0,0};
        int result=mx_crt_invoke_init_thunk(&s,&m,(uint32_t)f->kind,
                           f->site,f->ret,rdx,synthetic,&cb);
        if(result!=MX_CRT_BRANCH_BOUNDARY||s.fault||s.pending_import||
           s.imports!=1U||s.import_trace!=f->kind||cb.calls!=1U)
            return 10+i;
        if(s.rax!=f->e_rax||rbx!=f->e_rbx||s.rcx!=f->e_rcx||
           rdx!=f->e_rdx||s.rdi!=f->e_rdi||s.rsi!=f->e_rsi)
            return 50+i;
        if(s.rsp!=f->e_rsp||s.rip!=f->e_rip||s.zf!=f->e_zf)
            return 90+i;
        if(cb.first!=f->e_cb_first||cb.second!=f->e_cb_second)
            return 130+i;
        for(unsigned j=0;j<256;j++){
            if(guest_stack[j]!=f->e_stack[j])return 170+i;
        }
    }
    return 0;
}
#ifdef HOST
int main(void){return smoke();}
#endif
"""

def data(pairs):
    chunks=[]
    for f,e,spec in pairs:
        initial=[spec["kind"],BASE+spec["call_rva"],BASE+spec["call_rva"]+5,
                 f["status"]]+[f[k] for k in ("rax","rbx","rcx","rdx","rdi","rsi","zf")]
        expected=[e[k] for k in KEYS]+[e["callback_first"],e["callback_second"]]
        stack="{"+",".join(str(b) for b in e["stack"])+"}"
        chunks.append(" {"+",".join("UINT64_C("+str(n)+")" for n in initial+expected)+","+stack+"},")
    return "\n".join(chunks)

def checked(command):
    proc=subprocess.run(command,capture_output=True,text=True)
    if proc.returncode:
        raise RuntimeError("Original import-thunk differential failed (exit "+
                           str(proc.returncode)+"): "+
                           (proc.stderr or proc.stdout)[-3200:])

def run(exe,reports):
    pe=PE(exe)
    if hashlib.sha256(pe.b).hexdigest()!=SHA:
        raise RuntimeError("Original MX Bikes executable SHA mismatch")
    specs=decode_calls(pe)
    pairs=[]
    for f in cases():
        spec=specs[f["call_index"]]
        pairs.append((f,reference_original(spec,f),spec))
    if len(pairs)!=32 or {spec["symbol"] for _,_,spec in pairs}!={"_initterm_e","_initterm"}:
        raise RuntimeError("Missing original MSVCR90 imported thunk matrices")
    with tempfile.TemporaryDirectory(prefix="private-original-crt-import-thunks-") as td:
        root=Path(td)
        harness=root/"private-import-thunk-check.c"
        harness.write_text(SMOKE.replace("WINDOW_ADDR",str(WINDOW))
                           .replace("SP_ADDR",str(SP))
                           .replace("__CASES__",data(pairs)))
        inc=ROOT/"arm64-lab"/"runtime"
        host=root/"host"
        checked(["cc","-std=c11","-O2","-Wall","-Wextra","-Werror",
                 "-DHOST","-I"+str(inc),str(harness),"-o",str(host)])
        checked([str(host)])
        arm=root/"private-msvcr90-thunks-arm64.elf"
        checked(["clang","--target=aarch64-unknown-linux-gnu","-fuse-ld=lld",
                 "-nostdlib","-static","-ffreestanding","-fno-builtin",
                 "-fno-stack-protector","-O2","-std=c11","-I"+str(inc),
                 "-Wl,-e,smoke","-Wl,-z,max-page-size=4096",
                 "-Wl,--build-id=none",str(harness),"-o",str(arm)])
        result=execute_arm64_elf(arm,instruction_budget=650000,timeout_us=9000000)
    reports.mkdir(parents=True,exist_ok=True)
    metadata={
        "pinned_original_executable":True,
        "original_calls_covered":2,
        "original_static_import_thunk_shapes":"CALL rel32 -> JMP [RIP+IAT] -> RET",
        "original_x64_vs_host_C_vs_AArch64_fixtures":len(pairs),
        "initterm_e_results_covered":[0,1,2,255,0x7fffffff,0x80000000,0xffffffff,42],
        "initterm_void_rax_preserved":True,
        "first_and_second_guest_arguments_matched":True,
        "stack_window_bytes_matched":256,
        "arm64_elf_exit":result["arm64_smoke_exit"],
        "amsg_exit_not_claimed_returning":True,
        "synthetic_msvcr90_callbacks_not_actual_initialization":True,
        "joined_continuous_CRT_path":False,
        "game_or_ios_booted":False
    }
    (reports/"crt-msvcr90-import-thunk-arm64.json").write_text(json.dumps(metadata,indent=2)+"\n")
    summary="\n".join([
        "# Original MX Bikes MSVCR90 imported-call thunk differential","",
        "- Original _initterm_e and _initterm CALL -> JMP IAT -> synthetic RET: **32/32 x64 / host C / ARM64 matched**",
        "- 16 cases per import; eight return-status varieties for _initterm_e; void _initterm preserved RAX",
        "- Guest CALL return-slot and 256-byte stack, RAX/RBX/RCX/RDX/RDI/RSI, RSP/RIP, ZF: matched",
        "- Guest Win64 ABI arguments and injected callback counts checked",
        "- ARM64 ELF return code: **"+str(result["arm64_smoke_exit"])+"**","",
        "**Callbacks are deterministic fixtures, NOT real MSVCR90 initializer traversal. This is an isolated imported-call differential, not a joined CRT or an iOS game boot.**",""])
    (reports/"crt-msvcr90-import-thunk-arm64.md").write_text(summary)
    print(summary)

if __name__=="__main__":
    if len(sys.argv)!=3:raise SystemExit("usage: script.py /private/owned-game.exe metadata-dir")
    run(Path(sys.argv[1]),Path(sys.argv[2]))
