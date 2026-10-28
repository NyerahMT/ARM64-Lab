#!/usr/bin/env python3
"""Original x64 vs generated AArch64 CRT initialization-state frontier.

Three original paths and two unexecuted direct CALL boundaries are verified
under deterministic isolated guest memory. Never exports game-derived bytes,
generated original C, ELF or original binary into public repositories.
"""
from pathlib import Path
import hashlib,json,struct,subprocess,sys,tempfile

from capstone import Cs,CS_ARCH_X86,CS_MODE_64
from unicorn import Uc,UC_ARCH_X86,UC_MODE_64,UC_HOOK_CODE
from unicorn.x86_const import (
    UC_X86_REG_RAX,UC_X86_REG_RBX,UC_X86_REG_RCX,UC_X86_REG_RDX,
    UC_X86_REG_RDI,UC_X86_REG_RSI,UC_X86_REG_RSP,UC_X86_REG_RIP,
    UC_X86_REG_EFLAGS
)

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/"arm64-lab"))
from tools.pe_probe import PE
from tools.crt_init_state_lift import lift_crt_init_state
from tools.import_aot_smoke import execute_arm64_elf

SHA="4ae7de3854b4d0a18271679fb57a1f2fdf0b21804417b85dd82055078ea123b6"
IMAGE=0x140000000
START=0x2ab07f
END=0x2ab0d3
CALL_ALREADY=0x2ab08d
CALL_INIT=0x2ab0b6
STATE=IMAGE+0xe4ada0
ALT=IMAGE+0x3d803c
DIRECTS=(0x2ab72c,0x2ab948)
STACK=0x700000000
SP=STACK+0xff08
KEYS=("rax","rbx","rcx","rdx","rdi","rsi","rsp","rip","zf",
      "state_after","alt_after","visited","instructions")

def cases():
    states=(0,1,2,0xffffffff,0x80000000,3,5,0x10000,0x7fffffff)
    for i in range(27):
        yield {
            "state":states[i%len(states)],
            "alt":(i*0x123)&0xffffffff,
            "rax":0x111122223333+i*17,
            "rbx":0x121212340000+i*29,
            "rcx":0x456701234000+i*47,
            "rdx":0x999988880000+i*31,
            "rdi":0x234567000000+i*71,
            "rsi":0x876543210000+i*119,
        }

def x64_reference(code,decoded,f):
    uc=Uc(UC_ARCH_X86,UC_MODE_64)
    for page in {(IMAGE+START)&~4095,STATE&~4095,ALT&~4095}:
        uc.mem_map(page,4096)
    uc.mem_map(STACK,0x10000)
    uc.mem_write(IMAGE+START,code)
    uc.mem_write(STATE,struct.pack("<I",f["state"]))
    uc.mem_write(ALT,struct.pack("<I",f["alt"]))
    uc.reg_write(UC_X86_REG_RIP,IMAGE+START)
    uc.reg_write(UC_X86_REG_RSP,SP)
    uc.reg_write(UC_X86_REG_EFLAGS,0x202)
    registers=(("rax",UC_X86_REG_RAX),("rbx",UC_X86_REG_RBX),
               ("rcx",UC_X86_REG_RCX),("rdx",UC_X86_REG_RDX),
               ("rdi",UC_X86_REG_RDI),("rsi",UC_X86_REG_RSI))
    for name,reg in registers:
        uc.reg_write(reg,f[name])
    target=CALL_INIT if f["state"]==0 else CALL_ALREADY if f["state"]==1 else END
    indexed={IMAGE+ins.address:j for j,ins in enumerate(decoded)}
    track={"visited":0,"instructions":0}
    def on_code(emu,pc,length,data):
        if pc not in indexed:
            raise RuntimeError("Original CRT left bounded initialization-state block")
        if pc in (IMAGE+CALL_ALREADY,IMAGE+CALL_INIT):
            raise RuntimeError("Unvalidated original CRT direct CALL executed")
        track["visited"]|=1<<indexed[pc]
        track["instructions"]+=1
    uc.hook_add(UC_HOOK_CODE,on_code)
    uc.emu_start(IMAGE+START,IMAGE+target,timeout=2_000_000,count=30)
    output={}
    for name,reg in registers+(("rsp",UC_X86_REG_RSP),("rip",UC_X86_REG_RIP)):
        output[name]=uc.reg_read(reg)
    output["zf"]=int(bool(uc.reg_read(UC_X86_REG_EFLAGS)&64))
    output["state_after"]=struct.unpack("<I",uc.mem_read(STATE,4))[0]
    output["alt_after"]=struct.unpack("<I",uc.mem_read(ALT,4))[0]
    output.update(track)
    if output["rip"]!=IMAGE+target or output["rsp"]!=SP:
        raise RuntimeError("Original guest did not stop before specified boundary")
    if f["state"]==0:
        if output["state_after"]!=1 or output["alt_after"]!=f["alt"]:
            raise RuntimeError("Original CRT uninitialized transition diverged")
    elif f["state"]==1:
        if output["state_after"]!=1 or output["alt_after"]!=f["alt"]:
            raise RuntimeError("Original CRT active-initialization state diverged")
    elif output["state_after"]!=f["state"] or output["alt_after"]!=1:
        raise RuntimeError("Original CRT alternate-state flag diverged")
    return output

HARNESS=r"""
#include <stdint.h>
#include "mx_crt_vm.h"
#define STATE_GLOBAL UINT64_C(STATE_VA)
#define ALT_GLOBAL UINT64_C(ALT_VA)
#define START UINT64_C(START_VA)
#define STOP1 UINT64_C(STOP_FIRST_VA)
#define STOP0 UINT64_C(STOP_SECOND_VA)
#define JOIN UINT64_C(JOIN_VA)
#define SP UINT64_C(SP_VA)
typedef struct {
    uint64_t state,alt,rax,rbx,rcx,rdx,rdi,rsi;
    uint64_t e_rax,e_rbx,e_rcx,e_rdx,e_rdi,e_rsi,e_rsp,e_rip,e_zf;
    uint64_t e_state_after,e_alt_after,e_visited,e_instructions;
} fixture;
static const fixture fixtures[]={
__CASES__
};
static uint8_t current_state[4],alternate_state[4];
int lifted_crt_init_state(mx_crt_state*,mx_cfg_memory*,uint64_t*);
int smoke(void) {
    mx_cfg_region regions[2]={{STATE_GLOBAL,current_state,4},
                               {ALT_GLOBAL,alternate_state,4}};
    mx_cfg_memory mem={regions,2};
    for(unsigned i=0;i<sizeof(fixtures)/sizeof(fixtures[0]);i++) {
        const fixture *f=&fixtures[i];
        uint32_t value=(uint32_t)f->state;
        uint32_t alt=(uint32_t)f->alt;
        if(!mx_cfg_transfer(&mem,STATE_GLOBAL,&value,4,1) ||
           !mx_cfg_transfer(&mem,ALT_GLOBAL,&alt,4,1))return 10+i;
        mx_crt_state s={0};
        s.rip=START;s.rsp=SP;
        s.rax=f->rax;s.rbx=f->rbx;s.rcx=f->rcx;
        s.rdi=f->rdi;s.rsi=f->rsi;
        uint64_t rdx=f->rdx;
        int status=lifted_crt_init_state(&s,&mem,&rdx);
        int expected_status=(f->state==0U || f->state==1U) ? 5 : MX_CRT_BRANCH_BOUNDARY;
        if(status!=expected_status || s.fault || s.pending_import || s.imports)
            return 50+i;
        if(s.rax!=f->e_rax || s.rbx!=f->e_rbx || s.rcx!=f->e_rcx ||
           rdx!=f->e_rdx || s.rdi!=f->e_rdi || s.rsi!=f->e_rsi)
            return 90+i;
        if(s.rsp!=f->e_rsp || s.rip!=f->e_rip || s.zf!=f->e_zf)
            return 130+i;
        if(s.visited!=f->e_visited || s.instructions!=f->e_instructions)
            return 170+i;
        uint32_t after_state=0,after_alt=0;
        if(!mx_cfg_transfer(&mem,STATE_GLOBAL,&after_state,4,0) ||
           !mx_cfg_transfer(&mem,ALT_GLOBAL,&after_alt,4,0))
            return 210+i;
        if(after_state!=f->e_state_after || after_alt!=f->e_alt_after)
            return 250+i;
    }
    return 0;
}
#ifdef HOST
int main(void){return smoke();}
#endif
"""

def c_fixture(pairs):
    lines=[]
    for f,e in pairs:
        values=[f[k] for k in ("state","alt","rax","rbx","rcx","rdx","rdi","rsi")]
        values.extend(e[k] for k in KEYS)
        lines.append(" {"+",".join("UINT64_C("+str(x)+")" for x in values)+"},")
    return "\n".join(lines)

def checked(argv):
    output=subprocess.run(argv,text=True,capture_output=True)
    if output.returncode:
        raise RuntimeError("Private state frontier build/run exit "+
                           str(output.returncode)+": "+(output.stderr or output.stdout)[-3000:])

def run(executable,reports):
    pe=PE(executable)
    if hashlib.sha256(pe.b).hexdigest()!=SHA:
        raise RuntimeError("Original owned executable does not match pinned SHA")
    code=pe.read_rva(START,END-START)
    lifted,meta=lift_crt_init_state(code,START,IMAGE)
    if (meta["decoded_original_instructions"]!=18 or
        meta["direct_call_sites_rva"]!=[hex(CALL_ALREADY),hex(CALL_INIT)] or
        meta["direct_call_targets_rva"]!=[hex(n) for n in DIRECTS] or
        meta["state_global_va"]!=hex(STATE) or meta["alternate_flag_va"]!=hex(ALT) or
        meta["direct_calls_executed"] or meta["join_rva"]!=hex(END)):
        raise RuntimeError("Original CRT state/control/callee identity changed")
    md=Cs(CS_ARCH_X86,CS_MODE_64);md.detail=True
    original=list(md.disasm(code,START))
    pairs=[(f,x64_reference(code,original,f)) for f in cases()]
    if (len(pairs)!=27 or
        {x["state"] for x,_ in pairs}!={0,1,2,0xffffffff,0x80000000,3,5,0x10000,0x7fffffff}):
        raise RuntimeError("Incomplete original CRT global state coverage")
    with tempfile.TemporaryDirectory(prefix="private-crt-init-state-") as temp:
        root=Path(temp)
        cfile=root/"translated-original-state.c"
        smoke=root/"state-differential-harness.c"
        cfile.write_text(lifted)
        smoke.write_text(HARNESS.replace("STATE_VA",str(STATE))
                         .replace("ALT_VA",str(ALT))
                         .replace("START_VA",str(IMAGE+START))
                         .replace("STOP_FIRST_VA",str(IMAGE+CALL_ALREADY))
                         .replace("STOP_SECOND_VA",str(IMAGE+CALL_INIT))
                         .replace("JOIN_VA",str(IMAGE+END))
                         .replace("SP_VA",str(SP))
                         .replace("__CASES__",c_fixture(pairs)))
        include=ROOT/"arm64-lab"/"runtime"
        host=root/"host"
        checked(["cc","-std=c11","-O2","-Wall","-Wextra","-Werror",
                 "-DHOST","-I"+str(include),str(cfile),str(smoke),"-o",str(host)])
        checked([str(host)])
        arm=root/"original-crt-state-aarch64.elf"
        checked(["clang","--target=aarch64-unknown-linux-gnu","-fuse-ld=lld",
                 "-nostdlib","-static","-ffreestanding","-fno-builtin",
                 "-fno-stack-protector","-O2","-std=c11","-I"+str(include),
                 "-Wl,-e,smoke","-Wl,-z,max-page-size=4096",
                 "-Wl,--build-id=none",str(cfile),str(smoke),"-o",str(arm)])
        result=execute_arm64_elf(arm,instruction_budget=650000,timeout_us=9000000)
    reports.mkdir(parents=True,exist_ok=True)
    metadata={
        "original_second_crt_rva":hex(START),
        "original_state_frontier_instructions_static":18,
        "arm64_compared_original_state_cases":len(pairs),
        "cases_by_state_group":{
            "already_initializing_state_one":3,
            "uninitialized_state_zero":3,
            "other_nonzero_states":21,
        },
        "direct_crt_calls_identified":list(meta["direct_call_targets_rva"]),
        "direct_crt_calls_executed":False,
        "guest_register_flags_state_globals_matched":True,
        "arm64_smoke_exit":result["arm64_smoke_exit"],
        "last_join_rva":hex(END),
        "full_126_instruction_crt_executed":False,
        "game_or_iphone_booted":False,
        "limitations":"Three state-frontier paths with no direct CRT callee execution. This is isolated differential coverage, not a joined extension to the earlier 20-instruction region."
    }
    (reports/"next-crt-init-state-arm64.json").write_text(json.dumps(metadata,indent=2)+"\n")
    summary="\n".join([
        "# MX Bikes next CRT — original initialization-state differential","",
        "- Original 18-instruction control region decoded and validated: **yes**",
        "- Three initialization-state path groups: **27/27 original x64 / native / ARM64 matched**",
        "- Existing state, zero-to-initializing state, alternate global-state path: **verified**",
        "- Original direct CRT callees: **identified but not invoked**",
        "- Compared bounded global writes, RAX/RBX/RCX/RDX/RDI/RSI, RSP/RIP, ZF and executed bitmap",
        "- ARM64 ELF smoke exit: **"+str(result["arm64_smoke_exit"])+"**","",
        "**This is an isolated state-machine region, not a joined 126-instruction CRT or game startup.**",""])
    (reports/"next-crt-init-state-arm64.md").write_text(summary)
    print(summary)

if __name__=="__main__":
    if len(sys.argv)!=3:
        raise SystemExit("usage: script.py /private/original.exe /private/report-dir")
    run(Path(sys.argv[1]),Path(sys.argv[2]))
