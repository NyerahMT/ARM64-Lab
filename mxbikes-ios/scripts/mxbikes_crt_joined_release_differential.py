#!/usr/bin/env python3
"""Verify one continuous 49-instruction original MX Bikes CRT control region.

The privately owned original x64 runs through both imported CALL sites with
deterministic synthetic GetStartupInfoA and Sleep handlers. Translated C/AArch64
uses five strict block lifts, then compares guest register/flag/global/stack
effects and retry paths. This is NOT live Windows or full startup.
"""
import hashlib,json,struct,subprocess,sys,tempfile
from pathlib import Path
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
from unicorn import Uc,UC_ARCH_X86,UC_MODE_64,UC_HOOK_CODE
from unicorn.x86_const import (
    UC_X86_REG_RIP,UC_X86_REG_RSP,UC_X86_REG_RAX,UC_X86_REG_RBX,
    UC_X86_REG_RDI,UC_X86_REG_RSI,UC_X86_REG_RCX,UC_X86_REG_RDX,UC_X86_REG_EFLAGS,
    UC_X86_REG_GS_BASE
)

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/"arm64-lab"))
from tools.pe_probe import PE
from tools.crt_entry_prefix_lift import lift_crt_entry_prefix
from tools.crt_gs_lock_lift import lift_crt_gs_lock_prefix
from tools.crt_retry_lift import lift_crt_retry
from tools.crt_init_state_lift import lift_crt_init_state
from tools.crt_common_release_lift import lift_crt_common_release
from tools.import_aot_smoke import execute_arm64_elf
from mxbikes_first_callee_emu import import_slots

SHA="4ae7de3854b4d0a18271679fb57a1f2fdf0b21804417b85dd82055078ea123b6"
BASE=0x140000000
ENTRY=0x2ab02c
GET_INFO_CALL=0x2ab043
AFTER_INFO=0x2ab049
CAS_RETRY=0x2ab059
LOCK_BRANCH=0x2ab064
DONE=0x2ab07f
FINAL=0x2ab0d3
RELEASE_END=0x2ab108
RELEASE_CALL=0x2ab0ec
CALL_BUSY=0x2ab08d
CALL_INIT=0x2ab0b6
STATE=BASE+0xe4ada0
ALT=BASE+0x3d803c
GLOBAL=BASE+0xe4ada8
GS=0x720000000
STACK=0x700000000
SP=STACK+0xff08
WIN=SP-256
STUB_INFO=0x600000000
STUB_SLEEP=STUB_INFO+0x20
FIELDS=("rax","rbx","rcx","rdi","rsi","rsp","rip","zf","global","sleep_return","suffix_bits","suffix_steps","sleep_calls","rdx","state_after","alt_after","state_bits","state_steps","release_bits","release_steps")

def scenarios():
    for i in range(27):
        mode=i%3
        thread=0x112233440000+i*0x319
        other=0x778800110000+i*101
        yield {
            "mode":mode, "thread":thread,
            "state":(0,1,2)[(i//3)%3], "alt":(i*0x123)&0xffffffff,
            "rdx":0x889977665544+i*31,
            "global_initial":0 if mode==0 else (thread if mode==1 else other),
            "rax":0x123456000000+i*971,
            "rbx":0x554400001100+i*881,
            "rsi":0x667788110000+i*311,
            "rdi":0x889900001100+i*71,
            "rcx":0x111122223333+i*127
        }

def reference(original:bytes,info_slot:int,sleep_slot:int,original_instr,scenario):
    x=Uc(UC_ARCH_X86,UC_MODE_64)
    pages={(BASE+ENTRY)&~0xfff,(BASE+info_slot)&~0xfff,
           (BASE+sleep_slot)&~0xfff,GLOBAL&~0xfff,ALT&~0xfff}
    for pg in pages:x.mem_map(pg,0x1000)
    x.mem_map(GS,0x1000)
    x.mem_map(STUB_INFO,0x1000)
    x.mem_map(STACK,0x20000)
    x.mem_write(BASE+ENTRY,original)
    x.mem_write(BASE+info_slot,struct.pack("<Q",STUB_INFO))
    x.mem_write(BASE+sleep_slot,struct.pack("<Q",STUB_SLEEP))
    x.mem_write(STUB_INFO,b"\xc3")
    x.mem_write(STUB_SLEEP,b"\xc3")
    x.mem_write(GS+0x30,struct.pack("<Q",GS))
    x.mem_write(GS+8,struct.pack("<Q",scenario["thread"]))
    x.mem_write(GLOBAL,struct.pack("<Q",scenario["global_initial"]))
    x.mem_write(STATE,struct.pack("<I",scenario["state"]))
    x.mem_write(ALT,struct.pack("<I",scenario["alt"]))
    x.reg_write(UC_X86_REG_GS_BASE,GS)
    for name,reg in (("rax",UC_X86_REG_RAX),("rbx",UC_X86_REG_RBX),
                     ("rcx",UC_X86_REG_RCX),("rsi",UC_X86_REG_RSI),
                     ("rdi",UC_X86_REG_RDI),("rdx",UC_X86_REG_RDX)):
        x.reg_write(reg,scenario[name])
    x.reg_write(UC_X86_REG_RIP,BASE+ENTRY)
    x.reg_write(UC_X86_REG_RSP,SP)
    x.reg_write(UC_X86_REG_EFLAGS,0x202)
    suffix_code=[ins for ins in original_instr if CAS_RETRY<=ins.address<DONE]
    state_code=[ins for ins in original_instr if DONE<=ins.address<FINAL]
    state_bits={BASE+ins.address:j for j,ins in enumerate(state_code)}
    release_code=[ins for ins in original_instr if FINAL<=ins.address<RELEASE_END]
    release_bits={BASE+ins.address:j for j,ins in enumerate(release_code)}
    suffix={BASE+ins.address:j for j,ins in enumerate(suffix_code)}
    expected={BASE+ins.address for ins in original_instr}
    counts={"info":0,"sleep":0,"suffix_bits":0,"suffix_steps":0,
            "state_bits":0,"state_steps":0,"release_bits":0,"release_steps":0,
            "in_retry_branch":False}
    def hook(emu,pc,size,user):
        if pc==STUB_INFO:
            counts["info"]+=1
            if counts["info"]!=1:return
            if emu.reg_read(UC_X86_REG_RSP)%16!=8:
                raise RuntimeError("Original GetStartupInfoA callee stack alignment mismatch")
            address=emu.reg_read(UC_X86_REG_RCX)
            data=struct.pack("<I",104)+bytes(100)
            if address<WIN or address+104>WIN+512:
                raise RuntimeError("Original startup info memory escaped bounded stack")
            emu.mem_write(address,data)
            return
        if pc==STUB_SLEEP:
            counts["sleep"]+=1
            if scenario["mode"]!=2 or counts["sleep"]!=1:
                raise RuntimeError("Unexpected original Sleep callback path")
            if emu.reg_read(UC_X86_REG_RCX)!=1000:
                raise RuntimeError("Original CRT did not pass Sleep(1000)")
            emu.mem_write(GLOBAL,struct.pack("<Q",0))
            return
        if pc not in expected or pc in (BASE+CALL_BUSY,BASE+CALL_INIT,BASE+RELEASE_CALL):
            raise RuntimeError("Original x64 escaped bounded startup or attempted unverified direct call")
        # Initial XOR/CAS is owned by the preceding GS block. Only
        # instrument instructions starting at the first branch, then any
        # backward retries, just as the native joined harness resets its
        # counters when that block returns.
        if pc==BASE+LOCK_BRANCH:
            counts["in_retry_branch"]=True
        if counts["in_retry_branch"] and pc in suffix:
            counts["suffix_bits"]|=1<<suffix[pc]
            counts["suffix_steps"]+=1
        if pc in state_bits:
            counts["state_bits"]|=1<<state_bits[pc]
            counts["state_steps"]+=1
        if pc in release_bits:
            counts["release_bits"]|=1<<release_bits[pc]
            counts["release_steps"]+=1
    x.hook_add(UC_HOOK_CODE,hook)
    stop=CALL_INIT if scenario["state"]==0 else CALL_BUSY if scenario["state"]==1 else RELEASE_END
    x.emu_start(BASE+ENTRY,BASE+stop,timeout=2_000_000,count=125)
    if counts["info"]!=1 or counts["sleep"]!=(1 if scenario["mode"]==2 else 0):
        raise RuntimeError("Original startup import calls did not match the intended scenario")
    out={}
    for name,reg in (("rax",UC_X86_REG_RAX),("rbx",UC_X86_REG_RBX),
                     ("rcx",UC_X86_REG_RCX),("rdi",UC_X86_REG_RDI),
                     ("rsi",UC_X86_REG_RSI),("rdx",UC_X86_REG_RDX),("rsp",UC_X86_REG_RSP),
                     ("rip",UC_X86_REG_RIP)):
        out[name]=x.reg_read(reg)
    out["zf"]=int(bool(x.reg_read(UC_X86_REG_EFLAGS)&64))
    out["global"]=struct.unpack("<Q",x.mem_read(GLOBAL,8))[0]
    out["state_after"]=struct.unpack("<I",x.mem_read(STATE,4))[0]
    out["alt_after"]=struct.unpack("<I",x.mem_read(ALT,4))[0]
    out["sleep_return"]=struct.unpack("<Q",x.mem_read(SP-0xb0,8))[0]
    out["suffix_bits"]=counts["suffix_bits"]
    out["suffix_steps"]=counts["suffix_steps"]
    out["sleep_calls"]=counts["sleep"]
    out["state_bits"]=counts["state_bits"]
    out["state_steps"]=counts["state_steps"]
    out["release_bits"]=counts["release_bits"]
    out["release_steps"]=counts["release_steps"]
    out["stack"]=bytes(x.mem_read(WIN,512))
    owner_expected=(0 if scenario["state"]==2 and scenario["mode"]!=1
                    else scenario["thread"])
    if (out["rip"]!=BASE+stop or out["rsp"]!=SP-0xa8 or
            out["global"]!=owner_expected):
        raise RuntimeError("Original 49-instruction CRT outcome failed bounded reference checks")
    return out

NATIVE=r"""
#include <stdint.h>
#include "mx_crt_primitives.h"
#define ENTRY UINT64_C(ENTRY_VA)
#define GS UINT64_C(GS_VA)
#define SP UINT64_C(SP_VA)
#define WIN UINT64_C(WIN_VA)
#define GLOBAL UINT64_C(GLOBAL_VA)
#define STATE UINT64_C(STATE_VA)
#define ALT UINT64_C(ALT_VA)
#define AFTER_INFO UINT64_C(AFTER_INFO_VA)
#define BRANCH UINT64_C(BRANCH_VA)
#define RELEASE UINT64_C(RELEASE_VA)
typedef struct {
    uint64_t mode,thread,global_initial,rax,rbx,rcx,rsi,rdi,state,alt,rdx;
    uint64_t e_rax,e_rbx,e_rcx,e_rdi,e_rsi,e_rsp,e_rip,e_zf,e_global;
    uint64_t e_sleep_return,e_suffix_bits,e_suffix_steps,e_sleep_calls;
    uint64_t e_rdx,e_state_after,e_alt_after,e_state_bits,e_state_steps;
    uint64_t e_release_bits,e_release_steps;
    uint8_t expected_stack[512];
} fixture;
static const fixture cases[]={
__CASES__
};
static uint8_t stack_bytes[512],teb[256],shared[8],state_global[4],alternate_flag[4];
typedef struct {mx_cfg_memory *memory;uint32_t slept;int release;} sleep_ctx;
int lifted_crt_entry_prefix(mx_crt_state *,mx_cfg_memory *);
int lifted_crt_gs_lock_prefix(mx_crt_state *,mx_cfg_memory *,uint64_t,int);
int lifted_crt_lock_retry(mx_crt_state *,mx_cfg_memory *,int (*)(void*,uint32_t),void*,int);
int lifted_crt_init_state(mx_crt_state *,mx_cfg_memory *,uint64_t *);
int lifted_crt_common_release(mx_crt_state *,mx_cfg_memory *,uint64_t *,int);
static int fake_sleep(void *p,uint32_t millis) {
    sleep_ctx *ctx=(sleep_ctx*)p;
    if(millis!=1000U)return 0;
    ctx->slept++;
    if(ctx->release) {
        uint64_t zero=0;
        return mx_cfg_transfer(ctx->memory,GLOBAL,&zero,8,1);
    }
    return 1;
}
int smoke(void) {
    mx_cfg_region areas[5]={{WIN,stack_bytes,512},{GS,teb,256},{GLOBAL,shared,8},
                            {STATE,state_global,4},{ALT,alternate_flag,4}};
    mx_cfg_memory memory={areas,5};
    for(unsigned i=0;i<sizeof(cases)/sizeof(cases[0]);i++) {
        const fixture *f=&cases[i];
        volatile uint8_t *a=stack_bytes,*b=teb,*c=shared,*d=state_global,*e=alternate_flag;
        for(unsigned j=0;j<512;j++)a[j]=0;
        for(unsigned j=0;j<256;j++)b[j]=0;
        for(unsigned j=0;j<8;j++)c[j]=0;
        for(unsigned j=0;j<4;j++){d[j]=0;e[j]=0;}
        uint64_t ptr=GS;
        uint64_t initial=f->global_initial;
        uint32_t state=(uint32_t)f->state,alt=(uint32_t)f->alt;
        if(!mx_cfg_transfer(&memory,GS+UINT64_C(0x30),&ptr,8,1) ||
           !mx_cfg_transfer(&memory,GS+8U,(void*)&f->thread,8,1) ||
           !mx_cfg_transfer(&memory,GLOBAL,&initial,8,1) ||
           !mx_cfg_transfer(&memory,STATE,&state,4,1) ||
           !mx_cfg_transfer(&memory,ALT,&alt,4,1))return 10+i;
        mx_crt_state s={0};
        s.rip=ENTRY;s.rsp=SP;s.rax=f->rax;s.rbx=f->rbx;
        s.rcx=f->rcx;s.rdi=f->rdi;s.rsi=f->rsi;
        uint64_t rdx=f->rdx;
        if(lifted_crt_entry_prefix(&s,&memory)!=MX_CRT_IMPORT_BOUNDARY)return 30+i;
        /* The original CALL pushes a return address before GetStartupInfoA. */
        uint64_t ret=AFTER_INFO;
        if(!mx_cfg_transfer(&memory,s.rsp-8U,&ret,8,1))return 50+i;
        for(unsigned j=0;j<13;j++) {
            uint64_t word=(j==0?104U:0U);
            if(!mx_cfg_transfer(&memory,s.rcx+8U*j,&word,8,1))return 70+i;
        }
        s.rip=AFTER_INFO;
        s.visited=0;s.instructions=0;
        if(lifted_crt_gs_lock_prefix(&s,&memory,GS,1)!=MX_CRT_BRANCH_BOUNDARY)
            return 90+i;
        if(s.rip!=BRANCH || s.instructions!=6U)return 110+i;
        s.visited=0;s.instructions=0;
        sleep_ctx host={&memory,0,f->mode==2};
        if(lifted_crt_lock_retry(&s,&memory,fake_sleep,&host,1)!=MX_CRT_BRANCH_BOUNDARY)
            return 130+i;
        if(s.fault || s.pending_import || s.imports!=host.slept)return 150+i;
        if(s.visited!=f->e_suffix_bits || s.instructions!=f->e_suffix_steps ||
           s.imports!=f->e_sleep_calls)return 210+i;
        if(s.rip!=UINT64_C(STATE_BEGIN_VA))return 160+i;
        /* State frontier is reached continuously, but resets only the
         * instruction-trace counters, not guest memory/registers/flags. */
        s.visited=0;s.instructions=0;
        int state_result=lifted_crt_init_state(&s,&memory,&rdx);
        int expected_result=(f->state==0U || f->state==1U)?5:MX_CRT_BRANCH_BOUNDARY;
        if(state_result!=expected_result)return 165+i;
        if(s.visited!=f->e_state_bits || s.instructions!=f->e_state_steps)
            return 220+i;
        if(f->state==2U){
            /* Only the already-initialized state reaches the release CFG.
             * Original direct CRT calls remain explicit stop boundaries. */
            if(s.rip!=RELEASE)return 161+i;
            s.visited=0;s.instructions=0;
            int released=lifted_crt_common_release(&s,&memory,&rdx,1);
            if(released!=MX_CRT_BRANCH_BOUNDARY)return 162+i;
        }
        if(f->state==2U){
            if(s.visited!=f->e_release_bits || s.instructions!=f->e_release_steps)
                return 163+i;
        }else if(f->e_release_bits || f->e_release_steps){
            return 164+i;
        }
        if(s.rax!=f->e_rax || s.rbx!=f->e_rbx || s.rcx!=f->e_rcx ||
           rdx!=f->e_rdx || s.rdi!=f->e_rdi || s.rsi!=f->e_rsi)return 170+i;
        if(s.rsp!=f->e_rsp || s.rip!=f->e_rip || s.zf!=f->e_zf)
            return 190+i;
        uint64_t global=0,last_return=0;
        if(!mx_cfg_transfer(&memory,GLOBAL,&global,8,0) ||
           !mx_cfg_transfer(&memory,SP-UINT64_C(0xb0),&last_return,8,0))
            return 230+i;
        if(global!=f->e_global || last_return!=f->e_sleep_return)return 250+i;
        uint32_t init_state=0,other_state=0;
        if(!mx_cfg_transfer(&memory,STATE,&init_state,4,0) ||
           !mx_cfg_transfer(&memory,ALT,&other_state,4,0) ||
           init_state!=f->e_state_after || other_state!=f->e_alt_after)return 255+i;
        for(unsigned j=0;j<512;j++)
            if(stack_bytes[j]!=f->expected_stack[j])return 270+i;
    }
    return 0;
}
#ifdef HOST
int main(void){return smoke();}
#endif
"""

def encode(pairs):
    rows=[]
    for f,out in pairs:
        values=[f[k] for k in ("mode","thread","global_initial","rax","rbx","rcx","rsi","rdi","state","alt","rdx")]
        values+=[out[k] for k in FIELDS]
        bytespart="{"+",".join(str(x) for x in out["stack"])+"}"
        rows.append(" {"+",".join("UINT64_C("+str(v)+")" for v in values)+","+bytespart+"},")
    return "\n".join(rows)

def checked(argv):
    result=subprocess.run(argv,capture_output=True,text=True)
    if result.returncode:
        raise RuntimeError("Original joined CRT host/AArch64 failed exit "+
                           str(result.returncode)+": "+(result.stderr or result.stdout)[-3200:])

def run(executable,output):
    pe=PE(executable)
    if hashlib.sha256(pe.b).hexdigest()!=SHA:
        raise RuntimeError("Private MX Bikes exe SHA mismatch")
    iat={rva:(dll.lower(),name) for rva,dll,name in import_slots(pe)}
    entry,info=lift_crt_entry_prefix(pe.read_rva(ENTRY,AFTER_INFO-ENTRY),ENTRY,iat,BASE)
    gs,gsmeta=lift_crt_gs_lock_prefix(pe.read_rva(AFTER_INFO,LOCK_BRANCH+2-AFTER_INFO),AFTER_INFO,BASE)
    state_c,state_meta=lift_crt_init_state(pe.read_rva(DONE,FINAL-DONE),DONE,BASE)
    release_c,release_meta=lift_crt_common_release(pe.read_rva(FINAL,RELEASE_END-FINAL),FINAL,BASE)
    retry,retrymeta=lift_crt_retry(pe.read_rva(CAS_RETRY,LOCK_BRANCH-CAS_RETRY),
                               pe.read_rva(LOCK_BRANCH,DONE-LOCK_BRANCH),
                               CAS_RETRY,LOCK_BRANCH,iat,BASE)
    if (info["stop_before_import_rva"]!=hex(GET_INFO_CALL) or
        gsmeta["stop_before_branch_rva"]!=hex(LOCK_BRANCH) or
        retrymeta["stop_before_rva"]!=hex(DONE) or
        state_meta["join_rva"]!=hex(FINAL) or state_meta["decoded_original_instructions"]!=18 or
        release_meta["release_join_rva"]!=hex(RELEASE_END) or
        release_meta["decoded_original_instructions"]!=11 or
        release_meta["lock_owner_global_va"]!=hex(GLOBAL) or
        release_meta["state_global_va"]!=hex(STATE) or
        release_meta["direct_call_site_rva"]!=hex(RELEASE_CALL)):
        raise RuntimeError("Original source spans cannot be joined")
    get_call_slot=int(info["verified_import_symbol"]=="kernel32.dll::GetStartupInfoA")
    if get_call_slot!=1:
        raise RuntimeError("Unvalidated original GetStartupInfoA call")
    original=pe.read_rva(ENTRY,RELEASE_END-ENTRY)
    md=Cs(CS_ARCH_X86,CS_MODE_64);md.detail=True
    static=list(md.disasm(original,ENTRY))
    if len(static)!=49 or sum(x.size for x in static)!=len(original):
        raise RuntimeError("Unexpected original 49-instruction source interval")
    info_ins=next(x for x in static if x.address==GET_INFO_CALL)
    sleep_ins=next(x for x in static if x.mnemonic=="call" and x.address>AFTER_INFO)
    info_slot=info_ins.address+info_ins.size+info_ins.operands[0].mem.disp
    sleep_slot=sleep_ins.address+sleep_ins.size+sleep_ins.operands[0].mem.disp
    if (iat.get(info_slot)!=("kernel32.dll","GetStartupInfoA") or
        iat.get(sleep_slot)!=("kernel32.dll","Sleep")):
        raise RuntimeError("Wrong original Win64 imports")
    pairs=[(f,reference(original,info_slot,sleep_slot,static,f)) for f in scenarios()]
    if len(pairs)!=27 or len({f["state"] for f,_ in pairs})!=3:
        raise RuntimeError("Missing joined state cases")
    if (sum(1 for f,_ in pairs if f["state"]==2 and f["mode"]==1)!=3 or
        sum(1 for f,_ in pairs if f["state"]==2 and f["mode"]!=1)!=6):
        raise RuntimeError("Missing recursive and exclusive-release joint paths")
    with tempfile.TemporaryDirectory(prefix="mxbikes-private-crt-joined-retry-") as td:
        root=Path(td)
        sources=[root/"private-entry.c",root/"private-gs.c",root/"private-retry.c",
                 root/"private-init-state.c",root/"private-release.c"]
        for file,code in zip(sources,(entry,gs,retry,state_c,release_c)):
            file.write_text(code)
        smoke=root/"private-smoke.c"
        smoke.write_text(NATIVE.replace("ENTRY_VA",str(BASE+ENTRY))
                .replace("GS_VA",str(GS)).replace("SP_VA",str(SP))
                .replace("WIN_VA",str(WIN)).replace("GLOBAL_VA",str(GLOBAL))
                .replace("AFTER_INFO_VA",str(BASE+AFTER_INFO))
                .replace("BRANCH_VA",str(BASE+LOCK_BRANCH))
                .replace("RELEASE_VA",str(BASE+FINAL))
                .replace("STATE_VA",str(STATE))
                .replace("STATE_BEGIN_VA",str(BASE+DONE)).replace("ALT_VA",str(ALT))
                .replace("__CASES__",encode(pairs)))
        inc=ROOT/"arm64-lab"/"runtime"
        exe=root/"host"
        checked(["cc","-std=c11","-O2","-Wall","-Wextra","-Werror",
                "-DHOST","-I"+str(inc),*map(str,sources),str(smoke),"-o",str(exe)])
        checked([str(exe)])
        a64=root/"translated-original-crt-arm64.elf"
        checked(["clang","--target=aarch64-unknown-linux-gnu","-fuse-ld=lld",
                 "-nostdlib","-static","-ffreestanding","-fno-builtin",
                 "-fno-stack-protector","-O2","-std=c11","-I"+str(inc),
                 "-Wl,-e,smoke","-Wl,-z,max-page-size=4096",
                 "-Wl,--build-id=none",*map(str,sources),str(smoke),"-o",str(a64)])
        arm=execute_arm64_elf(a64,instruction_budget=650000,timeout_us=9000000)
    output.mkdir(parents=True,exist_ok=True)
    report={
        "continuous_original_instructions_available":49,
        "static_original_crt_instructions":126,
        "matched_original_x64_and_arm64_fixtures":27,
        "test_groups":{"lock_acquisition":9,"recursive_ownership":9,"sleep_retry":9,
                       "state_zero_direct_call":9,"state_one_direct_call":9,
                       "state_two_release_or_retain":9,
                       "release_success":6,"recursive_owner_retains_lock":3},
        "native_arm64_smoke_exit":arm["arm64_smoke_exit"],
        "bounded_arm64_instruction_budget":650000,
        "two_win64_import_calls_modeled_with_injected_callbacks":True,
        "real_windows_imports_implemented":False,
        "native_multithreading_correct":False,
        "full_crt_or_game_boot":False,
        "last_original_address_exclusive":hex(RELEASE_END),
        "direct_crt_callees_executed":False
    }
    (output/"next-crt-joined-release-arm64.json").write_text(json.dumps(report,indent=2)+"\n")
    summary="\n".join([
        "# MX Bikes original CRT — 49-instruction continuous native ARM64 comparison","",
        "- **27/27** original x64 / native host / AArch64 comparisons matched",
        "- Three lock paths: **9 acquired, 9 recursive, 9 Sleep+retry**",
        "- Joined original **49-instruction** region through two synthetic Win64 CALL responses",
        "- Compared RAX/RBX/RCX/RDX/RDI/RSI, ZF, 512-byte stack, lock/CRT globals, and state/release path bitmaps",
        "- ARM64 smoke exit: **"+str(arm["arm64_smoke_exit"])+"**","",
        "**Nine initialized-state fixtures exercised lock retention (3) or release (6); two other state groups stop before direct CRT calls. No real Win64, full CRT, game, or iOS startup.**",""])
    (output/"next-crt-joined-release-arm64.md").write_text(summary)
    print(summary)

if __name__=="__main__":
    if len(sys.argv)!=3:raise SystemExit("usage: python script.py /private/exe REPORT_DIR")
    run(Path(sys.argv[1]),Path(sys.argv[2]))
