#!/usr/bin/env python3
"""Bounded original 19-instruction argument-init callback x64/C/ARM64 differential.

The SHA-verified, licensed original x64 callback is executed in private
Unicorn. Its two local function calls and one MSVCR90 __getmainargs import
receive controlled x64 oracle responses. Valid native ARM64
__getmainargs paths use the shared stateful guest-process adapter, while the
failure path remains an explicit injected status. This still requires a real
Windows CRT compatibility proof; real _getmainargs, wrapper execution, remaining initializer
callbacks and native engine startup are not established.

No proprietary executable bytes, recovered source, generated C or AArch64
objects are written outside the transient PRIVATE runner.
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
    UC_X86_REG_RAX,UC_X86_REG_RBX,UC_X86_REG_RCX,UC_X86_REG_RDX,
    UC_X86_REG_R8,UC_X86_REG_R9,UC_X86_REG_R11,UC_X86_REG_RDI,
    UC_X86_REG_RSI,UC_X86_REG_RSP,UC_X86_REG_RIP,UC_X86_REG_EFLAGS,
)
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/"arm64-lab"))
from tools.pe_probe import PE
from tools.pe_call_clusters import unwind_functions
from tools.crt_import_cluster_lift import lift_crt_import_cluster
from tools.import_aot_smoke import execute_arm64_elf
from mxbikes_first_callee_emu import import_slots
from mxbikes_crt_exception_callback_differential import BASE,SHA,STACK,SP,STOP

ENTRY=0x2aafc4
WRAPPER=0x2ab7e4
LOCAL_HELPER=0x2ab72c
DATA_RVA=0x3d8000
DATA_SIZE=8192
STUB=0x600000000
MASK=(1<<64)-1
REGS=[
    ("rax",UC_X86_REG_RAX),("rbx",UC_X86_REG_RBX),
    ("rcx",UC_X86_REG_RCX),("rdx",UC_X86_REG_RDX),
    ("r8",UC_X86_REG_R8),("r9",UC_X86_REG_R9),
    ("r11",UC_X86_REG_R11),("rdi",UC_X86_REG_RDI),
    ("rsi",UC_X86_REG_RSI),("rsp",UC_X86_REG_RSP),
    ("rip",UC_X86_REG_RIP),
]

def fnv(data):
    h=0xcbf29ce484222325
    for b in data:
        h=((h^b)*0x100000001b3)&MASK
    return h

def seed_image(case):
    raw=bytearray((i*9+case*13+3)&255 for i in range(DATA_SIZE))
    # Original argument initializer reads CRT input globals at RVA 0x3d85b0
    # and 0x3d85b4 (wildcard expansion and startupinfo.newmode). In the
    # controlled, already-initialized startup fixture, both must be zero.
    raw[0x5b0:0x5b8]=b"\x00"*8
    return bytes(raw)

def calls_and_input(pe):
    if hashlib.sha256(pe.b).hexdigest()!=SHA:
        raise RuntimeError("Original executable SHA mismatch")
    spans=unwind_functions(pe)
    end=spans.get(ENTRY)
    if end is None or not 40<=end-ENTRY<=256:
        raise RuntimeError("Original argument initializer unwind span changed")
    from capstone import Cs,CS_ARCH_X86,CS_MODE_64
    from capstone.x86 import X86_OP_IMM
    md=Cs(CS_ARCH_X86,CS_MODE_64)
    md.detail=True
    code=pe.read_rva(ENTRY,end-ENTRY)
    ins=list(md.disasm(code,ENTRY))
    if (len(ins)!=19 or sum(i.size for i in ins)!=len(code) or
        ins[-1].mnemonic!="ret"):
        raise RuntimeError("Expected bounded complete original 19-instruction callback")
    direct={i.operands[0].imm for i in ins
            if i.mnemonic=="call" and len(i.operands)==1 and
            i.operands[0].type==X86_OP_IMM}
    if direct!={WRAPPER,LOCAL_HELPER}:
        raise RuntimeError("Original direct-callee identity changed")
    imported={rva:(dll,name) for rva,dll,name in import_slots(pe)}
    expected=[rva for rva,(dll,name) in imported.items()
              if dll.lower()=="msvcr90.dll" and name=="__getmainargs"]
    if len(expected)!=1:
        raise RuntimeError("Expected one original __getmainargs IAT slot")
    generated,meta=lift_crt_import_cluster(
        code,ENTRY,imported,{},BASE,
        local_targets=direct,function_name="native_argument_callback"
    )
    if (meta["decoded_instructions"]!=19 or
        meta["import_calls"]!=1 or meta["local_call_sites"]!=2 or
        meta["unique_import_services"]!=["__getmainargs"]):
        raise RuntimeError("Original x64 callback no longer has expected call graph")
    return generated,meta,expected[0],code

def service_mutation(uc,argc,argv,envp):
    for ptr,width,value in ((argc,4,3),
                            (argv,8,BASE+DATA_RVA+0x1000),
                            (envp,8,BASE+DATA_RVA+0x1100)):
        if not BASE+DATA_RVA<=ptr<=BASE+DATA_RVA+DATA_SIZE-width:
            raise RuntimeError("Original guest __getmainargs pointer outside bounded globals")
        uc.mem_write(ptr,int(value).to_bytes(width,"little"))

def x64_case(code,slot,index):
    uc=Uc(UC_ARCH_X86,UC_MODE_64)
    uc.mem_map(BASE,0x800000)
    uc.mem_map(STACK,0x10000)
    uc.mem_map(STUB,4096)
    uc.mem_write(BASE+ENTRY,code)
    uc.mem_write(BASE+WRAPPER,b"\xc3")
    uc.mem_write(BASE+LOCAL_HELPER,b"\xc3")
    uc.mem_write(BASE+slot,struct.pack("<Q",STUB))
    uc.mem_write(STUB,b"\xc3")
    uc.mem_write(BASE+DATA_RVA,seed_image(index))
    uc.mem_write(SP,struct.pack("<Q",STOP))
    rcx=0x140010000+index*17
    uc.reg_write(UC_X86_REG_RCX,rcx)
    uc.reg_write(UC_X86_REG_RSP,SP)
    uc.reg_write(UC_X86_REG_RIP,BASE+ENTRY)
    trace=[]
    def visit(machine,pc,length,opaque):
        if pc not in (BASE+WRAPPER,BASE+LOCAL_HELPER,STUB):
            return
        guest_rsp=machine.reg_read(UC_X86_REG_RSP)
        if guest_rsp!=SP-0x40:
            raise RuntimeError("Original Win64 imported/direct guest stack changed")
        if pc==BASE+WRAPPER:
            trace.append(1)
            value=(0 if index%2==0 else 0xffffffff)
        elif pc==STUB:
            trace.append(2)
            if index%2==0:
                startup=struct.unpack("<Q",bytes(
                    machine.mem_read(guest_rsp+40,8)))[0]
                if (startup!=BASE+DATA_RVA+0x34 or
                    (machine.reg_read(UC_X86_REG_R9)&0xffffffff)!=0 or
                    struct.unpack("<I",bytes(machine.mem_read(startup,4)))[0]!=0):
                    raise RuntimeError(
                        "Original successful __getmainargs fixture has "
                        "uninitialized Win64 wildcard/newmode input")
                service_mutation(
                    machine,machine.reg_read(UC_X86_REG_RCX),
                    machine.reg_read(UC_X86_REG_RDX),
                    machine.reg_read(UC_X86_REG_R8))
            value=(0 if index%2==0 else MASK)
        else:
            trace.append(3)
            value=0x1200+index
        machine.reg_write(UC_X86_REG_RAX,value)
    uc.hook_add(UC_HOOK_CODE,visit)
    uc.emu_start(BASE+ENTRY,STOP,timeout=3000000,count=120)
    if uc.reg_read(UC_X86_REG_RIP)!=STOP or uc.reg_read(UC_X86_REG_RSP)!=SP+8:
        raise RuntimeError("Original 19-instruction callback did not return")
    expected_trace=([1,2] if index%2==0 else [1,2,3])
    if trace!=expected_trace:
        raise RuntimeError("Original bounded callback dependency profile: "+
                           "fixture="+str(index)+
                           " observed_event_types="+repr(trace)+
                           " expected="+repr(expected_trace))
    bits=uc.reg_read(UC_X86_REG_EFLAGS)
    values=[uc.reg_read(reg) for _,reg in REGS]+[
        int(bool(bits&64)),int(bool(bits&128)),int(bool(bits&1))]
    return {
        "index":index,"initial_rcx":rcx,
        "expected":values,
        "stack_hash":fnv(bytes(uc.mem_read(SP-128,256))),
        "globals_hash":fnv(bytes(uc.mem_read(BASE+DATA_RVA,DATA_SIZE))),
        "trace":trace,
    }

HARNESS=r"""
#include <stdint.h>
#include "mx_crt_cluster_guest.h"
#include "mx_crt_native_import_bridge.h"
#define SP UINT64_C(__SP__)
#define STACK_BEGIN UINT64_C(__STACK_BEGIN__)
#define ENTRY UINT64_C(__ENTRY__)
#define EXIT_PC UINT64_C(__EXIT__)
#define DATA_BEGIN UINT64_C(__DATA_BEGIN__)
#define DATA_END UINT64_C(__DATA_END__)
#define WRAPPER UINT64_C(__WRAPPER__)
#define LOCAL_HELPER UINT64_C(__HELPER__)
typedef struct {
 uint64_t initial_rcx,expected[14];
 uint64_t stack_hash,globals_hash;
 uint32_t trace_count;
 uint8_t trace[3];
} fixture;
static const fixture cases[]={__CASES__};
static uint8_t stack_mem[256],data_mem[8192];
typedef struct {uint32_t index,events;uint8_t trace[3];} ctx;
static uint64_t hash_bytes(const uint8_t*p,uint32_t n){
 uint64_t h=UINT64_C(0xcbf29ce484222325);
 for(uint32_t i=0;i<n;i++)h=(h^(uint64_t)p[i])*UINT64_C(0x100000001b3);
 return h;
}
static int emit_trace(ctx*c,uint8_t kind) {
 if(c->events>=3U)return 0;
 c->trace[c->events++]=kind;
 return 1;
}
static int imported(void*opaque,mx_crt_service_id svc,
                    mx_crt_cluster_state *s,mx_cfg_memory *mem,
                    uint64_t callee_rsp) {
 ctx*c=(ctx*)opaque;
 if(!c||svc!=MX_CRT_SERVICE_GETMAINARGS||
    callee_rsp!=SP-0x40U||s->rsp!=SP-0x38U||
    !emit_trace(c,2))return 0;
 if((c->index%2U)==0U){
    mx_crt_process process={0};
    if(mx_crt_process_bind_args(&process,mem,3U,
           DATA_BEGIN+0x1000U,DATA_BEGIN+0x1100U)
           !=MX_CRT_PROCESS_HANDLED)return 0;
    mx_crt_native_import_bridge runtime={mem,&process,0,0U,0};
    if(!mx_crt_native_import_callback(&runtime,svc,s,mem,callee_rsp)||
       runtime.calls_handled!=1U||
       runtime.last_service!=MX_CRT_SERVICE_GETMAINARGS)
        return 0;
 }else{
    /* Explicit injected error-case for the original x64 differential. */
    s->rax=UINT64_MAX;
 }
 return 1;
}
static int local(void*opaque,uint64_t destination,
                 mx_crt_cluster_state*s,mx_cfg_memory*m){
 ctx*c=(ctx*)opaque;
 if(!c||s->local_depth!=1U||s->rsp!=SP-0x40U)return
    MX_CRT_CLUSTER_IMPORT_UNSUPPORTED;
 if(destination==WRAPPER) {
    if(!emit_trace(c,1))return MX_CRT_CLUSTER_INVALID;
    s->rax=(c->index%2U)==0U?0U:UINT64_C(0xffffffff);
 }else if(destination==LOCAL_HELPER){
    if(!emit_trace(c,3))return MX_CRT_CLUSTER_INVALID;
    s->rax=0x1200U+c->index;
 }else return MX_CRT_CLUSTER_IMPORT_UNSUPPORTED;
 uint64_t ret=mx_crt_cluster_read(s,m,s->rsp,8);
 if(s->fault)return MX_CRT_CLUSTER_MEMORY_FAULT;
 s->rsp+=8U;s->rip=ret;
 return MX_CRT_CLUSTER_RETURNED;
}
int native_argument_callback(mx_crt_cluster_state *s,mx_cfg_memory *m,
                            mx_crt_cluster_import_fn imported,
                            mx_crt_cluster_direct_fn local,void*ctx);
int smoke(void){
 mx_cfg_region ranges[2]={
    {STACK_BEGIN,stack_mem,256},
    {DATA_BEGIN,data_mem,8192},
 };
 mx_cfg_memory mem={ranges,2};
 for(uint32_t k=0;k<sizeof(cases)/sizeof(cases[0]);k++){
    const fixture*f=&cases[k];
    for(uint32_t j=0;j<256;j++)stack_mem[j]=0U;
    for(uint32_t j=0;j<8192;j++)
       data_mem[j]=(uint8_t)((j*9U+k*13U+3U)&255U);
    for(uint32_t j=0x5b0U;j<0x5b8U;j++)data_mem[j]=0U;
    uint64_t ret=EXIT_PC;
    if(!mx_cfg_transfer(&mem,SP,&ret,8,1))return 1;
    mx_crt_cluster_state state={0};
    state.rcx=f->initial_rcx;state.rsp=SP;state.rip=ENTRY;
    ctx callbacks={k,0,{0,0,0}};
    if(native_argument_callback(&state,&mem,imported,local,&callbacks)!=
       MX_CRT_CLUSTER_RETURNED||state.imports!=1U||
       state.local_calls!=((k%2U)==0U?1U:2U)||
       state.local_depth!=0U)
       return 10+k;
    uint64_t actual[14]={
        state.rax,state.rbx,state.rcx,state.rdx,state.r8,state.r9,
        state.r11,state.rdi,state.rsi,state.rsp,state.rip,
        state.zf,state.sf,state.cf,
    };
    for(uint32_t j=0;j<14;j++)
       if(actual[j]!=f->expected[j])return 40+k;
    if(callbacks.events!=f->trace_count)return 70+k;
    for(uint32_t j=0;j<f->trace_count;j++)
       if(callbacks.trace[j]!=f->trace[j])return 80+k;
    if(hash_bytes(stack_mem,256)!=f->stack_hash)return 100+k;
    if(hash_bytes(data_mem,8192)!=f->globals_hash)return 120+k;
 }
 return 0;
}
#ifdef HOST
int main(void){return smoke();}
#endif
"""

def fixtures_c(rows):
    lines=[]
    for f in rows:
        vals=",".join("UINT64_C("+str(x)+")" for x in f["expected"])
        events=",".join(str(x) for x in (f["trace"]+[0]*3)[:3])
        lines.append("{UINT64_C("+str(f["initial_rcx"])+"),{"+
                     vals+"},UINT64_C("+str(f["stack_hash"])+
                     "),UINT64_C("+str(f["globals_hash"])+"),"+
                     str(len(f["trace"]))+",{"+events+"}}")
    return ",\n".join(lines)

def execute(exe,report):
    pe=PE(exe)
    generated,meta,slot,code=calls_and_input(pe)
    rows=[x64_case(code,slot,i) for i in range(8)]
    rendered=HARNESS.replace("__SP__",str(SP))
    rendered=rendered.replace("__STACK_BEGIN__",str(SP-128))
    rendered=rendered.replace("__ENTRY__",str(BASE+ENTRY))
    rendered=rendered.replace("__EXIT__",str(STOP))
    rendered=rendered.replace("__DATA_BEGIN__",str(BASE+DATA_RVA))
    rendered=rendered.replace("__DATA_END__",str(BASE+DATA_RVA+DATA_SIZE))
    rendered=rendered.replace("__WRAPPER__",str(BASE+WRAPPER))
    rendered=rendered.replace("__HELPER__",str(BASE+LOCAL_HELPER))
    rendered=rendered.replace("__CASES__",fixtures_c(rows))
    if any(token in rendered for token in (
            "__SP__","__STACK_BEGIN__","__ENTRY__","__EXIT__",
            "__DATA_BEGIN__","__DATA_END__","__WRAPPER__",
            "__HELPER__","__CASES__")):
        raise RuntimeError("Unreplaced native differential placeholders")
    with tempfile.TemporaryDirectory(prefix="private-argument-callback-aot-") as td:
        work=Path(td)
        source=work/"original-body.c"
        harness=work/"original-differential.c"
        source.write_text(generated)
        harness.write_text(rendered)
        flags=["-std=c11","-O2","-Wall","-Wextra","-Werror",
               "-I"+str(ROOT/"arm64-lab"/"runtime")]
        def checked(args):
            result=subprocess.run(args,text=True,capture_output=True)
            if result.returncode:
                raise RuntimeError("Private differential compilation/execution failed; "+
                                   str(result.returncode)+"; "+
                                   (result.stderr or result.stdout)[-2200:])
        host=work/"host"
        checked(["cc",*flags,"-DHOST",str(source),str(harness),"-o",str(host)])
        checked([str(host)])
        elf=work/"arm64.elf"
        checked([
            "clang","--target=aarch64-unknown-linux-gnu",
            "-fuse-ld=lld","-nostdlib","-static","-ffreestanding",
            "-fno-builtin","-fno-stack-protector",
            *flags,"-Wl,-e,smoke","-Wl,-z,max-page-size=4096",
            "-Wl,--build-id=none",str(source),str(harness),"-o",str(elf)
        ])
        arm=execute_arm64_elf(elf,instruction_budget=1100000,
                              timeout_us=10000000)
    report.mkdir(parents=True,exist_ok=True)
    metadata={
        "original_callback_rva":hex(ENTRY),
        "original_x64_source_instructions":meta["decoded_instructions"],
        "original_x64_vs_compiled_C_vs_executed_ARM64_fixtures":len(rows),
        "controlled_local_calls":meta["local_call_sites"],
        "controlled_import_calls":meta["import_calls"],
        "original_local_dependencies_executed":False,
        "real_msvcr90_getmainargs_executed":False,
        "bounded_stateful_getmainargs_bridge_used":True,
        "native_stateful_getmainargs_success_cases":len(rows)//2,
        "controlled_error_import_cases":len(rows)//2,
        "argument_outputs_written_into_bounded_guest_globals":True,
        "full_crt_table_executed":False,
        "native_game_engine_executed":False,
        "arm64_smoke_exit":arm["arm64_smoke_exit"],
    }
    (report/"crt-original-argsetup-body-arm64.json").write_text(
        json.dumps(metadata,indent=2)+"\n")
    summary="\n".join([
        "# Original MX Bikes 19-instruction _initterm argument callback AArch64","",
        "- SHA-pinned authentic original x64 body at "+hex(ENTRY),
        "- Original x64 vs native host C vs actually executed ARM64: **8/8 fixtures matched**",
        "- Verified guest registers/flags, all 256 guest stack bytes,",
        "  bounded original guest globals and imported/local call ordering",
        "- Four valid original x64 call frames invoke the stateful native",
        "  guest __getmainargs adapter and write bounded argv/envp globals",
        "- Four deliberately injected error-return fixtures retain coverage",
        "  of the original CRT fallback branch; no real MSVCR90 DLL is run",
        "- Two original local callsites: controlled responses; second is reached on the injected __getmainargs error path",
        "- Native ARM64 test exit: **"+str(arm["arm64_smoke_exit"])+"**","",
        "**Only the 19-instruction parent body is differentially executed;",
        "the original wrapper/helper, real __getmainargs and entire CRT",
        "initializer table are NOT jointly initialized or executed.**",""
    ])
    (report/"crt-original-argsetup-body-arm64.md").write_text(summary)
    print(summary)

if __name__=="__main__":
    if len(sys.argv)!=3:
        raise SystemExit("usage: script.py private-original-exe report-dir")
    execute(Path(sys.argv[1]),Path(sys.argv[2]))
