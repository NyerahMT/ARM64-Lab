#!/usr/bin/env python3
"""Original MX Bikes filename helper -> MSVCR90!strrchr Win64 import oracle.

Uses actual SHA-pinned original x64 CALL instruction and original PE import
JMP thunk in Unicorn. The proprietary CRT body is NOT executed; an explicitly
bounded deterministic byte-scanning host mock supplies the MSVCR90 result.
Compare observable original CALL/RET ABI to host C and EXECUTED native ARM64
guest implementation. Never export original bytes, generated PE snippets, or
the transient linked ARM64 object.
"""
from pathlib import Path
import hashlib
import json
import struct
import subprocess
import sys
import tempfile

from capstone import Cs, CS_ARCH_X86, CS_MODE_64
from capstone.x86 import X86_OP_IMM, X86_OP_MEM
from unicorn import UC_HOOK_CODE
from unicorn.x86_const import (
    UC_X86_REG_RAX, UC_X86_REG_RCX, UC_X86_REG_RDX,
    UC_X86_REG_RIP, UC_X86_REG_RSP, UC_X86_REG_EFLAGS
)
from mxbikes_first_callee_emu import import_slots
from mxbikes_main_joined_callee_native import new_cpu, BASE, STACK
from mxbikes_whole_game_map import walk_unwind

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/"arm64-lab"))
from tools.pe_probe import PE
from tools.import_aot_smoke import execute_arm64_elf

SHA="4ae7de3854b4d0a18271679fb57a1f2fdf0b21804417b85dd82055078ea123b6"
HELPER=0x15b790
THUNK=0x2aaeaa
STUB=0x730001000
SRC=STACK+0x12000
SP=STACK+0x13000
CASES=[
    (b"C:\\MXBikes\\mxbikes.exe",ord("\\")),
    (b"C:\\MXBikes\\mxbikes.exe",ord("e")),
    (b"abc.txt",ord(".")),
    (b"abc.txt",ord("Z")),
    (b"",0),
    (b"A",0x10041),
    (b"x"*230+b".exe",ord("x"))
]


def identify_original(pe):
    if hashlib.sha256(pe.b).hexdigest()!=SHA:
        raise RuntimeError("Wrong original MX Bikes image")
    decoder=Cs(CS_ARCH_X86,CS_MODE_64)
    decoder.detail=True
    instr=list(decoder.disasm(pe.read_rva(THUNK,6),THUNK))
    if (len(instr)!=1 or instr[0].mnemonic!="jmp" or
        len(instr[0].operands)!=1 or
        instr[0].operands[0].type!=X86_OP_MEM or
        instr[0].reg_name(instr[0].operands[0].mem.base)!="rip" or
        instr[0].operands[0].mem.index):
        raise RuntimeError("Original strrchr imported JMP thunk changed")
    iat=THUNK+instr[0].size+instr[0].operands[0].mem.disp
    named={(slot,dll.lower(),symbol.lower())
           for slot,dll,symbol in import_slots(pe)}
    if (iat,"msvcr90.dll","strrchr") not in named:
        raise RuntimeError("strrchr PE thunk no longer resolves original MSVCR90 slot")
    records,_,_,_=walk_unwind(pe)
    end=records.get(HELPER)
    if not end or end<=HELPER or end-HELPER>4096:
        raise RuntimeError("Original filename helper unwind extent changed")
    raw=pe.read_rva(HELPER,end-HELPER)
    body=list(decoder.disasm(raw,HELPER))
    if not body or sum(x.size for x in body)!=len(raw):
        raise RuntimeError("Original filename helper failed bounded linear decode")
    calls=[ins for ins in body if ins.mnemonic=="call" and
           len(ins.operands)==1 and
           ins.operands[0].type==X86_OP_IMM and
           int(ins.operands[0].imm)==THUNK]
    if len(calls)!=1 or calls[0].size!=5:
        raise RuntimeError("Cannot uniquely locate original strrchr CALL site")
    return calls[0].address,iat


def oracle(pe,call,iat,case_index):
    payload,search=CASES[case_index]
    if b"\x00" in payload or len(payload)+1>256:
        raise RuntimeError("Fixture must be bounded and NUL terminated")
    uc=new_cpu(pe)
    uc.mem_map(STUB,4096)
    uc.mem_write(STUB,b"\xc3")
    uc.mem_write(BASE+iat,struct.pack("<Q",STUB))
    uc.mem_write(SRC,payload+b"\x00")
    flags=0x202|[0,1,0x40,0x80,0xc1,0x41,0x200][case_index]
    registers={
        UC_X86_REG_RIP:BASE+call,
        UC_X86_REG_RSP:SP,
        UC_X86_REG_RAX:0x12340000+case_index,
        UC_X86_REG_RCX:SRC,
        UC_X86_REG_RDX:search,
        UC_X86_REG_EFLAGS:flags
    }
    for name,value in registers.items():uc.reg_write(name,value)
    observed=[]
    def modeled_import(cpu,pc,size,opaque):
        if pc!=STUB:return
        if cpu.reg_read(UC_X86_REG_RCX)!=SRC or (
            cpu.reg_read(UC_X86_REG_RDX)!=search):
            raise RuntimeError("Original Win64 strrchr arguments differ")
        needle=search&255
        data=payload+b"\x00"
        indices=[index for index,value in enumerate(data) if value==needle]
        answer=SRC+indices[-1] if indices else 0
        cpu.reg_write(UC_X86_REG_RAX,answer)
        observed.append(answer)
    uc.hook_add(UC_HOOK_CODE,modeled_import)
    uc.emu_start(BASE+call,BASE+call+5,timeout=2000000,count=5)
    if uc.reg_read(UC_X86_REG_RIP)!=BASE+call+5 or len(observed)!=1:
        raise RuntimeError("Original x64 CALL/thunk/modeled CRT/RET failed")
    ret_word=struct.unpack("<Q",bytes(uc.mem_read(SP-8,8)))[0]
    if ret_word!=BASE+call+5 or uc.reg_read(UC_X86_REG_RSP)!=SP:
        raise RuntimeError("Original strrchr Win64 caller return slot changed")
    f=uc.reg_read(UC_X86_REG_EFLAGS)
    return {
        "payload":payload, "search":search,
        "rax":uc.reg_read(UC_X86_REG_RAX),
        "rip":uc.reg_read(UC_X86_REG_RIP),
        "rsp":uc.reg_read(UC_X86_REG_RSP),
        "cf":int(bool(f&1)), "zf":int(bool(f&64)), "sf":int(bool(f&128)),
        "call":call, "ret":ret_word
    }


SOURCE=r'''
#include <stdint.h>
#include "mx_game_crt_strrchr.h"
#define SRC UINT64_C(__SRC__)
#define SP UINT64_C(__SP__)
#define CALLEE UINT64_C(__THUNK__)
#define CALL UINT64_C(__CALL__)
#define RETURN (CALL+5U)
#define COUNT __COUNT__U
static uint8_t bytes[256],stack[256];
typedef struct {
    uint32_t length;
    uint32_t search;
    uint8_t payload[256];
    uint64_t expected_rax;
    uint8_t cf,zf,sf;
} fixture;
static const fixture cases[COUNT]={
__ROWS__
};
int smoke(void){
  for(uint32_t c=0;c<COUNT;c++){
    for(uint32_t i=0;i<256U;i++)bytes[i]=0U;
    const fixture*f=&cases[c];
    for(uint32_t i=0;i<f->length;i++)bytes[i]=f->payload[i];
    mx_cfg_region regions[]={
      {SRC,bytes,sizeof(bytes)},
      {SP-128U,stack,sizeof(stack)}
    };
    mx_cfg_memory guest={regions,2};
    mx_crt_cluster_state state={0};
    state.rip=CALL;state.rsp=SP;state.rcx=SRC;state.rdx=f->search;
    state.rax=UINT64_C(0x12340000)+c;
    state.cf=f->cf;state.zf=f->zf;state.sf=f->sf;
    if(mx_game_crt_strrchr_import_call(&state,&guest,
           CALL,CALLEE,RETURN,256U)!=MX_GAME_STRRCHR_OK)
       return 10+(int)c;
    uint64_t slot=0;
    if(!mx_cfg_transfer(&guest,SP-8U,&slot,8U,0))
        return 20+(int)c;
    if(state.rax!=f->expected_rax||state.rip!=RETURN||
       state.rsp!=SP||state.rcx!=SRC||state.rdx!=f->search||
       state.cf!=f->cf||state.zf!=f->zf||state.sf!=f->sf||
       state.imports!=1U||state.instructions!=3U||slot!=RETURN)
       return 30+(int)c;
  }
  return 0;
}
#ifdef HOST
int main(void){return smoke();}
#endif
'''


def run(executable,out):
    pe=PE(executable)
    call,iat=identify_original(pe)
    references=[oracle(pe,call,iat,index) for index in range(len(CASES))]
    rows=[]
    for item in references:
        payload=list(item["payload"])
        rows.append("{"+str(len(payload))+","+str(item["search"])+
                    ",{"+",".join(map(str,payload))+
                    "},UINT64_C("+str(item["rax"])+"),"+
                    ",".join(str(item[x]) for x in ("cf","zf","sf"))+"}")
    code=(SOURCE.replace("__SRC__",str(SRC))
                .replace("__SP__",str(SP))
                .replace("__THUNK__",str(BASE+THUNK))
                .replace("__CALL__",str(BASE+call))
                .replace("__COUNT__",str(len(CASES)))
                .replace("__ROWS__",",\n".join(rows)))
    with tempfile.TemporaryDirectory(prefix="mxb-crt-strrchr-") as td:
        root=Path(td)
        c=root/"bounded-original-import.c"
        c.write_text(code)
        options=["-std=c11","-O2","-Wall","-Wextra","-Werror",
                 "-I",str(ROOT/"arm64-lab"/"runtime")]
        host=root/"host"
        result=subprocess.run(["cc",*options,"-DHOST",str(c),"-o",str(host)],
                              capture_output=True,text=True)
        if result.returncode:
            raise RuntimeError("Native strrchr host compile: "+result.stderr[-2600:])
        result=subprocess.run([str(host)],capture_output=True,text=True)
        if result.returncode:
            raise RuntimeError("Original x64/host strrchr mismatch: "+str(result.returncode))
        arm=root/"strrchr-aarch64.elf"
        result=subprocess.run([
            "clang","--target=aarch64-unknown-linux-gnu","-fuse-ld=lld",
            "-nostdlib","-static","-ffreestanding","-fno-builtin",
            "-fno-stack-protector",*options,"-Wl,-e,smoke",
            "-Wl,-z,max-page-size=4096","-Wl,--build-id=none",
            str(c),"-o",str(arm)
        ],capture_output=True,text=True)
        if result.returncode:
            raise RuntimeError("AArch64 CRT strrchr compile: "+result.stderr[-2600:])
        result=execute_arm64_elf(arm,instruction_budget=350000,
                                 timeout_us=5000000)
        if result["arm64_smoke_exit"]!=0:
            raise RuntimeError("Original x64 vs ARM64 strrchr guest mismatch: "+
                               str(result["arm64_smoke_exit"]))
    out.mkdir(parents=True,exist_ok=True)
    report={
        "sha_verified_original_executable":True,
        "original_filename_helper_call_rva":hex(call),
        "original_strrchr_thunk_rva":hex(THUNK),
        "original_import_IAT_rva":hex(iat),
        "original_import_symbol":"MSVCR90.dll!strrchr",
        "original_x64_call_thunk_and_host_model_cases":len(references),
        "matched_native_aarch64_cases":len(references),
        "bounded_guest_string_search_verified":True,
        "real_microsoft_crt_body_executed":False,
        "connected_original_crt_startup_calls_strrchr":False,
        "notes":"Differential verifies exact original CALL/IAT JMP/RET and modeled import bytes. Does not claim filename helper reaches this call in full startup or production locale support."
    }
    (out/"crt-original-strrchr-guest-native.json").write_text(
        json.dumps(report,indent=2)+"\n")
    summary="\n".join([
       "# Original MX Bikes filename helper MSVCR90 strrchr native boundary",
       "",
       "- Authenticated original CALL/thunk/CRT symbol: **YES**",
       "- Original x64 Win64 CALL/JMP/modeled return versus host and ARM64: **"+
         str(len(references))+"/"+str(len(references))+" cases passed**",
       "- Exact return slot, RAX, RCX/RDX, flags and guest memory: **MATCH**",
       "- Fatal/unsupported results never manufactured: **YES**",
       "",
       "**Only modeled MSVCR90 strrchr behavior and its original imported boundary; real CRT DLL is not executed and the continuous filename parser has not reached this call.**",""
    ])
    (out/"crt-original-strrchr-guest-native.md").write_text(summary)
    print(summary)
    return report


if __name__=="__main__":
    if len(sys.argv)!=3:
        raise SystemExit("usage: script.py PRIVATE_ORIGINAL_EXE METADATA_OUTPUT")
    run(Path(sys.argv[1]),Path(sys.argv[2]))
