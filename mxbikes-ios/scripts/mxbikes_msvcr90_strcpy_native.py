#!/usr/bin/env python3
"""Validate the original MX Bikes helper's MSVCR90 strcpy import thunk.

Authentic game instructions: RVA 0x15b7a5 CALL RVA 0x2ab41a, original
0x2ab41a JMP through the genuine MSVCR90!strcpy IAT entry, and original
Win64 RET frame. The original DLL is NOT executed: a controlled host mock
models strcpy bytes, and identical native ARM64 service is compared against
x64 original call/thunk+the explicitly modeled API return.
"""
from pathlib import Path
import hashlib,json,struct,subprocess,sys,tempfile
from capstone import Cs,CS_ARCH_X86,CS_MODE_64,CS_GRP_CALL,CS_GRP_JUMP
from capstone.x86 import X86_OP_IMM,X86_OP_MEM
from unicorn import Uc,UC_HOOK_CODE
from unicorn.x86_const import (
 UC_X86_REG_RIP,UC_X86_REG_RSP,UC_X86_REG_RAX,UC_X86_REG_RCX,
 UC_X86_REG_RDX,UC_X86_REG_R8,UC_X86_REG_R9,UC_X86_REG_EFLAGS
)
from mxbikes_filename_helper_native import verify_helper,BASE
from mxbikes_main_joined_callee_native import new_cpu,STACK
from mxbikes_first_callee_emu import import_slots
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/"arm64-lab"))
from tools.pe_probe import PE
from tools.import_aot_smoke import execute_arm64_elf

SHA="4ae7de3854b4d0a18271679fb57a1f2fdf0b21804417b85dd82055078ea123b6"
CALL=0x15b7a5
THUNK=0x2ab41a
RETURN=CALL+5
HOST=0x730001000
MAX=260
SP=STACK+0x10000-0x108-0x288-8-0x38
SRC=STACK+0x12000
CASES=[
 b"C:\\MXBikes\\mxbikes.exe",
 b"C:\\Games\\MX Bikes\\mxbikes.exe",
 b"C:\\mxbikes.exe",
 b"",
 b"C:\\Games\\"+b"x"*230+b".exe"
]
if any(len(s)+1>MAX for s in CASES):
    raise RuntimeError("Test string exceeds validated game buffer bound")

def original_thunk(pe):
    _,stop,dest=verify_helper(pe)
    md=Cs(CS_ARCH_X86,CS_MODE_64);md.detail=True
    inst=list(md.disasm(pe.read_rva(THUNK,6),THUNK))
    if(len(inst)!=1 or not inst[0].group(CS_GRP_JUMP) or
       inst[0].operands[0].type!=X86_OP_MEM or
       inst[0].reg_name(inst[0].operands[0].mem.base)!="rip" or
       inst[0].operands[0].mem.index):
        raise RuntimeError("Original strcpy PE thunk identity changed")
    iat=THUNK+inst[0].size+inst[0].operands[0].mem.disp
    symbols={(int(rv),str(dll).lower(),str(name).lower())
             for rv,dll,name in import_slots(pe)}
    if(iat,"msvcr90.dll","strcpy") not in symbols:
        raise RuntimeError("Original thunk not bound to MSVCR90!strcpy")
    if(stop.address!=CALL or stop.operands[0].imm!=THUNK):
        raise RuntimeError("Original game source CALL changed")
    return iat,dest

def original_reference(pe,iat,dest,case_index):
    source=CASES[case_index]
    uc=new_cpu(pe)
    uc.mem_map(HOST,4096)
    uc.mem_write(HOST,b"\xc3") # controlled mock: instruction RET only
    uc.mem_write(BASE+iat,struct.pack("<Q",HOST))
    uc.mem_write(SRC,source+b"\x00")
    uc.mem_write(dest,bytes([0x5a])*MAX)
    initial_flags=0x202|[0,1,0x40,0x80,0xc1][case_index]
    regs={
       UC_X86_REG_RIP:BASE+CALL,UC_X86_REG_RSP:SP,
       UC_X86_REG_RAX:0x123456789,
       UC_X86_REG_RCX:dest,UC_X86_REG_RDX:SRC,
       UC_X86_REG_R8:0x19,UC_X86_REG_R9:0x321,
       UC_X86_REG_EFLAGS:initial_flags
    }
    for r,v in regs.items():uc.reg_write(r,v)
    called=[]
    def import_service(m,pc,size,ctx):
        if pc!=HOST:return
        called.append(pc)
        dst=m.reg_read(UC_X86_REG_RCX)
        src=m.reg_read(UC_X86_REG_RDX)
        if dst!=dest or src!=SRC:
            raise RuntimeError("Unexpected original strcpy call arguments")
        data=bytearray()
        for i in range(MAX):
            byte=bytes(m.mem_read(src+i,1))
            data+=byte
            if byte==b"\x00":break
        else:raise RuntimeError("Guest strcpy source unterminated")
        m.mem_write(dst,bytes(data))
        m.reg_write(UC_X86_REG_RAX,dst)
    uc.hook_add(UC_HOOK_CODE,import_service)
    uc.emu_start(BASE+CALL,BASE+RETURN,timeout=2000000,count=12)
    if len(called)!=1 or uc.reg_read(UC_X86_REG_RIP)!=BASE+RETURN:
        raise RuntimeError("Original Win64 CALL/JMP/RET did not reach expected main helper continuation")
    after={
      "rax":uc.reg_read(UC_X86_REG_RAX),
      "rsp":uc.reg_read(UC_X86_REG_RSP),
      "rip":uc.reg_read(UC_X86_REG_RIP),
      "rcx":uc.reg_read(UC_X86_REG_RCX),
      "rdx":uc.reg_read(UC_X86_REG_RDX),
      "eflags":uc.reg_read(UC_X86_REG_EFLAGS),
      "guest_return_at_callee_stack":struct.unpack("<Q",bytes(uc.mem_read(SP-8,8)))[0],
      "destination_bytes":list(bytes(uc.mem_read(dest,MAX)))
    }
    if (after["rsp"]!=SP or after["rax"]!=dest or
       after["guest_return_at_callee_stack"]!=BASE+RETURN):
        raise RuntimeError("Original x64 modeled CRT import guest ABI state mismatch")
    return after

C=r'''#include <stdint.h>
#include "mx_game_crt_strcpy.h"
#define BASE UINT64_C(0x140000000)
#define STACK UINT64_C(0x710000000)
#define SP UINT64_C(__SP__)
#define SRC UINT64_C(__SRC__)
#define DEST UINT64_C(__DEST__)
#define CALLSITE UINT64_C(__CALL__)
#define THUNK UINT64_C(__THUNK__)
#define CONTINUATION UINT64_C(__RETURN__)
#define N_CASES __CASES__U
#define MAX_BYTES 260U
typedef struct {
 uint32_t source_len;
 uint8_t source[260];
 uint8_t expected_dest[260];
 uint64_t rax,rsp,rip,rcx,rdx,return_slot;
 uint32_t eflags;
} fixture;
static const fixture cases[N_CASES]={__ROWS__};
static uint8_t guest_stack[131072U],guest_global[4096U];
int smoke(void){
 mx_cfg_region areas[2]={
   {STACK,guest_stack,131072U},
   {DEST&~UINT64_C(4095),guest_global,4096U}
 };
 mx_cfg_memory mem={areas,2U};
 for(unsigned k=0;k<N_CASES;k++){
   const fixture *f=&cases[k];
   for(unsigned j=0;j<131072U;j++)guest_stack[j]=0U;
   for(unsigned j=0;j<4096U;j++)guest_global[j]=0U;
   for(unsigned j=0;j<MAX_BYTES;j++){
      uint8_t old=0x5aU;
      if(!mx_cfg_transfer(&mem,DEST+j,&old,1U,1))return 1;
   }
   for(unsigned j=0;j<f->source_len+1U;j++){
      uint8_t byte=f->source[j];
      if(!mx_cfg_transfer(&mem,SRC+j,&byte,1U,1))return 2;
   }
   mx_crt_cluster_state s={0};
   s.rip=CALLSITE;s.rsp=SP;s.rax=UINT64_C(0x123456789);
   s.rcx=DEST;s.rdx=SRC;s.r8=0x19U;s.r9=0x321U;
   s.cf=(f->eflags&1U)!=0U;
   s.zf=(f->eflags&64U)!=0U;
   s.sf=(f->eflags&128U)!=0U;
   if(mx_game_crt_strcpy_import_call(&s,&mem,
      CALLSITE,THUNK,CONTINUATION,MAX_BYTES)!=MX_GAME_STRCPY_OK)
       return 3;
   if(s.rax!=f->rax||s.rsp!=f->rsp||s.rip!=f->rip||
      s.rcx!=f->rcx||s.rdx!=f->rdx ||
      s.cf!=((f->eflags&1U)!=0U)||
      s.zf!=((f->eflags&64U)!=0U)||
      s.sf!=((f->eflags&128U)!=0U) ||
      s.imports!=1U||s.instructions!=3U)return 4;
   uint64_t ret=0U;
   if(!mx_cfg_transfer(&mem,SP-8U,&ret,8U,0)||
      ret!=f->return_slot)return 5;
   for(unsigned j=0;j<MAX_BYTES;j++){
      uint8_t value=0U;
      if(!mx_cfg_transfer(&mem,DEST+j,&value,1U,0) ||
         value!=f->expected_dest[j])return 6;
   }
 }
 /* Fail closed when buffer is too short, source is unmapped, or overlaps. */
 mx_crt_cluster_state bad={0};
 bad.rcx=DEST;bad.rdx=SRC;
 if(mx_game_crt_bounded_strcpy(&bad,&mem,0U)!=
    MX_GAME_STRCPY_UNSUPPORTED)return 7;
 bad.rcx=DEST;bad.rdx=DEST;
 if(mx_game_crt_bounded_strcpy(&bad,&mem,MAX_BYTES)!=
    MX_GAME_STRCPY_UNSUPPORTED)return 8;
 bad.rcx=DEST;bad.rdx=BASE+0xabcdU;
 if(mx_game_crt_bounded_strcpy(&bad,&mem,MAX_BYTES)!=
    MX_GAME_STRCPY_MEMORY)return 9;
 return 0;
}
#ifdef HOST
int main(void){return smoke();}
#endif
'''

def generate(dest,references):
    rows=[]
    for path,obs in zip(CASES,references):
        source=list(path+b"\x00")
        expected=obs["destination_bytes"]
        rows.append("{"+str(len(path))+",{"+",".join(str(x) for x in source)+"},{"+
            ",".join(str(x) for x in expected)+"},"+
            ",".join("UINT64_C("+str(obs[key])+")" for key in
                     ("rax","rsp","rip","rcx","rdx","guest_return_at_callee_stack"))+
            ","+str(obs["eflags"])+"}")
    src=C
    for key,value in {
      "__SP__":SP,"__SRC__":SRC,"__DEST__":dest,
      "__CALL__":BASE+CALL,"__THUNK__":BASE+THUNK,
      "__RETURN__":BASE+RETURN,"__CASES__":len(CASES),
      "__ROWS__":",\n".join(rows)
    }.items():src=src.replace(key,str(value))
    return src

def run(executable,out):
    pe=PE(executable)
    if hashlib.sha256(pe.b).hexdigest()!=SHA:
        raise RuntimeError("Original MX Bikes EXE SHA mismatch")
    iat,dest=original_thunk(pe)
    refs=[original_reference(pe,iat,dest,k) for k in range(len(CASES))]
    source=generate(dest,refs)
    with tempfile.TemporaryDirectory(prefix="mxb-msvcr90-strcpy-") as td:
        root=Path(td);private=root/"game-import-private.c"
        private.write_text(source)
        opts=["-std=c11","-O2","-Wall","-Wextra","-Werror",
              "-I",str(ROOT/"arm64-lab"/"runtime")]
        host=root/"host"
        p=subprocess.run(["cc",*opts,"-DHOST",str(private),"-o",str(host)],
                         capture_output=True,text=True)
        if p.returncode:raise RuntimeError("Host compile error: "+p.stderr[-2600:])
        p=subprocess.run([str(host)],capture_output=True,text=True)
        if p.returncode:raise RuntimeError("Host modeled CRT strcpy mismatch code "+str(p.returncode))
        arm=root/"guest-import-aarch64.elf"
        p=subprocess.run(["clang","--target=aarch64-unknown-linux-gnu",
          "-fuse-ld=lld","-nostdlib","-static","-ffreestanding",
          "-fno-builtin","-fno-stack-protector",*opts,
          "-Wl,-e,smoke","-Wl,-z,max-page-size=4096",
          "-Wl,--build-id=none",str(private),"-o",str(arm)],
          capture_output=True,text=True)
        if p.returncode:raise RuntimeError("ARM64 compile error: "+p.stderr[-2600:])
        observed=execute_arm64_elf(arm,instruction_budget=1950000,
                                   timeout_us=15000000)
        if observed["arm64_smoke_exit"]!=0:
            raise RuntimeError("ARM64 strcpy import differential reported nonzero")
    out.mkdir(parents=True,exist_ok=True)
    report={
      "original_sha_verified":True,
      "original_source_game_call_rva":hex(CALL),
      "original_iar_thunk_rva":hex(THUNK),
      "original_iat_slot_rva":hex(iat),
      "exact_original_import":"MSVCR90.dll!strcpy",
      "original_x64_call_thunk_and_modeled_host_cases":len(CASES),
      "native_aarch64_model_import_cases":len(CASES),
      "guest_string_bytes_and_abi_differential":True,
      "real_msvcr90_library_executed":False,
      "live_main_helper_path_joined_native":False,
      "next_internal_continuation_rva":hex(RETURN),
      "engine_booted":False,
      "scope":"Exact original CALL/JMP import identity with controlled host-model strcpy and real native ARM64 copied bytes, RET and registers"
    }
    (out/"msvcr90-strcpy-native.json").write_text(json.dumps(report,indent=2)+"\n")
    lines=[
      "# MX Bikes MSVCR90 strcpy import thunk native differential","",
      "- Original CALL: **0x15b7a5 → 0x2ab41a**",
      "- PE import: **MSVCR90.dll!strcpy**",
      "- Original x64 CALL/JMP/RET vs native ARM64 modeled-service cases: **"+str(len(CASES))+"/"+str(len(CASES))+"**",
      "- Bounded original guest string bytes and Win64 return pointer: **MATCH**",
      "- Original helper continuation reached: **"+hex(RETURN)+"**",
      "",
      "**Uses a controlled test implementation of the CRT import, not the actual MSVCR90 DLL. "
      "This service is tested independently and has not yet been joined to the full native main/helper path.**",""
    ]
    summary="\n".join(lines)
    (out/"msvcr90-strcpy-native.md").write_text(summary)
    print(summary)
    return report

if __name__=="__main__":
    if len(sys.argv)!=3:
        raise SystemExit("usage: strcpy.py original-exe report-dir")
    run(Path(sys.argv[1]),Path(sys.argv[2]))
