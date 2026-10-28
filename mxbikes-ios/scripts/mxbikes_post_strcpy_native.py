#!/usr/bin/env python3
"""Join original MX Bikes main through CRT strcpy, three helper stack writes,
and the following original direct JMP as one native AArch64 differential.

All private source bytes and C fixtures remain ephemeral in runner. Two
external DLL calls use explicit deterministic models. Stop before executing
the jump target at original RVA 0x15b7cf.
"""
from pathlib import Path
import hashlib,json,subprocess,sys,tempfile
from capstone import Cs,CS_ARCH_X86,CS_MODE_64
from capstone.x86 import X86_OP_MEM
from mxbikes_joined_strcpy_native import (
 BASE,MAIN,AFTER_IMPORT,RETURN,EXE_SHA,CASES,NUM_CASES,
 original_run,original_main_with_module_name,original_probe,
 original_joined,verify_next_import,original_thunk,
 inspect_original,verify_helper,generate_joined
)
from mxbikes_post_strcpy_probe import discover,reference
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/"arm64-lab"))
from tools.pe_probe import PE
from tools.import_aot_smoke import execute_arm64_elf

NEXT=0x15b7cf

def verify_source(pe):
    scanned,stop=discover(pe)
    instructions=list(Cs(CS_ARCH_X86,CS_MODE_64).disasm(
        pe.read_rva(RETURN,stop.address-RETURN),RETURN))
    expected=[
       ("mov","qword ptr [rsp + 0x20], 0"),
       ("lea","rax, [rip + 0x23b0e6]"),
       ("mov","qword ptr [rsp + 0x28], rax")
    ]
    if (len(instructions)!=3 or
        [(x.mnemonic,x.op_str) for x in instructions]!=expected or
        stop.address!=0x15b7bf or stop.mnemonic!="jmp" or
        stop.op_str!="0x15b7cf"):
        raise RuntimeError("Original post-strcpy helper instruction layout changed")
    decoder=Cs(CS_ARCH_X86,CS_MODE_64);decoder.detail=True
    second=list(decoder.disasm(pe.read_rva(0x15b7b3,7),0x15b7b3))
    if len(second)!=1 or len(second[0].operands)!=2:
        raise RuntimeError("Original helper constant reference cannot be decoded")
    op=second[0].operands[1]
    if op.type!=X86_OP_MEM or second[0].reg_name(op.mem.base)!="rip":
        raise RuntimeError("Original helper LEA no longer RIP-relative")
    constant=BASE+second[0].address+second[0].size+op.mem.disp
    if constant!=BASE+0x3968a0:
        raise RuntimeError("Original helper constant VA changed")
    return scanned,stop,constant

def append_to_existing_native(existing,references,constant):
    code=existing
    before='static int final_strcpy_smoke(void){'
    if code.count(before)!=1:raise RuntimeError("Unexpected native fixture signature")
    tuples=[]
    register_order=["rax","rcx","rdx","r8","r9","rsp","rip"]
    for item in references:
        regs=item["numeric_registers"]
        tuples.append("{"+
             ",".join("UINT64_C("+str(regs[k])+")" for k in register_order)+
             ",UINT64_C("+str(item["stack_qword_0"])+")"+
             ",UINT64_C("+str(item["stack_qword_1"])+"),"+
             ",".join(str(item["flags"][k]) for k in ("cf","zf","sf"))+
             "}")
    prefix=r'''
#include "mx_game_path_after_strcpy.h"
#define AFTER_STRCPY (BASE+UINT64_C(0x15b7aa))
#define AFTER_STRCPY_JUMP (BASE+UINT64_C(0x15b7cf))
typedef struct {
    uint64_t rax,rcx,rdx,r8,r9,rsp,rip;
    uint64_t local0,local1;
    uint8_t cf,zf,sf;
} after_strcpy_fixture;
static const after_strcpy_fixture original_after_strcpy[STRCPY_GUEST_CASES]={
__ORIGINAL_CASES__
};
static const mx_game_path_after_strcpy_layout after_strcpy_layout={
 AFTER_STRCPY,UINT64_C(__CONSTANT__),AFTER_STRCPY_JUMP
};
'''
    prefix=prefix.replace("__ORIGINAL_CASES__",",\n".join(tuples))
    prefix=prefix.replace("__CONSTANT__",str(constant))
    code=code.replace(before,prefix+"\n"+before)
    needle='''      read_guest(&guest,ENTRY_SP-0x288U-8U,8U)!=t->helper_return)
      return 61;
 }'''
    addition='''      read_guest(&guest,ENTRY_SP-0x288U-8U,8U)!=t->helper_return)
      return 61;
   const after_strcpy_fixture*a=&original_after_strcpy[k];
   if(mx_game_path_after_strcpy(&s,&guest,&after_strcpy_layout)!=
      MX_GAME_PATH_AFTER_STRCPY_FRONTIER)return 63;
   if(s.rax!=a->rax || s.rcx!=a->rcx ||s.rdx!=a->rdx||
      s.r8!=a->r8||s.r9!=a->r9||
      s.rsp!=a->rsp||s.rip!=a->rip||
      s.cf!=a->cf||s.zf!=a->zf||s.sf!=a->sf||
      s.instructions!=36U)return 64;
   if(read_guest(&guest,s.rsp+0x20U,8U)!=a->local0 ||
      read_guest(&guest,s.rsp+0x28U,8U)!=a->local1)return 65;
 }'''
    if code.count(needle)!=1:raise RuntimeError("Original joined strcpy native sequence changed")
    code=code.replace(needle,addition)
    return code

def run(executable,out):
    pe=PE(executable)
    if hashlib.sha256(pe.b).hexdigest()!=EXE_SHA:
        raise RuntimeError("SHA of original MX Bikes executable changed")
    scanned,stop,constant=verify_source(pe)
    layout,_,_=inspect_original(pe)
    iat_module=verify_next_import(pe)
    iat_strcpy,destination=original_thunk(pe)
    _,helper_stop,prior_constant=verify_helper(pe)
    first_refs=[original_run(pe,layout,k) for k in range(NUM_CASES)]
    name_refs=[(i,original_main_with_module_name(pe,layout,iat_module,i))
                for i in CASES]
    helper_refs=[(i,original_probe(pe,layout,iat_module,helper_stop,i))
                for i in CASES]
    strcpy_refs=[(i,original_joined(pe,layout,iat_module,iat_strcpy,destination,i))
                 for i in CASES]
    after_refs=[reference(pe,iat_module,iat_strcpy,destination,stop,i,
                           execute_direct_jump=True)
                for i in CASES]
    if not all(x["post_strcpy_insns_executed"]==3 and
               x["numeric_registers"]["rip"]==BASE+NEXT and
               x["stack_qword_0"]==0 and
               x["stack_qword_1"]==constant for x in after_refs):
        raise RuntimeError("Original post-strcpy stack/PC reference changed")
    prior_native=generate_joined(layout,first_refs,name_refs,
                                 helper_refs,strcpy_refs,prior_constant,destination)
    native=append_to_existing_native(prior_native,after_refs,constant)
    with tempfile.TemporaryDirectory(prefix="mxb-original-poststrcpy-") as td:
        root=Path(td)
        c=root/"private-original-poststrcpy-joined.c"
        c.write_text(native)
        options=["-std=c11","-O2","-Wall","-Wextra","-Werror",
                 "-I",str(ROOT/"arm64-lab"/"runtime")]
        host=root/"host"
        result=subprocess.run(["cc",*options,"-DHOST",str(c),"-o",str(host)],
                              capture_output=True,text=True)
        if result.returncode:
            raise RuntimeError("Post-strcpy host compilation: "+result.stderr[-3800:])
        result=subprocess.run([str(host)],capture_output=True,text=True)
        if result.returncode:
            raise RuntimeError("Host x64/translated guest differential failed "+str(result.returncode))
        arm=root/"native-original-after-strcpy.elf"
        result=subprocess.run(["clang","--target=aarch64-unknown-linux-gnu",
             "-fuse-ld=lld","-nostdlib","-static","-ffreestanding",
             "-fno-builtin","-fno-stack-protector",*options,
             "-Wl,-e,smoke","-Wl,-z,max-page-size=4096",
             "-Wl,--build-id=none",str(c),"-o",str(arm)],
             capture_output=True,text=True)
        if result.returncode:
            raise RuntimeError("Post-strcpy ARM64 compilation: "+result.stderr[-3800:])
        result=execute_arm64_elf(arm,instruction_budget=1950000,
                                 timeout_us=15000000)
        if result["arm64_smoke_exit"]!=0:
            raise RuntimeError("Post-strcpy joined native ARM64 mismatch")
    out.mkdir(parents=True,exist_ok=True)
    report={
       "sha_verified_owned_original":True,
       "original_main_to_strcpy_connected":True,
       "new_original_post_strcpy_instructions_native_executed":4,
       "new_native_execution_cases":len(after_refs),
       "original_x64_cases_matched":len(after_refs),
       "original_guest_stack_qwords_compared":2,
       "original_jump_target_rva":hex(NEXT),
       "native_continuation_rva":hex(NEXT),
       "entire_original_filename_helper_implemented":False,
       "next_jump_target_executed":False,
       "guest_kernel32_msvcr90_imports_modeled":True,
       "engine_initialized":False,
       "iOS_binary_built":False
    }
    (out/"joined-post-strcpy-native.json").write_text(json.dumps(report,indent=2)+"\n")
    md="\n".join([
        "# MX Bikes native startup through original post-strcpy JMP","",
        "- Continuous original main → filename → strcpy → helper block: **VERIFIED**",
        "- Original post-strcpy instructions added to native execution: **4**",
        "- Original x64 versus AArch64 differential matches: **"+
          str(len(after_refs))+"/"+str(len(after_refs))+"**",
        "- Original two guest stack-local qwords and RIP-relative constant compared: **YES**",
        "- New native control frontier: **0x15b7cf**",
        "",
        "**This does not execute the jump target, return the entire helper, "
        "or initialize the game engine. Both DLL responses are controlled models.**",""
    ])
    (out/"joined-post-strcpy-native.md").write_text(md)
    print(md)
    return report

if __name__=="__main__":
    if len(sys.argv)!=3:raise SystemExit("usage: after_strcpy_native.py original_exe outputdir")
    run(Path(sys.argv[1]),Path(sys.argv[2]))
