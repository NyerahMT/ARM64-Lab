#!/usr/bin/env python3
"""Extend joined original MX Bikes native filename startup through 0x2f JNE.

Normal string byte -> original RVA 0x15b7ff JMP back to 0x15b7c1.
Synthetic slash byte -> original RVA 0x15b7f5.
Both verified against original SHA-pinned x64 guest emulation; 2 external
Win64 DLL imports are explicit deterministic fixtures, not real Windows.
No gameplay or rendering.
"""
from pathlib import Path
import hashlib,json,subprocess,sys,tempfile
from capstone import Cs,CS_ARCH_X86,CS_MODE_64
from mxbikes_joined_strcpy_native import (
 EXE_SHA,BASE,CASES,NUM_CASES,
 original_run,original_main_with_module_name,original_probe,
 original_joined,verify_next_import,original_thunk,
 inspect_original,verify_helper,generate_joined)
from mxbikes_post_strcpy_native import verify_source,append_to_existing_native
from mxbikes_after_strcpy_branch_native import (
 verify_branch,original_branch,extend_native,INPUTS)
from mxbikes_filename_separator_native import (
 validate_original,extend_successors)
from mxbikes_post_strcpy_probe import discover as discover_first,reference as reference_first
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/"arm64-lab"))
from tools.pe_probe import PE
from tools.import_aot_smoke import execute_arm64_elf

NORMAL=0x15b7e8
LOOP=0x15b7c1
SLASH_FALL=0x15b7f5
STRCPY_JCC_BRANCHES={"normal":(0x15b7f3,"jne","0x15b7ff"),
                      "loop":(0x15b7ff,"jmp","0x15b7c1")}

def validate_source(pe):
    md=Cs(CS_ARCH_X86,CS_MODE_64);md.detail=True
    patterns=[
       (0x15b7e8,"mov","rax, qword ptr [rsp + 0x28]"),
       (0x15b7ed,"movsx","eax, byte ptr [rax]"),
       (0x15b7f0,"cmp","eax, 0x2f"),
       (0x15b7f3,"jne","0x15b7ff"),
       (0x15b7ff,"jmp","0x15b7c1"),
    ]
    for address,mnemonic,operands in patterns:
        inst=next(md.disasm(pe.read_rva(address,10),address),None)
        if inst is None or (inst.mnemonic,inst.op_str)!=(mnemonic,operands):
            raise RuntimeError("Original signed slash test/loop-back identity changed at "+hex(address))

def extend(native,refs,slash_case):
    entry="static int final_strcpy_smoke(void){"
    if native.count(entry)!=1:
        raise RuntimeError("Native separator test fixture anchor missing")
    order=("rax","rbx","rcx","rdx","r8","r9","rdi","rsi","r11","rsp","rip")
    def row(x):
        return ("{"+",".join("UINT64_C("+str(x[k])+")" for k in order)+","+
                ",".join(str(x[k]) for k in ("cf","zf","sf"))+"}")
    values=[row(x) if x is not None else "{0}" for x in refs]
    extra=r'''
#include "mx_game_path_slash_loop.h"
#define SLASH_START (BASE+UINT64_C(0x15b7e8))
#define SLASH_LOOP (BASE+UINT64_C(0x15b7c1))
#define SLASH_FOUND (BASE+UINT64_C(0x15b7f5))
typedef struct {
 uint64_t rax,rbx,rcx,rdx,r8,r9,rdi,rsi,r11,rsp,rip;
 uint8_t cf,zf,sf;
} original_slash_case;
static const original_slash_case expected_slash_loop[STRCPY_GUEST_CASES]={
__ROWS__
};
static const original_slash_case expected_slash_found=__SLASH_ROW__;
static const mx_game_slash_loop_layout slash_layout={
 SLASH_START,SLASH_FOUND,SLASH_LOOP
};
'''
    extra=extra.replace("__ROWS__",",\n".join(values))
    extra=extra.replace("__SLASH_ROW__",row(slash_case))
    native=native.replace(entry,extra+"\n"+entry)
    anchor='''      s.instructions!=(br->byte==0U?42U:44U))return 70;
 }'''
    expanded='''      s.instructions!=(br->byte==0U?42U:44U))return 70;
   if(br->byte!=0U&&br->byte!=0x5cU){
     const original_slash_case*o=&expected_slash_loop[k];
     if(k==0){
        mx_crt_cluster_state special=s;
        uint8_t slash=0x2fU;
        if(!mx_cfg_transfer(&guest,STRING_DEST,&slash,1U,1))return 71;
        if(mx_game_slash_loop(&special,&guest,&slash_layout)!=
           MX_GAME_SLASH_LOOP_REACHED)return 72;
        const original_slash_case*t=&expected_slash_found;
        if(special.rax!=t->rax||special.rbx!=t->rbx||
           special.rcx!=t->rcx||special.rdx!=t->rdx||
           special.r8!=t->r8||special.r9!=t->r9||
           special.rdi!=t->rdi||special.rsi!=t->rsi||
           special.r11!=t->r11||special.rsp!=t->rsp||
           special.rip!=t->rip||special.cf!=t->cf||
           special.zf!=t->zf||special.sf!=t->sf||
           special.instructions!=48U)return 73;
        uint8_t restore=br->byte;
        if(!mx_cfg_transfer(&guest,STRING_DEST,&restore,1U,1))return 74;
     }
     if(mx_game_slash_loop(&s,&guest,&slash_layout)!=
        MX_GAME_SLASH_LOOP_REACHED)return 75;
     if(s.rax!=o->rax||s.rbx!=o->rbx||s.rcx!=o->rcx||
        s.rdx!=o->rdx||s.r8!=o->r8||s.r9!=o->r9||
        s.rdi!=o->rdi||s.rsi!=o->rsi||s.r11!=o->r11||
        s.rsp!=o->rsp||s.rip!=o->rip||
        s.cf!=o->cf||s.zf!=o->zf||s.sf!=o->sf||
        s.instructions!=49U)return 76;
   }
 }'''
    if native.count(anchor)!=1:raise RuntimeError("Original second JE ending changed")
    return native.replace(anchor,expanded)


def extend_next_iteration(native,refs,second_refs):
    """Append independently x64-proven pointer+1 and next TEST/JE to guest path."""
    entry="static int final_strcpy_smoke(void){"
    if native.count(entry)!=1:
        raise RuntimeError("Prior native loop entry signature changed")
    order=("rax","rbx","rcx","rdx","r8","r9","rdi","rsi","r11","rsp","rip")
    def row(item):
        if item is None:
            return "{0}"
        return ("{"+",".join("UINT64_C("+str(item[k])+")" for k in order)+
                ",UINT64_C("+str(item["pointer"])+"),"+
                ",".join(str(item[k]) for k in ("cf","zf","sf"))+"}")
    extra=r'''
#include "mx_game_filename_loop_iteration.h"
#define NEXT_ITERATION_ENTRY (BASE+UINT64_C(0x15b7c1))
#define NEXT_ITERATION_ZERO (BASE+UINT64_C(0x15b801))
#define NEXT_ITERATION_NONZERO (BASE+UINT64_C(0x15b7db))
typedef struct {
 uint64_t rax,rbx,rcx,rdx,r8,r9,rdi,rsi,r11,rsp,rip,ptr;
 uint8_t cf,zf,sf;
} original_iter_case;
static const original_iter_case original_iterations[STRCPY_GUEST_CASES]={
__ITER_REF__
};
static const original_iter_case original_second_loop[STRCPY_GUEST_CASES]={
__SECOND_LOOP_REF__
};
static const mx_game_filename_iteration_layout native_iteration_layout={
 NEXT_ITERATION_ENTRY,NEXT_ITERATION_ZERO,NEXT_ITERATION_NONZERO
};
'''
    native=native.replace(entry,extra.replace(
        "__ITER_REF__",",\n".join(row(x) for x in refs)).replace(
        "__SECOND_LOOP_REF__",",\n".join(row(x) for x in second_refs))+"\n"+entry)
    anchor='''        s.instructions!=49U)return 76;
   }
 }'''
    addition='''        s.instructions!=49U)return 76;
     const original_iter_case*t=&original_iterations[k];
     mx_game_filename_iteration_result observed={0};
     if(mx_game_filename_loop_iteration(&s,&guest,
        &native_iteration_layout,&observed)!=
        MX_GAME_LOOP_ITERATION_REACHED)return 77;
     if(s.rax!=t->rax||s.rbx!=t->rbx||s.rcx!=t->rcx||
        s.rdx!=t->rdx||s.r8!=t->r8||s.r9!=t->r9||
        s.rdi!=t->rdi||s.rsi!=t->rsi||s.r11!=t->r11||
        s.rsp!=t->rsp||s.rip!=t->rip||
        s.cf!=t->cf||s.zf!=t->zf||s.sf!=t->sf||
        observed.original_next_pointer!=t->ptr||
        read_guest(&guest,s.rsp+0x28U,8U)!=t->ptr||
        s.instructions!=56U)return 78;
     /* Continue the same original guest frame and file buffer:
      * second ':' is neither '\\' nor '/', so loop back again. */
     mx_game_path_separator_result separator={0};
     if(mx_game_path_separator_branch(&s,&guest,
          &original_separator_layout,&separator)!=
          MX_GAME_SEPARATOR_FRONTIER)return 79;
     if(s.rip!=NORMAL_JE_FALL||separator.normalized_byte!=0x3aU||
        s.instructions!=60U)return 80;
     if(mx_game_slash_loop(&s,&guest,&slash_layout)!=
          MX_GAME_SLASH_LOOP_REACHED)return 81;
     const original_iter_case*second=&original_second_loop[k];
     if(s.rax!=second->rax||s.rbx!=second->rbx||
        s.rcx!=second->rcx||s.rdx!=second->rdx||
        s.r8!=second->r8||s.r9!=second->r9||
        s.rdi!=second->rdi||s.rsi!=second->rsi||
        s.r11!=second->r11||s.rsp!=second->rsp||
        s.rip!=second->rip||s.cf!=second->cf||
        s.zf!=second->zf||s.sf!=second->sf||
        read_guest(&guest,s.rsp+0x28U,8U)!=second->ptr||
        s.instructions!=65U)return 82;
   }
 }'''
    if native.count(anchor)!=1:
        raise RuntimeError("Native normal slash loop ending changed")
    return native.replace(anchor,addition)

def run(exe,out):
    pe=PE(exe)
    if hashlib.sha256(pe.b).hexdigest()!=EXE_SHA:
        raise RuntimeError("Original owned MX Bikes binary digest changed")
    validate_source(pe)
    verify_branch(pe)
    validate_original(pe)
    _,_,after_constant=verify_source(pe)
    layout,_,_=inspect_original(pe)
    iat_module=verify_next_import(pe)
    iat_strcpy,destination=original_thunk(pe)
    _,helper_stop,first_constant=verify_helper(pe)
    if after_constant!=destination or first_constant!=destination:
        raise RuntimeError("Original game helper guest-global pointer changed")
    a=[original_run(pe,layout,k) for k in range(NUM_CASES)]
    b=[(k,original_main_with_module_name(pe,layout,iat_module,k))
       for k in CASES]
    c=[(k,original_probe(pe,layout,iat_module,helper_stop,k))
       for k in CASES]
    d=[(k,original_joined(pe,layout,iat_module,iat_strcpy,destination,k))
       for k in CASES]
    _,old_stop=discover_first(pe)
    e=[reference_first(pe,iat_module,iat_strcpy,destination,old_stop,k,
                       execute_direct_jump=True) for k in CASES]
    first=[original_branch(pe,iat_module,iat_strcpy,destination,k,value)
           for k,value in zip(CASES,INPUTS)]
    second=[original_branch(pe,iat_module,iat_strcpy,destination,k,value,
                            follow_successor=True)
            for k,value in zip(CASES,INPUTS)]
    refs=[(original_branch(pe,iat_module,iat_strcpy,destination,k,value,
                           follow_successor=True,follow_slash_loop=True)
           if value not in (0,0x5c) else None)
          for k,value in zip(CASES,INPUTS)]
    slash=original_branch(pe,iat_module,iat_strcpy,destination,CASES[0],0x2f,
                          follow_successor=True,follow_slash_loop=True)
    iteration_refs=[(
        original_branch(pe,iat_module,iat_strcpy,destination,k,value,
                        follow_successor=True,follow_slash_loop=True,
                        follow_loop_iteration=True)
        if value not in (0,0x5c) else None)
        for k,value in zip(CASES,INPUTS)]
    for item in iteration_refs:
        if item and (item["rip"]!=BASE+0x15b7db or
                     item["pointer"]!=destination+1):
            raise RuntimeError("Original x64 loop increment and second character changed")
    second_loop_refs=[(
        original_branch(pe,iat_module,iat_strcpy,destination,k,value,
                        follow_successor=True,follow_slash_loop=True,
                        follow_loop_iteration=True,
                        follow_second_loopback=True)
        if value not in (0,0x5c) else None)
        for k,value in zip(CASES,INPUTS)]
    for item in second_loop_refs:
        if item and (item["rip"]!=BASE+LOOP or
                     item["pointer"]!=destination+1 or
                     item["rax"]!=0x3a):
            raise RuntimeError("Original x64 second filename loop-back disagrees")
    for item in refs:
        if item and item["rip"]!=BASE+LOOP:
            raise RuntimeError("Original normal filename loop-back x64 control mismatch")
    if slash["rip"]!=BASE+SLASH_FALL:
        raise RuntimeError("Original literal slash test fallthrough failed")
    native=generate_joined(layout,a,b,c,d,first_constant,destination)
    native=append_to_existing_native(native,e,after_constant)
    native=extend_native(native,first,destination)
    native=extend_successors(native,second)
    native=extend(native,refs,slash)
    native=extend_next_iteration(native,iteration_refs,second_loop_refs)
    with tempfile.TemporaryDirectory(prefix="mxb-normal-slash-jcc-") as tmp:
        root=Path(tmp);source=root/"original-game-private-slash-native.c"
        source.write_text(native)
        opts=["-O2","-std=c11","-Wall","-Wextra","-Werror",
              "-I",str(ROOT/"arm64-lab"/"runtime")]
        host=root/"host"
        result=subprocess.run(["cc",*opts,"-DHOST",str(source),"-o",str(host)],
                              capture_output=True,text=True)
        if result.returncode:
            raise RuntimeError("Normal filename host differential compile: "+result.stderr[-3600:])
        result=subprocess.run([str(host)],capture_output=True,text=True)
        if result.returncode:
            raise RuntimeError("Normal filename x64 vs native host mismatch exit="+str(result.returncode))
        arm=root/"native-original-filename-loop.elf"
        result=subprocess.run(["clang","--target=aarch64-unknown-linux-gnu",
          "-fuse-ld=lld","-nostdlib","-static","-ffreestanding",
          "-fno-builtin","-fno-stack-protector",*opts,
          "-Wl,-e,smoke","-Wl,-z,max-page-size=4096",
          "-Wl,--build-id=none",str(source),"-o",str(arm)],
          capture_output=True,text=True)
        if result.returncode:
            raise RuntimeError("Native ARM64 original helper compilation: "+result.stderr[-3600:])
        status=execute_arm64_elf(arm,instruction_budget=1950000,timeout_us=15000000)
        if status["arm64_smoke_exit"]!=0:
            raise RuntimeError("Original filename slash native ARM64 comparison failed "+
                               str(status["arm64_smoke_exit"]))
    out.mkdir(parents=True,exist_ok=True)
    n=sum(x is not None for x in refs)
    report={
     "original_owned_executable_sha_verified":True,
     "joined_main_two_win32_models_strcpy_successors":True,
     "new_original_normal_JNE_and_loopback_instructions":5,
     "native_arm64_normal_loop_cases":n,
     "separate_original_slash_fallthrough_cases":1,
     "total_new_original_x64_vs_arm64_scenarios":n+1,
     "normal_path_loopback_rva":hex(LOOP),
     "slash_separator_found_rva":hex(SLASH_FALL),
     "entire_filename_loop_verified":False,
     "loop_body_executed":True,
     "one_more_original_loop_iteration_executed":True,
     "original_x64_vs_arm64_increment_differentials":sum(x is not None for x in iteration_refs),
     "next_guest_character":":",
     "second_original_separator_and_loopback_verified":True,
     "second_loopback_x64_arm64_matched_cases":sum(x is not None for x in second_loop_refs),
     "second_original_control_frontier":hex(LOOP),
     "loop_zero_byte_termination_verified":False,
     "engine_or_renderer_running":False,
     "ios_build_available":False,
     "note":"Starts at original game main and stops at original 0x15B7C1 loop header / 0x15B7F5 found-separator. Two DLL imports are controlled models; normal path is not whole filename processing."
    }
    (out/"normal-filename-loop-native.json").write_text(json.dumps(report,indent=2)+"\n")
    summary="\n".join([
      "# MX Bikes original filename parser slash test and loop-back — native ARM64","",
      "- Original connected game main → two API models → filename helper: **PASS**",
      "- New normal filename instructions: **5**",
      "- Original x64 versus native ARM64 loop-back examples: **"+str(n)+"/"+str(n)+"**",
      "- Independent literal slash comparison example: **PASS**",
      "- Normal control now reaches original loop header: **0x15B7C1**",
      "- Original loop-body 7 additional x64-equivalent instructions: **VERIFIED**",
      "- Original x64 versus ARM64 next-character cases: **"+
        str(sum(x is not None for x in iteration_refs))+"/"+
        str(sum(x is not None for x in iteration_refs))+"**",
      "- Next guest character after initial C: **':'**",
      "- Second original backslash/slash comparison and backward JMP:",
      "  **"+str(sum(x is not None for x in second_loop_refs))+
      "/"+str(sum(x is not None for x in second_loop_refs))+
      " x64/native ARM64 cases matched**",
      "- Connected normal filename control loops back to: **0x15B7C1**",
      "",
      "**This verifies x64/native code equivalence at the original branch frontier; "
      "the whole filename parser, engine and game graphics are not running.**",""
    ])
    (out/"normal-filename-loop-native.md").write_text(summary)
    print(summary)
    return report

if __name__=="__main__":
    if len(sys.argv)!=3:raise SystemExit("usage: native_loop.py original_game.exe outdir")
    run(Path(sys.argv[1]),Path(sys.argv[2]))
