#!/usr/bin/env python3
"""Extend verified MX Bikes native startup through BOTH original separator JEs.

Run SHA-verified x64 original main through controlled GetModuleFileNameA and
strcpy models, joined filename helper first JE, and either of two original
second JE blocks. Compare native ARM64 guest state at the EXACT next
successor PC for each of five deterministic byte inputs.
"""
from pathlib import Path
import hashlib,json,subprocess,sys,tempfile
from mxbikes_joined_strcpy_native import (
 EXE_SHA,BASE,CASES,NUM_CASES,original_run,original_main_with_module_name,
 original_probe,original_joined,verify_next_import,original_thunk,
 inspect_original,verify_helper,generate_joined
)
from mxbikes_post_strcpy_native import verify_source,append_to_existing_native
from mxbikes_after_strcpy_branch_native import (
  verify_branch,original_branch,extend_native,INPUTS,START,FALLTHROUGH,TAKEN
)
from mxbikes_post_strcpy_probe import discover as discover_first,reference as reference_first
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/"arm64-lab"))
from tools.pe_probe import PE
from tools.import_aot_smoke import execute_arm64_elf

NONZERO_TAKEN=0x15b7f5
NONZERO_NEXT=0x15b7e8
ZERO_TAKEN=0x15b81b
ZERO_NEXT=0x15b809

def extend_successors(native,refs):
    before="static int final_strcpy_smoke(void){"
    if native.count(before)!=1:
        raise RuntimeError("Expected joined native test entry missing")
    order=("rax","rbx","rcx","rdx","r8","r9","rdi","rsi","r11","rsp","rip")
    rows=[]
    for sample in refs:
        rows.append("{"+
          ",".join("UINT64_C("+str(sample[x])+")" for x in order)+","+
          ",".join(str(sample[k]) for k in ("cf","zf","sf","byte"))+"}")
    extra=r'''
#include "mx_game_path_separator_branch.h"
#define NORMAL_JE_START (BASE+UINT64_C(0x15b7db))
#define ZERO_JE_START (BASE+UINT64_C(0x15b801))
#define NORMAL_JE_TAKEN (BASE+UINT64_C(0x15b7f5))
#define NORMAL_JE_FALL (BASE+UINT64_C(0x15b7e8))
#define ZERO_JE_TAKEN (BASE+UINT64_C(0x15b81b))
#define ZERO_JE_FALL (BASE+UINT64_C(0x15b809))
typedef struct{
  uint64_t rax,rbx,rcx,rdx,r8,r9,rdi,rsi,r11,rsp,rip;
  uint8_t cf,zf,sf,byte;
} second_branch_case;
static const second_branch_case original_second_branch[STRCPY_GUEST_CASES]={
__SECOND_REFS__
};
static const mx_game_path_separator_layout original_separator_layout={
 NORMAL_JE_START,ZERO_JE_START,
 NORMAL_JE_TAKEN,NORMAL_JE_FALL,ZERO_JE_TAKEN,ZERO_JE_FALL
};
'''
    native=native.replace(before,
                          extra.replace("__SECOND_REFS__",",\n".join(rows))+"\n"+before)
    anchor='''      outcome.branch_taken!=(br->byte==0U)||
      s.instructions!=40U)return 68;
 }'''
    replacement='''      outcome.branch_taken!=(br->byte==0U)||
      s.instructions!=40U)return 68;
   const second_branch_case*second=&original_second_branch[k];
   mx_game_path_separator_result next={0};
   if(mx_game_path_separator_branch(&s,&guest,
       &original_separator_layout,&next)!=MX_GAME_SEPARATOR_FRONTIER)
      return 69;
   if(s.rax!=second->rax||s.rbx!=second->rbx||s.rcx!=second->rcx||
      s.rdx!=second->rdx||s.r8!=second->r8||s.r9!=second->r9||
      s.rdi!=second->rdi||s.rsi!=second->rsi||s.r11!=second->r11||
      s.rsp!=second->rsp||s.rip!=second->rip||
      s.cf!=second->cf||s.zf!=second->zf||s.sf!=second->sf||
      next.zero_path!=(br->byte==0U)||
      (br->byte!=0U&&next.normalized_byte!=br->byte)||
      s.instructions!=(br->byte==0U?42U:44U))return 70;
 }'''
    if native.count(anchor)!=1:
        raise RuntimeError("Native first original JE verification anchor changed")
    return native.replace(anchor,replacement)

def validate_original(pe):
    mddata=[(0x15b7db,("mov","rax, qword ptr [rsp + 0x28]")),
            (0x15b7e0,("movsx","eax, byte ptr [rax]")),
            (0x15b7e3,("cmp","eax, 0x5c")),
            (0x15b7e6,("je","0x15b7f5")),
            (0x15b801,("cmp","qword ptr [rsp + 0x20], 0")),
            (0x15b807,("je","0x15b81b"))]
    from capstone import Cs,CS_ARCH_X86,CS_MODE_64
    md=Cs(CS_ARCH_X86,CS_MODE_64)
    for address,expected in mddata:
        ins=list(md.disasm(pe.read_rva(address,10),address))[0]
        if(ins.mnemonic,ins.op_str)!=expected:
            raise RuntimeError("Original separator Jcc instruction no longer matches")

def run(executable,destination):
    pe=PE(executable)
    if hashlib.sha256(pe.b).hexdigest()!=EXE_SHA:
        raise RuntimeError("Unrecognized original owned MX Bikes binary")
    verify_branch(pe)
    validate_original(pe)
    _,_,dst_constant=verify_source(pe)
    layout,_,_=inspect_original(pe)
    module_iat=verify_next_import(pe)
    strcpy_iat,dest=original_thunk(pe)
    _,helper_stop,helper_constant=verify_helper(pe)
    if dst_constant!=dest or helper_constant!=dest:
        raise RuntimeError("Original guest filename global address changed")
    oldrefs=[original_run(pe,layout,k) for k in range(NUM_CASES)]
    modrefs=[(k,original_main_with_module_name(pe,layout,module_iat,k))
             for k in CASES]
    helperrefs=[(k,original_probe(pe,layout,module_iat,helper_stop,k))
                for k in CASES]
    strcpyrefs=[(k,original_joined(pe,layout,module_iat,strcpy_iat,dest,k))
                for k in CASES]
    _,first_stop=discover_first(pe)
    afterrefs=[reference_first(pe,module_iat,strcpy_iat,dest,first_stop,k,
                execute_direct_jump=True) for k in CASES]
    first=[original_branch(pe,module_iat,strcpy_iat,dest,k,byte)
           for k,byte in zip(CASES,INPUTS)]
    nextcases=[original_branch(pe,module_iat,strcpy_iat,dest,k,byte,
                               follow_successor=True)
               for k,byte in zip(CASES,INPUTS)]
    destinations=[]
    for sample in nextcases:
        byte=sample["byte"]
        target=(ZERO_TAKEN if byte==0 else
                NONZERO_TAKEN if byte==0x5c else NONZERO_NEXT)
        if sample["rip"]!=BASE+target:
            raise RuntimeError("Original second JE did not reach verified destination")
        destinations.append(hex(target))
    native=generate_joined(layout,oldrefs,modrefs,
                           helperrefs,strcpyrefs,helper_constant,dest)
    native=append_to_existing_native(native,afterrefs,dst_constant)
    native=extend_native(native,first,dest)
    native=extend_successors(native,nextcases)
    with tempfile.TemporaryDirectory(prefix="mxb-linked-separator-") as td:
        root=Path(td)
        source=root/"original-guest-two-branch-native.c"
        source.write_text(native)
        opts=["-std=c11","-O2","-Wall","-Wextra","-Werror",
              "-I",str(ROOT/"arm64-lab"/"runtime")]
        host=root/"host"
        p=subprocess.run(["cc",*opts,"-DHOST",str(source),"-o",str(host)],
                         capture_output=True,text=True)
        if p.returncode:raise RuntimeError("Host guest linker compilation: "+p.stderr[-3000:])
        p=subprocess.run([str(host)],capture_output=True,text=True)
        if p.returncode:raise RuntimeError("Host guest linker differential exit "+str(p.returncode))
        arm=root/"native-original-separator-jcc.elf"
        p=subprocess.run(["clang","--target=aarch64-unknown-linux-gnu",
             "-fuse-ld=lld","-nostdlib","-static","-ffreestanding",
             "-fno-builtin","-fno-stack-protector",*opts,
             "-Wl,-e,smoke","-Wl,-z,max-page-size=4096",
             "-Wl,--build-id=none",str(source),"-o",str(arm)],
             capture_output=True,text=True)
        if p.returncode:raise RuntimeError("ARM64 guest linker compilation: "+p.stderr[-3000:])
        r=execute_arm64_elf(arm,instruction_budget=1950000,timeout_us=15000000)
        if r["arm64_smoke_exit"]!=0:
            raise RuntimeError("ARM64 original second JE guest differential failed "+
                               str(r["arm64_smoke_exit"]))
    destination.mkdir(parents=True,exist_ok=True)
    normal_taken=sum(x["byte"]==0x5c for x in nextcases)
    zero_taken=sum(x["byte"]==0 for x in nextcases)
    report={
      "original_owned_PE_sha_verified":True,
      "connected_original_game_startup_through_two_import_models":True,
      "additional_original_x64_instructions_translated_in_2nd_JE":6,
      "original_x64_vs_AArch64_cases_passed":len(nextcases),
      "normal_filename_branch_cases":len(nextcases)-zero_taken,
      "separator_backslash_branch_taken":normal_taken,
      "empty_byte_stack_cmp_branch_taken":zero_taken,
      "other_nonzero_fallthroughs":len(nextcases)-normal_taken-zero_taken,
      "original_branch_destination_RVAs":destinations,
      "both_original_second_branch_successors_tested":True,
      "engine_initialized":False,
      "next_control_destinations_executed":False,
      "iOS_application_built":False,
      "warnings":"Both external DLL calls use explicit deterministic models. Branch variant tests alter the guest filename byte after strcpy. Only SF/ZF/CF tracked, not OF."
    }
    (destination/"joined-filename-separator-jcc.json").write_text(json.dumps(report,indent=2)+"\n")
    summary="\n".join([
      "# MX Bikes — original filename separator conditional joined on ARM64","",
      "- Full previous connected main/filename/strcpy/native chain: **PASS**",
      "- Original new second-branch instructions: **4 on nonzero / 2 on zero path**",
      "- Original x64 vs actual ARM64 execution cases: **"+
        str(len(nextcases))+"/"+str(len(nextcases))+"**",
      "- Normal filename branch to **0x15B7E8**, backslash to **0x15B7F5**, empty-byte branch to **0x15B81B**",
      "- Backslash comparison cases: **"+str(normal_taken)+"**",
      "- Empty-byte comparison cases: **"+str(zero_taken)+"**",
      "- Flags and machine return/guest memory verified: **YES**",
      "",
      "**No next branch destinations, renderer, game engine, or iOS binary executed. "
      "Windows imports remain explicitly modeled.**",""
    ])
    (destination/"joined-filename-separator-jcc.md").write_text(summary)
    print(summary)
    return report

if __name__=="__main__":
    if len(sys.argv)!=3:raise SystemExit("usage: separator.py original-game.exe output-dir")
    run(Path(sys.argv[1]),Path(sys.argv[2]))
