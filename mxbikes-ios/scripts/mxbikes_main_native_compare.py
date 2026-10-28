#!/usr/bin/env python3
"""Verify native first game-main block against PRIVATE original x64 execution.

Loads the user's own executable in private CI, executes 8 genuine x64 source
instructions with fail-closed boundary checks, then executes the same guest
effects as host C and actual native ARM64 ELF. No game-derived executable,
derived source or runtime cookie leaves the ephemeral job.
"""
from pathlib import Path
import json
import os
import shutil
import subprocess
import sys
import tempfile

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/"arm64-lab"))
from tools.import_aot_smoke import execute_arm64_elf
from mxbikes_main_first_block import probe,BASE,MAIN,TEB

SOURCE=r"""
#include <stdint.h>
#include "mx_main_entry_prefix.h"
#define BASE UINT64_C(0x140000000)
#define COOKIE UINT64_C(COOKIE_V)
#define ARG0 UINT64_C(ARG0_V)
#define ARG1 UINT64_C(ARG1_V)
#define SHOW UINT64_C(SHOW_V)
#define START_RSP UINT64_C(START_RSP_V)
#define AFTER_RSP UINT64_C(AFTER_RSP_V)
#define INIT_COOKIE UINT64_C(INIT_COOKIE_V)
#define EXPECT_RAX UINT64_C(EXPECT_RAX_V)
#define EXPECT_RCX UINT64_C(EXPECT_RCX_V)
#define EXPECT_STACK UINT64_C(EXPECT_STACK_V)
#define EXPECT_ARG0 UINT64_C(EXPECT_ARG0_V)
#define EXPECT_ARG1 UINT64_C(EXPECT_ARG1_V)
#define EXPECT_SHOW UINT32_C(EXPECT_SHOW_V)
static uint8_t stack_area[4096],cookie_data[8],arg0_data[8],arg1_data[8],show_data[4];
int smoke(void){
    mx_cfg_region areas[5]={
      {UINT64_C(0x70001f000),stack_area,4096U},
      {COOKIE,cookie_data,8U},
      {ARG0,arg0_data,8U},
      {ARG1,arg1_data,8U},
      {SHOW,show_data,4U}
    };
    mx_cfg_memory memory={areas,5};
    uint64_t cookie_value=INIT_COOKIE;
    if(!mx_cfg_transfer(&memory,COOKIE,&cookie_value,8U,1))return 1;
    mx_main_prefix_state state={0};
    state.rip=BASE+UINT64_C(0x136710);
    state.rsp=START_RSP;
    state.rax=10U;
    state.rcx=BASE;
    state.rdx=0U;
    state.r8=UINT64_C(0x7200002c0);
    state.r9=10U;
    mx_main_prefix_layout layout={
       BASE+UINT64_C(0x136710),BASE+UINT64_C(0x136741),
       COOKIE,ARG0,ARG1,SHOW,0x288U,0x250U
    };
    int result=mx_main_execute_prefix(&state,&memory,&layout);
    if(result!=MX_MAIN_PREFIX_CALL_BOUNDARY)return 2;
    if(state.rip!=layout.call_site || state.rsp!=AFTER_RSP ||
       state.rax!=EXPECT_RAX || state.rcx!=EXPECT_RCX ||
       state.rdx!=0U || state.r8!=UINT64_C(0x7200002c0) ||
       state.r9!=10U || state.instructions!=8U)return 3;
    uint64_t saved_stack=0,arg0=0,arg1=0;
    uint32_t show=0U;
    if(!mx_cfg_transfer(&memory,AFTER_RSP+0x250U,&saved_stack,8U,0) ||
       !mx_cfg_transfer(&memory,ARG0,&arg0,8U,0) ||
       !mx_cfg_transfer(&memory,ARG1,&arg1,8U,0) ||
       !mx_cfg_transfer(&memory,SHOW,&show,4U,0))return 4;
    if(saved_stack!=EXPECT_STACK || arg0!=EXPECT_ARG0 ||
       arg1!=EXPECT_ARG1 || show!=EXPECT_SHOW)return 5;
    return 0;
}
#ifdef HOST
int main(void){return smoke();}
#endif
"""

def run(exe,reports):
    if not shutil.which("cc") or not shutil.which("clang"):
        raise RuntimeError("Both host CC and AArch64 clang are required")
    original=probe(exe,include_private_reference=True)
    ref=original.pop("_private_reference")
    if original["original_x64_instructions_executed"]!=8 or (
       original["first_transfer_rva"]!="0x136741" or
       original["first_transfer_target_rva"]!="0x136120"):
        raise RuntimeError("Original game-main entry shape changed")
    const={
        "COOKIE_V":ref["cookie_va"],"ARG0_V":ref["arg0_va"],
        "ARG1_V":ref["arg1_va"],"SHOW_V":ref["show_va"],
        "START_RSP_V":ref["initial_rsp"],"AFTER_RSP_V":ref["final_rsp"],
        "INIT_COOKIE_V":ref["initial_cookie"],
        "EXPECT_RAX_V":ref["final_rax"],"EXPECT_RCX_V":ref["final_rcx"],
        "EXPECT_STACK_V":ref["saved_stack_cookie"],
        "EXPECT_ARG0_V":ref["stored_arg0"],"EXPECT_ARG1_V":ref["stored_arg1"],
        "EXPECT_SHOW_V":ref["stored_show"]
    }
    source=SOURCE
    for name,value in const.items():
        # Match complete parenthesized tokens. Names such as COOKIE_V and
        # INIT_COOKIE_V overlap as substrings and must never be replaced
        # without token boundaries.
        target="("+name+")"
        if source.count(target)!=1:
            raise RuntimeError("Native fixture constant missing or ambiguous: "+name)
        source=source.replace(target,"("+str(value)+")")
    with tempfile.TemporaryDirectory(prefix="mxbikes-main-aot-") as td:
        work=Path(td)
        script=work/"original-main-first-block-derived.c"
        script.write_text(source)
        flags=["-O2","-std=c11","-Wall","-Wextra","-Werror",
               "-I",str(ROOT/"arm64-lab"/"runtime")]
        host=work/"host"
        subprocess.run(["cc",*flags,"-DHOST",str(script),"-o",str(host)],
                       check=True,capture_output=True,text=True)
        subprocess.run([str(host)],check=True,capture_output=True,text=True)
        arm=work/"original-main-first-block-aarch64.elf"
        subprocess.run(["clang","--target=aarch64-unknown-linux-gnu",
            "-fuse-ld=lld","-nostdlib","-static","-ffreestanding",
            "-fno-builtin","-fno-stack-protector",*flags,
            "-Wl,-e,smoke","-Wl,-z,max-page-size=4096",
            "-Wl,--build-id=none",str(script),"-o",str(arm)],
            check=True,capture_output=True,text=True)
        result=execute_arm64_elf(arm,instruction_budget=180000,
                                   timeout_us=4000000)
        if result.get("arm64_smoke_exit")!=0:
            raise RuntimeError("Original game-main translated ARM64 mismatch exit "+
                               str(result.get("arm64_smoke_exit")))
    reports.mkdir(parents=True,exist_ok=True)
    meta={
        "original_game_main_rva":original["game_main_entry_rva"],
        "first_direct_call_rva":original["first_transfer_rva"],
        "first_callee_rva":original["first_transfer_target_rva"],
        "original_x64_instructions_executed":8,
        "host_native_guest_effects_match_original":True,
        "aarch64_native_guest_effects_match_original":True,
        "original_game_callee_executed":False,
        "graphics_or_engine_initialized":False,
        "limitations":"Only first eight original x64 game-main instructions, with real registers and guest stores compared against native AArch64 ELF; game call not entered."
    }
    (reports/"main-first-native.json").write_text(json.dumps(meta,indent=2)+"\n")
    report="\n".join([
        "# MX Bikes — original game-main ARM64 first-block differential",
        "",
        "- Original game main RVA: **"+meta["original_game_main_rva"]+"**",
        "- Authentically executed x64 instructions: **8**",
        "- Native host and AArch64 agree with original guest-register and memory effects: **YES**",
        "- First original CALL reached but **not executed**: "+
           meta["first_direct_call_rva"]+" to "+meta["first_callee_rva"],
        "",
        "**Scope:** First original game-main block only. Engine, Windows services, rendering and iOS are not booted.",
        ""
    ])
    (reports/"main-first-native.md").write_text(report)
    print(report)

if __name__=="__main__":
    if len(sys.argv)!=3:
        raise SystemExit("usage: script.py owned-mxbikes.exe report-dir")
    run(Path(sys.argv[1]),Path(sys.argv[2]))
