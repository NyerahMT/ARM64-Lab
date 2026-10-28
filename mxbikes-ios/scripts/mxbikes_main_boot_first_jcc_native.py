#!/usr/bin/env python3
"""Boot-first ARM64 original filename scan after modeled strcpy: MOVSX/TEST/JE.

This stage extends the 12 genuine game-main callee returns from the previous
cumulative native stage, reading the first copied path byte through the
original Win64 guest memory map, and executing original x64 0x15b7cf->0x15b7db
branch semantics on real AArch64. Other branch outcomes are independently
verified from original x64 and retained in the historical native regression.
"""
import json,sys
from pathlib import Path
import mxbikes_main_boot_strcpy_native as prior
import mxbikes_after_strcpy_branch_native as scan
import mxbikes_joined_strcpy_native as originals
import mxbikes_main_joined_callee_native as joined
import mxbikes_main_filename_native as filename
import mxbikes_msvcr90_strcpy_native as crt

BASE=joined.BASE
COUNT=prior.COUNT

def append_branch(pe,source,cases):
    scan.verify_branch(pe)
    _,dest=crt.original_thunk(pe)
    if sum(status=="returned" and r["rip"]==BASE+joined.AFTER_CALL
           for _,r,_,status in cases)!=COUNT:
        raise ValueError("Original startup no longer covers 12 real CALL returns")
    include='#include "mx_game_path_after_strcpy.h"'
    if source.count(include)!=1:
        raise ValueError("Previously proven native post-copy block missing")
    source=source.replace(include,include+'\n#include "mx_game_path_after_strcpy_branch.h"')
    definition=f"""
static const mx_game_path_after_strcpy_branch_layout original_path_branch={{
 UINT64_C({BASE+scan.START}),UINT64_C({BASE+scan.TAKEN}),
 UINT64_C({BASE+scan.FALLTHROUGH})
}};
"""
    anchor="static int main_to_callee(mx_crt_cluster_state*s,mx_cfg_memory*m,"
    if source.count(anchor)!=1:raise ValueError("Original native guest-entry moved")
    source=source.replace(anchor,definition+anchor)
    decl=" unsigned genuine_copy_frontiers=0U;"
    if source.count(decl)!=1:
        raise ValueError("Native cumulative copy count missing")
    source=source.replace(decl,decl+"\n unsigned genuine_branch_frontiers=0U;")
    point="      genuine_copy_frontiers++;"
    if source.count(point)!=1:
        raise ValueError("Original strcpy/post-copy native code missing")
    new=f"""
      const unsigned prior_branch_instr=s.instructions;
      mx_game_path_after_strcpy_branch_result branch={{0}};
      if(mx_game_path_after_strcpy_branch(&s,&mem,
              &original_path_branch,&branch)!=MX_GAME_PATH_BRANCH_REACHED)
          return 204;
      if(s.rip!=UINT64_C({BASE+scan.FALLTHROUGH})||
         s.rsp!=before_copy_rsp||
         s.rax!=(uint64_t)supplied_path[0]||
         s.cf!=0U||s.zf!=0U||s.sf!=0U||
         branch.branch_taken||branch.source_byte!=supplied_path[0]||
         branch.source_pointer!=UINT64_C({dest})||
         s.instructions!=prior_branch_instr+4U||
         s.imports!=2U)return 205;
      genuine_branch_frontiers++;
"""
    source=source.replace(point,point+"\n"+new)
    stop=" if(genuine_copy_frontiers!=12U)return 203;"
    if source.count(stop)!=1:
        raise ValueError("Native string-copy safety gate missing")
    source=source.replace(stop,stop+"\n if(genuine_branch_frontiers!=12U)return 206;")
    return source

def run(executable,out,*,native_extension=None):
    from tools.pe_probe import PE
    pe=PE(executable)
    first=filename.verify_next_import(pe)
    second,dest=crt.original_thunk(pe)
    scan.verify_branch(pe)
    count=0
    for i,byte in zip(originals.CASES,scan.INPUTS):
        result=scan.original_branch(pe,first,second,dest,i,byte)
        if result["rip"] not in (BASE+scan.TAKEN,BASE+scan.FALLTHROUGH):
            raise ValueError("Original x64 scanner branch escaped validated endpoints")
        count+=1
    if count!=5:raise ValueError("Original x64 signed-branch proof count changed")
    def combined_extension(pe,source,cases):
        source=append_branch(pe,source,cases)
        return native_extension(pe,source,cases) if native_extension is not None else source
    report=prior.run(executable,out,native_extension=combined_extension)
    if report["cumulative_arm64_filename_helper_strcpy_postjmp_cases"]!=COUNT:
        raise ValueError("Previous native cumulative boot frontier regressed")
    data={
       "original_sha256":report["original_sha256"],
       "native_arm64_original_game_main_guest_scenarios":16,
       "native_arm64_filename_strcpy_normal_branch_scenarios":COUNT,
       "independently_executed_original_x64_signed_character_cases":count,
       "native_first_original_filename_branch_next_rva":hex(scan.FALLTHROUGH),
       "original_x64_zero_branch_rva":hex(scan.TAKEN),
       "unexecuted_full_engine_or_ios_binary":True,
       "modeled_guest_imports_not_actual_windows_dll":True
    }
    (out/"joined-native-boot-filename-branch.json").write_text(json.dumps(data,indent=2)+"\n")
    lines=["# MX Bikes cumulative native game-main startup: filename branch","",
       "- Original game-main parser x64/ARM64: **16/16**",
       "- Native filename/module/helper/strcpy/branch progression: **12/12**",
       "- Original x64 bounded signed-byte comparison cases: **5/5**",
       "- Original next native game helper instruction frontier: **"+
          hex(scan.FALLTHROUGH)+"**","",
       "This is real AArch64 execution with modeled Win64/CRT APIs,",
       "not a booted game engine or iOS app.",""]
    (out/"joined-native-boot-filename-branch.md").write_text("\n".join(lines))
    print("\n".join(lines))
    return data

if __name__=="__main__":
    if len(sys.argv)!=3:raise SystemExit("usage: first-jcc.py original.exe output")
    run(Path(sys.argv[1]),Path(sys.argv[2]))
