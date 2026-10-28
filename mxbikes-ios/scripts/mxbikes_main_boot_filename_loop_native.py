#!/usr/bin/env python3
"""Batch-link original x64 filename separator and multiple loop iterations on ARM64.

16 original command-parser scenarios, 12 genuine main returns. All 12
native main->module filename->helper->strcpy paths run original separator
checks and two loop backedges through C, ':' and '\\', stopping at original
backslash separator RVA 0x15B7F5. Original x64 full chain with same path
is independently executed to this exact frontier. Bounded guest APIs only.
"""
import json,sys
from pathlib import Path
import mxbikes_main_boot_first_jcc_native as prior
import mxbikes_main_joined_callee_native as joined
import mxbikes_main_filename_native as filename
import mxbikes_main_boot_strcpy_native as copied
import mxbikes_after_strcpy_branch_native as x64
import mxbikes_filename_separator_native as separator
import mxbikes_filename_normal_loop_native as normal
import mxbikes_msvcr90_strcpy_native as crt

BASE=joined.BASE
COUNT=prior.COUNT
FINAL=0x15b7f5
HEADER=0x15b7c1
NORMAL=0x15b7db
SLASH=0x15b7e8

def append_loop(pe,source,cases):
    separator.validate_original(pe)
    normal.validate_source(pe)
    if tuple(filename.PATH[:3])!=(67,58,92):
        raise ValueError("Model fixture filename no longer begins C-colon-backslash")
    _,dest=crt.original_thunk(pe)
    if sum(k=="returned" and r["rip"]==BASE+joined.AFTER_CALL
           for _,r,_,k in cases)!=COUNT:
        raise ValueError("Real original callee return count changed")
    anchor='#include "mx_game_path_after_strcpy_branch.h"'
    if source.count(anchor)!=1:
        raise ValueError("Original signed-byte startup stage missing")
    source=source.replace(anchor,anchor+
       '\n#include "mx_game_path_separator_branch.h"'+
       '\n#include "mx_game_path_slash_loop.h"'+
       '\n#include "mx_game_filename_loop_iteration.h"')
    layouts=f"""
static const mx_game_path_separator_layout normal_separator={{
 UINT64_C({BASE+NORMAL}),UINT64_C({BASE+0x15b801}),
 UINT64_C({BASE+FINAL}),UINT64_C({BASE+SLASH}),
 UINT64_C({BASE+0x15b81b}),UINT64_C({BASE+0x15b809})
}};
static const mx_game_slash_loop_layout normal_slash={{
 UINT64_C({BASE+SLASH}),UINT64_C({BASE+FINAL}),
 UINT64_C({BASE+HEADER})
}};
static const mx_game_filename_iteration_layout real_path_iteration={{
 UINT64_C({BASE+HEADER}),UINT64_C({BASE+0x15b801}),
 UINT64_C({BASE+NORMAL})
}};
"""
    before="static int main_to_callee(mx_crt_cluster_state*s,mx_cfg_memory*m,"
    if source.count(before)!=1:raise ValueError("Guest native linker declaration changed")
    source=source.replace(before,layouts+before)
    inc=" unsigned genuine_branch_frontiers=0U;"
    if source.count(inc)!=1:raise ValueError("First signed-byte test count missing")
    source=source.replace(inc,inc+"\n unsigned genuine_path_separator_frontiers=0U;")
    destptr="      genuine_branch_frontiers++;"
    if source.count(destptr)!=1:
        raise ValueError("First filename branch genuine execution missing")
    c=f"""
      /* Original filename path: C, :, backslash. Reuse verified guest helpers.
       * 0x15b7db separator '\\\\'; 0x15b7e8 slash '/', 0x15b7c1 increment.
       */
      const unsigned before_scan=s.instructions;
      for(unsigned character=0U;character<3U;character++){{
          mx_game_path_separator_result sep={{0}};
          if(s.rip!=UINT64_C({BASE+NORMAL})||
             mx_game_path_separator_branch(&s,&mem,
                   &normal_separator,&sep)!=MX_GAME_SEPARATOR_FRONTIER)
             return 207;
          if(sep.zero_path||sep.normalized_byte!=supplied_path[character]||
             sep.branch_taken!=(character==2U))
             return 208;
          if(character==2U){{
              if(s.rip!=UINT64_C({BASE+FINAL}))return 209;
              break;
          }}
          if(s.rip!=UINT64_C({BASE+SLASH})||
             mx_game_slash_loop(&s,&mem,&normal_slash)!=
                MX_GAME_SLASH_LOOP_REACHED||
             s.rip!=UINT64_C({BASE+HEADER}))
              return 210;
          mx_game_filename_iteration_result iteration={{0}};
          if(mx_game_filename_loop_iteration(&s,&mem,
               &real_path_iteration,&iteration)!=MX_GAME_LOOP_ITERATION_REACHED||
             iteration.zero_branch||iteration.next_character!=
                  supplied_path[character+1U]||
             iteration.original_next_pointer!=UINT64_C({dest})+character+1U||
             s.rip!=UINT64_C({BASE+NORMAL}))
              return 211;
      }}
      if(s.rip!=UINT64_C({BASE+FINAL})||
         read_guest(&mem,before_copy_rsp+0x28U,8U)!=UINT64_C({dest})+2U||
         s.rax!=UINT64_C(0x5c)||s.zf!=1U||s.cf!=0U||s.sf!=0U||
         s.instructions!=before_scan+36U||s.imports!=2U||
         s.rsp!=before_copy_rsp)return 212;
      genuine_path_separator_frontiers++;
"""
    source=source.replace(destptr,destptr+"\n"+c)
    gate=" if(genuine_branch_frontiers!=12U)return 206;"
    if source.count(gate)!=1:raise ValueError("Native baseline branch gate missing")
    source=source.replace(gate,gate+
       "\n if(genuine_path_separator_frontiers!=12U)return 213;")
    return source

def run(executable,out,*,native_extension=None):
    from tools.pe_probe import PE
    pe=PE(executable)
    first=filename.verify_next_import(pe)
    second,dest=crt.original_thunk(pe)
    separator.validate_original(pe)
    normal.validate_source(pe)
    actual=x64.original_branch(pe,first,second,dest,
          copied.original_copy.CASES[0],filename.PATH[0],
          follow_successor=True,follow_slash_loop=True,
          follow_loop_iteration=True,follow_second_loopback=True,
          follow_third_backslash=True)
    if (actual["rip"]!=BASE+FINAL or actual["pointer"]!=dest+2 or
        actual["rax"]!=92 or not actual["zf"]):
        raise ValueError("Original x64 three-character parser boundary diverged")
    def combined_extension(pe,source,cases):
        source=append_loop(pe,source,cases)
        return native_extension(pe,source,cases) if native_extension is not None else source
    result=prior.run(executable,out,native_extension=combined_extension)
    if result["native_arm64_filename_strcpy_normal_branch_scenarios"]!=COUNT:
        raise ValueError("Earlier native original x64 path regressed")
    record={
       "original_SHA256":result["original_sha256"],
       "cumulative_original_game_main_parser_native_arm64":16,
       "cumulative_three_filename_characters_native_arm64":COUNT,
       "independent_original_x64_three_character_reference":1,
       "original_first_separator_found_rva":hex(FINAL),
       "original_next_filename_loop_backedges_executed":2,
       "original_file_parser_completed":False,
       "game_engine_or_ios_app_running":False}
    (out/"joined-native-boot-filename-loop.json").write_text(json.dumps(record,indent=2)+"\n")
    summary=["# MX Bikes original filename scanner joined ARM64","",
      "- Original startup command parser x64/ARM64: **16/16**",
      "- Native joined filename/helper/CRT separator progression: **12/12**",
      "- Original x64 checked through third character/backslash: **PASS**",
      "- Native original filename backedges executed per case: **2**",
      "- New original x64 frontend boundary: **"+hex(FINAL)+"**","",
      "Uses modeled Win64 imports. No full game engine, menu or IPA.",""]
    (out/"joined-native-boot-filename-loop.md").write_text("\n".join(summary))
    print("\n".join(summary))
    return record

if __name__=="__main__":
    if len(sys.argv)!=3:raise SystemExit("usage: boot-filename-loop.py original.exe out")
    run(Path(sys.argv[1]),Path(sys.argv[2]))
