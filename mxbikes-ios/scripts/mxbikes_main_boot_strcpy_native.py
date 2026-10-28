#!/usr/bin/env python3
"""Advance the native Win64-guest MX Bikes startup through strcpy and helper JMP.

Cumulative 16 input cases from genuine original game-main CALL; for 12
returning cases run modeled GetModuleFileNameA, genuine helper prologue,
modeled original MSVCR90!strcpy thunk and original post-copy instructions.
Retain bounded original x64 end-to-end references. No engine/IPA boot.
"""
import json,sys
from pathlib import Path
import mxbikes_main_boot_helper_native as boot
import mxbikes_main_joined_callee_native as joined
import mxbikes_msvcr90_strcpy_native as crt
import mxbikes_post_strcpy_native as postcopy
import mxbikes_post_strcpy_probe as original_postcopy
import mxbikes_joined_strcpy_native as original_copy
import mxbikes_main_filename_native as filename

BASE=joined.BASE
COUNT=boot.EXPECTED_RETURNED

def append_strcpy(pe,source,cases):
    _,destination=crt.original_thunk(pe)
    _,stop,constant=postcopy.verify_source(pe)
    if destination!=BASE+0x3968a0 or constant!=BASE+0x3968a0 or stop.address!=0x15b7bf:
        raise ValueError("Original internal strcpy destination/post-copy instruction identity changed")
    returns=sum(status=="returned" and row["rip"]==BASE+joined.AFTER_CALL
                for _,row,_,status in cases)
    if returns!=COUNT:raise ValueError("Original startup call returns changed")
    layout,_,_=joined.inspect_original(pe)
    previous={layout[k]&~4095 for k in ("cookie_va","arg0_va","arg1_va",
                     "show_va","callee_global0","callee_global1")}
    if destination&~4095 in previous:
        raise ValueError("Guest copy target overlaps original guest PE fixture page")
    inc='#include "mx_game_path_helper_prefix.h"'
    if source.count(inc)!=1:raise ValueError("Previous genuine filename helper missing")
    source=source.replace(inc,inc+
             '\n#include "mx_game_crt_strcpy.h"\n#include "mx_game_path_after_strcpy.h"')
    static=f"""
static uint8_t guest_copy_destination[4096U];
static const mx_game_path_after_strcpy_layout real_after_copy={{
 UINT64_C({BASE+crt.RETURN}),UINT64_C({constant}),
 UINT64_C({BASE+postcopy.NEXT})
}};
"""
    anchor="static int main_to_callee(mx_crt_cluster_state*s,mx_cfg_memory*m,"
    if source.count(anchor)!=1:raise ValueError("Joined native entry moved")
    source=source.replace(anchor,static+anchor)
    old="mx_cfg_region regions[PAGE_COUNT+2U];"
    if source.count(old)!=1:raise ValueError("Prior native guest region count changed")
    source=source.replace(old,"mx_cfg_region regions[PAGE_COUNT+3U];")
    mapping=" mx_cfg_memory mem={regions,PAGE_COUNT+2U};"
    newmap=f""" regions[PAGE_COUNT+2U].base=UINT64_C({destination&~4095});
 regions[PAGE_COUNT+2U].data=guest_copy_destination;
 regions[PAGE_COUNT+2U].length=4096U;
 mx_cfg_memory mem={{regions,PAGE_COUNT+3U}};"""
    if source.count(mapping)!=1:raise ValueError("Prior native guest map missing")
    source=source.replace(mapping,newmap)
    reset="   input_data[0x100U]=f->in_byte;"
    if source.count(reset)!=1:raise ValueError("Original per-test reset moved")
    source=source.replace(reset,
         "   for(unsigned n=0;n<4096U;n++)guest_copy_destination[n]=0U;\n"+reset)
    count=" unsigned genuine_helper_frontiers=0U;"
    if source.count(count)!=1:raise ValueError("Original helper counter moved")
    source=source.replace(count,count+"\n unsigned genuine_copy_frontiers=0U;")
    point="      genuine_helper_frontiers++;"
    if source.count(point)!=1:raise ValueError("Original helper execution location moved")
    native=f"""
      /* Original 0x15b7a5 CALL -> 0x2ab41a imported JMP/CRT RET. */
      const uint64_t before_copy_rsp=s.rsp;
      const unsigned before_copy_instructions=s.instructions;
      if(s.rip!=UINT64_C({BASE+crt.CALL})||
         s.rcx!=UINT64_C({destination})||
         s.rdx!=original_caller_rsp+0x140U)return 196;
      if(mx_game_crt_strcpy_import_call(&s,&mem,
          UINT64_C({BASE+crt.CALL}),UINT64_C({BASE+crt.THUNK}),
          UINT64_C({BASE+crt.RETURN}),260U)!=MX_GAME_STRCPY_OK)
          return 197;
      if(s.rip!=UINT64_C({BASE+crt.RETURN})||
         s.rsp!=before_copy_rsp||s.rax!=UINT64_C({destination})||
         s.imports!=2U||s.instructions!=before_copy_instructions+3U||
         read_guest(&mem,before_copy_rsp-8U,8U)!=UINT64_C({BASE+crt.RETURN}))
         return 198;
      for(unsigned n=0U;n<sizeof(supplied_path);n++){{
          uint8_t actual=0U;
          if(!mx_cfg_transfer(&mem,UINT64_C({destination})+n,
                    &actual,1U,0)||actual!=supplied_path[n])
             return 199;
      }}
      uint8_t zero_byte=255U;
      if(!mx_cfg_transfer(&mem,UINT64_C({destination})+
           sizeof(supplied_path),&zero_byte,1U,0)||zero_byte!=0U)
          return 200;
      const unsigned before_jump=s.instructions;
      if(mx_game_path_after_strcpy(&s,&mem,&real_after_copy)!=
             MX_GAME_PATH_AFTER_STRCPY_FRONTIER)return 201;
      if(s.rip!=UINT64_C({BASE+postcopy.NEXT})||
         s.rsp!=before_copy_rsp||s.rax!=UINT64_C({constant})||
         s.instructions!=before_jump+4U||
         read_guest(&mem,before_copy_rsp+0x20U,8U)!=0U||
         read_guest(&mem,before_copy_rsp+0x28U,8U)!=
           UINT64_C({constant}))return 202;
      genuine_copy_frontiers++;
"""
    source=source.replace(point,point+"\n"+native)
    gate=" if(genuine_helper_frontiers!=12U)return 195;"
    if source.count(gate)!=1:raise ValueError("Original helper safety gate moved")
    source=source.replace(gate,gate+"\n if(genuine_copy_frontiers!=12U)return 203;")
    return source

def run(executable,out,*,native_extension=None):
    from tools.pe_probe import PE
    pe=PE(executable)
    first_iat=filename.verify_next_import(pe)
    second_iat,destination=crt.original_thunk(pe)
    _,stop,constant=postcopy.verify_source(pe)
    layout,_,_=joined.inspect_original(pe)
    checked=[]
    for index in original_copy.CASES:
        earlier=original_copy.original_joined(pe,layout,first_iat,
                         second_iat,destination,index)
        later=original_postcopy.reference(pe,first_iat,second_iat,
                destination,stop,index,execute_direct_jump=True)
        if(earlier["rip"]!=BASE+crt.RETURN or
           later["numeric_registers"]["rip"]!=BASE+postcopy.NEXT or
           later["stack_qword_0"]!=0 or
           later["stack_qword_1"]!=constant):
            raise ValueError("Original x64 modeled CRT and helper-JMP reference drift")
        checked.append(index)
    if len(checked)!=5:
        raise ValueError("Original complete x64 strcpy reference test count changed")
    def combined_extension(pe,source,cases):
        source=append_strcpy(pe,source,cases)
        return native_extension(pe,source,cases) if native_extension is not None else source
    result=boot.run(executable,out,native_extension=combined_extension)
    if result["native_original_internal_helper_frontiers"]!=COUNT:
        raise ValueError("Previously linked helper path failed")
    report={
       "original_sha256":result["original_sha256"],
       "cumulative_x64_to_arm64_main_parser_cases":16,
       "cumulative_arm64_filename_helper_strcpy_postjmp_cases":COUNT,
       "independent_original_x64_end_to_end_strcpy_and_postjmp_cases":len(checked),
       "native_guest_original_postcopy_jump_rva":hex(postcopy.NEXT),
       "guest_windows_and_crt_services_explicitly_modeled":True,
       "full_game_engine_started":False,"iphone_ipa_produced":False
    }
    (out/"joined-native-boot-strcpy.json").write_text(json.dumps(report,indent=2)+"\n")
    lines=["# MX Bikes — connected original startup through native CRT strcpy","",
         "- Original game-main/callee ARM64 differential: **16/16**",
         "- ARM64 filename/helper/strcpy/post-copy paths: **12/12**",
         "- Independent original x64 modeled reference paths: **5/5**",
         "- First unresolved original helper continuation: **"+
            hex(postcopy.NEXT)+"**","",
         "Original imported DLL implementations are modeled, not executed.",
         "The game engine, renderer and iOS IPA are not running.",""]
    (out/"joined-native-boot-strcpy.md").write_text("\n".join(lines))
    print("\n".join(lines))
    return report

if __name__=="__main__":
    if len(sys.argv)!=3:raise SystemExit("usage: original-boot-strcpy.py owned.exe out")
    run(Path(sys.argv[1]),Path(sys.argv[2]))
