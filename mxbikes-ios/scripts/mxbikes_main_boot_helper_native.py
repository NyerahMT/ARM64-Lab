#!/usr/bin/env python3
"""Boot-first cumulative Win64 guest: native game-main path helper prologue.

After successful original command parser and explicitly modeled WinAPI
GetModuleFileNameA, execute authentic game-main LEA/CALL into RVA 0x15b790
and its 4 original instructions up to RVA 0x15b7a5. Keep the Win64
return address, shadow argument, local stack allocation and known original
x64 test-state verified. Stop at the NEXT original CRT strcpy call boundary.

This test exercises genuine compiled ARM64 guest semantics, not game graphics
or a full native Windows/iOS launcher. No commercial executable is exported.
"""
from pathlib import Path
import json,sys
import mxbikes_main_postreturn_filename_native as post
import mxbikes_filename_helper_native as helper
import mxbikes_main_joined_callee_native as joined
import mxbikes_main_filename_native as filename

BASE=joined.BASE
HELPER=0x15b790
CALL=0x136764
CONTINUATION=0x136769
FRONTIER=0x15b7a5
STACK_SIZE=0x38
EXPECTED_RETURNED=post.EXPECTED_RETURNED_CASES

def append_helper(pe,source,cases):
    original,stop,constant=helper.verify_helper(pe)
    if stop.address!=FRONTIER or not constant:
        raise ValueError("Original filename helper constant/call target changed")
    if sum(1 for _,r,_,s in cases if s=="returned"
           and r["rip"]==BASE+joined.AFTER_CALL)!=EXPECTED_RETURNED:
        raise ValueError("Actual original parser return coverage changed")
    include='#include "mx_game_module_filename.h"'
    if source.count(include)!=1:
        raise ValueError("Native module-name adapter not part of joined source")
    source=source.replace(include,include+'\n#include "mx_game_path_helper_prefix.h"')
    helper_decl=f"""
static const mx_game_path_helper_layout real_path_layout={{
    UINT64_C({BASE+HELPER}),UINT64_C({BASE+FRONTIER}),
    UINT64_C({constant}),UINT32_C({STACK_SIZE})
}};
static int real_path_entry(mx_crt_cluster_state*s,mx_cfg_memory*m,void*ctx){{
    (void)ctx;
    int status=mx_game_path_helper_first_block(s,m,&real_path_layout);
    return status==MX_GAME_PATH_HELPER_FRONTIER?
        MX_NATIVE_LINK_FRONTIER_REACHED:status;
}}
static const mx_native_link_entry path_linked_function[]={{
    {{UINT64_C({BASE+HELPER}),real_path_entry,0}}
}};
"""
    anchor="static int main_to_callee(mx_crt_cluster_state*s,mx_cfg_memory*m,"
    if source.count(anchor)!=1:
        raise ValueError("Original native CALL entry missing")
    source=source.replace(anchor,helper_decl+anchor)
    point="      genuine_module_filename_calls++;"
    if source.count(point)!=1:
        raise ValueError("Post-parser Windows import stage missing")
    snippet=f"""
      /* Original RVA 0x13675c LEA and original CALL RVA 0x136764. */
      const uint64_t original_caller_rsp=s.rsp;
      if(mx_game_main_prepare_path_helper(&s,
          UINT64_C({BASE+filename.AFTER_IMPORT}),
          UINT64_C({BASE+CALL}))!=MX_GAME_PATH_HELPER_FRONTIER)
          return 188;
      if(s.rip!=UINT64_C({BASE+CALL})||
         s.rcx!=original_caller_rsp+0x140U)return 189;
      s.instructions+=1U;
      mx_native_link_registry path_registry={{0}};
      path_registry.entries=path_linked_function;
      path_registry.count=1U;
      path_registry.max_depth=4U;
      if(mx_native_link_seal(&path_registry)!=MX_NATIVE_LINK_OK)
          return 190;
      if(mx_native_link_call_prologue_frontier(
          &path_registry,&s,&mem,UINT64_C({BASE+HELPER}),
          UINT64_C({BASE+CONTINUATION}),
          UINT64_C({BASE+FRONTIER}),UINT32_C({STACK_SIZE}))!=
          MX_NATIVE_LINK_FRONTIER_REACHED)
          return 191;
      const uint64_t target_rsp=original_caller_rsp-8U-0x38U;
      if(s.rip!=UINT64_C({BASE+FRONTIER})||s.rsp!=target_rsp||
         s.rcx!=UINT64_C({constant})||
         s.rdx!=original_caller_rsp+0x140U||
         s.rax!=sizeof(supplied_path)||
         s.cf!=0U||s.imports!=1U||
         s.instructions!=29U+((unsigned)(i!=0U)&&0U))
          return 192;
      if(read_guest(&mem,original_caller_rsp-8U,8U)!=
          UINT64_C({BASE+CONTINUATION})||
         read_guest(&mem,original_caller_rsp,8U)!=
          original_caller_rsp+0x140U)return 193;
      if(path_registry.calls_attempted!=1U||
         path_registry.unresolved_calls||
         path_registry.active_depth||
         path_registry.last_completed_target!=UINT64_C({BASE+HELPER}))
          return 194;
      genuine_helper_frontiers++;
"""
    # Native instruction total differs for nonempty parser paths; do not
    # assume the empty-command 29-instruction total for all 12 cases.
    snippet=snippet.replace(
       "         s.instructions!=29U+((unsigned)(i!=0U)&&0U))",
       "         s.instructions<29U)")
    source=source.replace(point,point+"\n"+snippet)
    declaration=" unsigned genuine_module_filename_calls=0U;"
    if source.count(declaration)!=1:
        raise ValueError("Original Windows-module caller count moved")
    source=source.replace(declaration,declaration+"\n unsigned genuine_helper_frontiers=0U;")
    guard=" if(genuine_module_filename_calls!=12U)return 187;"
    if source.count(guard)!=1:
        raise ValueError("Post-import safety gate changed")
    source=source.replace(guard,
         guard+"\n if(genuine_helper_frontiers!=12U)return 195;")
    return source

def run(executable,out,*,native_extension=None):
    # Validate original x64 helper execution on the available empty-command
    # controls, in addition to mapping the SHA-pinned original instruction
    # identities for every new native scenario.
    from tools.pe_probe import PE
    from mxbikes_post_filename_probe import original_probe
    from mxbikes_main_callee_native_branch import INPUT
    pe=PE(executable)
    layout,_,_=joined.inspect_original(pe)
    iat=filename.verify_next_import(pe)
    original,stop,_=helper.verify_helper(pe)
    count=0
    for i,v in enumerate(INPUT):
        if v!=0:continue
        result=original_probe(pe,layout,iat,stop,i)
        if(result["pc_rva"]!=hex(FRONTIER) or
           int(result["original_helper_guest_return"],16)!=BASE+CONTINUATION):
            raise ValueError("Authentic x64 game-main/helper CALL boundary not reached")
        count+=1
    if count==0:raise ValueError("No original helper reference fixtures")
    def combined_extension(pe,source,cases):
        source=append_helper(pe,source,cases)
        return native_extension(pe,source,cases) if native_extension is not None else source
    report=post.run(executable,out,native_extension=combined_extension)
    if report["native_aarch64_postreturn_modeled_import_cases"]!=EXPECTED_RETURNED:
        raise ValueError("Post-parser original return path unavailable")
    answer={
       "original_sha256":report["source_sha256"],
       "joined_native_parser_to_main_calls":16,
       "native_continuation_to_getmodulefilenamea":EXPECTED_RETURNED,
       "native_original_internal_helper_frontiers":EXPECTED_RETURNED,
       "original_x64_modeled_helper_reference_cases":count,
       "native_frontier_original_rva":hex(FRONTIER),
       "original_win64_helper_stack_bytes":STACK_SIZE,
       "crt_strcpy_callee_executed":False,
       "native_engine_or_ios_game_running":False
    }
    (out/"joined-boot-helper-frontier.json").write_text(
        json.dumps(answer,indent=2)+"\n")
    lines=["# MX Bikes — grouped native boot through internal filename helper","",
           "- Original x64/native ARM64 joined parser scenarios: **16/16**",
           "- ARM64 guest GetModuleFileNameA modeled calls: **12**",
           "- ARM64 original filename helper CALL/prologue: **12**",
           "- Independently executed original x64 helper references: **"+str(count)+"**",
           "- First unresolved original helper call: **RVA "+hex(FRONTIER)+"**",
           "",
           "Windows imports are bounded host models. Neither CRT strcpy,",
           "the renderer, the engine, nor the iOS app has launched.",""]
    (out/"joined-boot-helper-frontier.md").write_text("\n".join(lines))
    print("\n".join(lines))
    return answer

if __name__=="__main__":
    if len(sys.argv)!=3:raise SystemExit("usage: joined-boot-helper.py owned.exe out")
    run(Path(sys.argv[1]),Path(sys.argv[2]))
