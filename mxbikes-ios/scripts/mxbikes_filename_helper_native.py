#!/usr/bin/env python3
"""Joined real-game main->callee->filename import->next internal nonleaf prologue.

Runs authentic original x64 through modeled GetModuleFileNameA to CALL at
0x15b7a5. Executes AArch64 equivalent from main entry, genuine Win64 CALL
to original 0x15b790, and 4 original helper prologue instructions.
Stops BEFORE original helper's next CALL into 0x2ab41a; does not claim that
routine, full function, game engine, renderer, or iOS app works.
"""
from pathlib import Path
import hashlib,json,subprocess,sys,tempfile
from capstone import Cs,CS_ARCH_X86,CS_MODE_64,CS_GRP_CALL
from capstone.x86 import X86_OP_IMM,X86_OP_MEM
from mxbikes_main_filename_native import (
 BASE,MAIN,AFTER_IMPORT,AFTER_CALL,CALL_IMPORT,EXE_SHA,
 verify_main,inspect_original,verify_next_import,
 original_run,generate_filename_stage,NUM_CASES,BYTE_CASES,
 PATH,PATH_LEN
)
from mxbikes_post_filename_probe import original_probe,discover
from mxbikes_next_internal_helper_probe import helper_first_frontier,EXPECTED_CALL,TARGET
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/"arm64-lab"))
from tools.pe_probe import PE
from tools.import_aot_smoke import execute_arm64_elf

NEXT_CALL=0x15b7a5
NEXT_TARGET=0x2ab41a
AFTER_HELPER_CALL=0x136769
MAX_TEST=5

def verify_helper(pe):
    main,ctrl=discover(pe)
    if(ctrl.address!=EXPECTED_CALL or ctrl.op_str!="0x15b790" or
       main["original_precontrol_instructions"]!=1):
        raise RuntimeError("Original game post-module helper CALL changed")
    helper,stop=helper_first_frontier(pe)
    expected=[
      ("mov","qword ptr [rsp + 8], rcx"),
      ("sub","rsp, 0x38"),
      ("mov","rdx, qword ptr [rsp + 0x40]"),
      ("lea","rcx, [rip + 0x23b0fb]")
    ]
    originals=[(item["mnemonic"],item["operands"])
                for item in helper["original_prefix_forms"]]
    if(originals!=expected or stop.address!=NEXT_CALL or
       stop.mnemonic!="call" or stop.operands[0].type!=X86_OP_IMM or
       int(stop.operands[0].imm)!=NEXT_TARGET or
       helper["prefix_instructions_before_control"]!=4):
        raise RuntimeError("Original game next internal helper prologue changed")
    md=Cs(CS_ARCH_X86,CS_MODE_64);md.detail=True
    instructions=list(md.disasm(pe.read_rva(TARGET,NEXT_CALL-TARGET),TARGET))
    if (len(instructions)!=4 or instructions[-1].address!=0x15b79e or
       instructions[-1].operands[1].type!=X86_OP_MEM or
       instructions[-1].reg_name(instructions[-1].operands[1].mem.base)!="rip"):
        raise RuntimeError("Original internal helper static RIP address invalid")
    constant=BASE+instructions[-1].address+instructions[-1].size+instructions[-1].operands[1].mem.disp
    return helper,stop,constant

C_NEXT=r'''
#include "mx_game_path_helper_prefix.h"
#define HELPER (BASE+UINT64_C(0x15b790))
#define HELPER_ENTRY_CALL (BASE+UINT64_C(0x136764))
#define HELPER_MAIN_RETURN (BASE+UINT64_C(0x136769))
#define HELPER_FIRST_TRANSFER (BASE+UINT64_C(0x15b7a5))
#define HELPER_CONSTANT UINT64_C(__HELPER_CONSTANT__)
#define HELPER_TESTS __HELPER_TESTS__U
typedef struct {
    uint32_t original_index;
    uint64_t rax,rdx,rcx,r8,r9,r10,rsp,rip;
    uint8_t cf,zf,sf;
    uint64_t saved_argument,original_return;
} helper_case;
static const helper_case helper_cases[HELPER_TESTS]={
__HELPER_CASES__
};
static mx_game_path_helper_layout helper_layout={
  HELPER,HELPER_FIRST_TRANSFER,HELPER_CONSTANT,0x38U
};
static int native_real_helper(
    mx_crt_cluster_state*s,mx_cfg_memory*m,void*unused){
    (void)unused;
    int result=mx_game_path_helper_first_block(s,m,&helper_layout);
    return result==MX_GAME_PATH_HELPER_FRONTIER?
       MX_NATIVE_LINK_FRONTIER_REACHED:result;
}
static const mx_native_link_entry linked_game_functions[2]={
    {CALLEE,native_callee_prefix,0},
    {HELPER,native_real_helper,0}
};
static int helper_smoke(void){
  mx_cfg_region areas[PAGE_COUNT+2U];
  areas[0].base=STACK;areas[0].data=stack_bytes;areas[0].length=131072U;
  areas[1].base=DATA;areas[1].data=input_data;areas[1].length=4096U;
  for(unsigned x=0;x<PAGE_COUNT;x++){
     areas[2U+x].base=mapped_original_pages[x];
     areas[2U+x].data=original_image_pages[x];
     areas[2U+x].length=4096U;
  }
  mx_cfg_memory guest={areas,PAGE_COUNT+2U};
  mx_native_link_registry registry={0};
  registry.entries=linked_game_functions;registry.count=2U;
  registry.max_depth=4U;
  if(mx_native_link_seal(&registry)!=MX_NATIVE_LINK_OK)return 30;
  mx_game_module_context module={host_module_path,MODULE_PATH_LEN};
  for(unsigned k=0;k<HELPER_TESTS;k++){
     const helper_case*t=&helper_cases[k];
     const fixture*b=&fixtures[t->original_index];
     if(b->in_byte)return 31;
     for(unsigned n=0;n<131072U;n++)stack_bytes[n]=0U;
     for(unsigned p=0;p<PAGE_COUNT;p++){
        for(unsigned n=0;n<4096U;n++)original_image_pages[p][n]=0U;
     }
     input_data[0x100U]=0U;
     uint64_t cookie=b->pre[0],arg0=b->pre[1],arg1=b->pre[2];
     uint64_t callee0=b->pre[4];
     uint32_t show=(uint32_t)b->pre[3],callee1=(uint32_t)b->pre[5];
     uint64_t main_return=BASE+UINT64_C(0x777777);
     if(!mx_cfg_transfer(&guest,COOKIE,&cookie,8U,1)||
        !mx_cfg_transfer(&guest,ARG0,&arg0,8U,1)||
        !mx_cfg_transfer(&guest,ARG1,&arg1,8U,1)||
        !mx_cfg_transfer(&guest,SHOW,&show,4U,1)||
        !mx_cfg_transfer(&guest,CALLEE_G0,&callee0,8U,1)||
        !mx_cfg_transfer(&guest,CALLEE_G1,&callee1,4U,1)||
        !mx_cfg_transfer(&guest,ENTRY_SP,&main_return,8U,1))
         return 32;
     mx_crt_cluster_state s={0};
     s.rip=MAIN;s.rsp=ENTRY_SP;
     s.rax=UINT64_C(0x888876543210)+t->original_index;
     s.rbx=UINT64_C(0x123456789abcd);
     s.rcx=BASE;s.rdx=0U;s.r8=TEST_INPUT;s.r9=10U;
     s.rdi=UINT64_C(0x5778899aabbcc);
     s.rsi=UINT64_C(0x1123456789abc);
     s.r11=UINT64_C(0x54111122223333);
     s.cf=0U;s.sf=0U;s.zf=0U;
     if(main_to_callee(&s,&guest,&registry)!=MX_NATIVE_LINK_OK||
        s.rip!=AFTER_CALL)return 33;
     if(mx_game_main_filename_prepare(&s,AFTER_CALL,IMPORT_CALL)!=
            MX_GAME_FILENAME_OK)return 34;
     if(mx_game_main_filename_import_call(&s,&guest,&module,
         IMPORT_CALL,AFTER_IMPORT)!=MX_GAME_FILENAME_OK)return 35;
     if(mx_game_main_prepare_path_helper(
         &s,AFTER_IMPORT,HELPER_ENTRY_CALL)!=MX_GAME_PATH_HELPER_FRONTIER)
        return 36;
     if(s.rcx!=s.rsp+0x140U ||s.rip!=HELPER_ENTRY_CALL)return 37;
     s.instructions+=1U; /* authentic original CALL at RVA 0x136764 */
     int status=mx_native_link_call_prologue_frontier(
        &registry,&s,&guest,HELPER,HELPER_MAIN_RETURN,
        HELPER_FIRST_TRANSFER,0x38U);
     if(status!=MX_NATIVE_LINK_FRONTIER_REACHED)return 38;
     if(s.rax!=t->rax||s.rdx!=t->rdx||s.rcx!=t->rcx||
        s.r8!=t->r8||s.r9!=t->r9||
        s.rsp!=t->rsp||s.rip!=t->rip||
        s.cf!=t->cf||s.zf!=t->zf||s.sf!=t->sf ||
        s.instructions!=29U)return 39;
     if(read_guest(&guest,ENTRY_SP-0x288U,8U)!=t->saved_argument||
        read_guest(&guest,ENTRY_SP-0x288U-8U,8U)!=t->original_return)
        return 40;
     if(t->original_return!=HELPER_MAIN_RETURN ||
        t->saved_argument!=ENTRY_SP-0x288U+0x140U)return 41;
     for(unsigned n=0;n<MODULE_PATH_LEN+1U;n++){
        uint8_t value=0U;
        if(!mx_cfg_transfer(&guest,ENTRY_SP-0x288U+0x140U+n,
                            &value,1U,0)||
           value!=host_module_path[n])return 42;
     }
     if(s.imports!=1U)return 43;
  }
  if(registry.unresolved_calls||registry.calls_completed!=HELPER_TESTS||
     registry.calls_attempted!=2U*HELPER_TESTS ||
     registry.active_depth)return 44;
  return 0;
}
'''

def generate_next_source(layout,joined_refs,module_refs,helper_cases,constant):
    src,_=generate_filename_stage(layout,joined_refs,module_refs)
    original_main='int smoke(void){int first=prior_smoke();return first?first:filename_smoke();}'
    if src.count(original_main)!=1:
        raise RuntimeError("GetModuleFileNameA native test wrapper changed")
    src=src.replace(original_main,
        'static int earlier_smoke(void){int first=prior_smoke();return first?first:filename_smoke();}')
    rows=[]
    for index,x in helper_cases:
        raw=x["registers"]
        numbers=[int(raw[k],16) for k in ("rax","rdx","rcx","r8","r9","r10","rsp","rip")]
        flags=raw["flags"]
        row=("{"+str(index)+","+
           ",".join("UINT64_C("+str(v)+")" for v in numbers)+","+
           ",".join(str(int(flags[k])) for k in ("cf","zf","sf"))+","+
           "UINT64_C("+str(int(x["original_helper_shadow_arg"],16))+"),"+
           "UINT64_C("+str(int(x["original_helper_guest_return"],16))+")}")
        rows.append(row)
    extra=C_NEXT
    extra=extra.replace("__HELPER_CONSTANT__",str(constant))
    extra=extra.replace("__HELPER_TESTS__",str(len(helper_cases)))
    extra=extra.replace("__HELPER_CASES__",",\n".join(rows))
    if "__HELPER_" in extra:raise RuntimeError("Unexpanded native helper fixture")
    src=src.replace("#ifdef HOST",
        extra+"\nint smoke(void){int prior=earlier_smoke();return prior?prior:helper_smoke();}\n#ifdef HOST")
    return src

def run(executable,out):
    pe=PE(executable)
    if hashlib.sha256(pe.b).hexdigest()!=EXE_SHA:
        raise RuntimeError("Original game SHA mismatch")
    verify_main(executable)
    layout,_,_=inspect_original(pe)
    slot=verify_next_import(pe)
    helper,stop,constant=verify_helper(pe)
    first_refs=[original_run(pe,layout,k) for k in range(NUM_CASES)]
    chosen=[k for k in range(NUM_CASES) if BYTE_CASES[k]==0]
    from mxbikes_main_filename_native import original_main_with_module_name
    name_refs=[(k,original_main_with_module_name(pe,layout,slot,k))
               for k in chosen]
    helper_refs=[(k,original_probe(pe,layout,slot,stop,k))
                 for k in chosen[:MAX_TEST]]
    for _,r in helper_refs:
        if(r["pc_rva"]!=hex(NEXT_CALL) or
           int(r["original_helper_guest_return"],16)!=BASE+AFTER_HELPER_CALL):
            raise RuntimeError("Original helper CALL boundary not proven")
    source=generate_next_source(layout,first_refs,name_refs,helper_refs,constant)
    with tempfile.TemporaryDirectory(prefix="mxb-next-game-call-") as td:
        root=Path(td);private=root/"private-original-real-game-helper.c"
        private.write_text(source)
        flags=["-std=c11","-O2","-Wall","-Wextra","-Werror",
               "-I",str(ROOT/"arm64-lab"/"runtime")]
        host=root/"host"
        p=subprocess.run(["cc",*flags,"-DHOST",str(private),"-o",str(host)],
                        capture_output=True,text=True)
        if p.returncode:raise RuntimeError("Host compiler: "+p.stderr[-3000:])
        p=subprocess.run([str(host)],capture_output=True,text=True)
        if p.returncode:raise RuntimeError("Host x64/native joined mismatch code "+str(p.returncode))
        arm=root/"original-x64-helper-arm64.elf"
        p=subprocess.run(["clang","--target=aarch64-unknown-linux-gnu",
           "-fuse-ld=lld","-nostdlib","-static","-ffreestanding",
           "-fno-stack-protector","-fno-builtin",*flags,
           "-Wl,-e,smoke","-Wl,-z,max-page-size=4096",
           "-Wl,--build-id=none",str(private),"-o",str(arm)],
           capture_output=True,text=True)
        if p.returncode:raise RuntimeError("ARM64 compiler: "+p.stderr[-3000:])
        result=execute_arm64_elf(arm,instruction_budget=1950000,timeout_us=15000000)
        if result["arm64_smoke_exit"]!=0:
            raise RuntimeError("Joined original game to native helper ARM64 mismatch")
    out.mkdir(parents=True,exist_ok=True)
    report={
        "original_executable_sha_verified":True,
        "game_main_after_filename_lea_advanced":True,
        "original_main_call_rva":hex(EXPECTED_CALL),
        "original_internal_callee_rva":hex(TARGET),
        "original_helper_first_control_rva":hex(NEXT_CALL),
        "original_helper_first_control_target_rva":hex(NEXT_TARGET),
        "additional_joined_original_instructions":6,
        "native_arm64_end_to_end_cases":len(helper_refs),
        "original_x64_reference_cases":len(helper_refs),
        "guest_shadow_argument_and_return_slot_differential":True,
        "callee_retained_original_prologue_stack_adjustment":0x38,
        "native_next_original_callee_0x2ab41a_executed":False,
        "complete_original_helper_executed":False,
        "game_engine_initialized":False,
        "scope":"Game main through first native helper prologue and next original direct-call boundary; no downstream function execution"
    }
    (out/"postfilename-helper-native.json").write_text(json.dumps(report,indent=2)+"\n")
    summary="\n".join([
       "# MX Bikes — joined original filename helper on native ARM64","",
       "- Original main internal CALL: **0x136764 → 0x15b790**",
       "- New original instructions connected natively: **6** (main LEA, CALL, four helper prologue instructions)",
       "- Original x64 vs AArch64 guest-state differential: **"+str(len(helper_refs))+"/"+str(len(helper_refs))+"**",
       "- Guest shadow argument and original CALL return slot match: **YES**",
       "- Original callee-local 0x38-byte stack allocation preserved: **YES**",
       "- Next direct original internal call boundary: **0x15b7a5 → 0x2ab41a**",
       "",
       "**Stops before executing the original 0x2ab41a callee. Neither the full filename helper nor the game engine has run.**",""
    ])
    (out/"postfilename-helper-native.md").write_text(summary)
    print(summary)
    return report

if __name__=="__main__":
    if len(sys.argv)!=3:raise SystemExit("usage: joined-helper.py original-exe metadata-dir")
    run(Path(sys.argv[1]),Path(sys.argv[2]))
