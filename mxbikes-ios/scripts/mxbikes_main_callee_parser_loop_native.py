#!/usr/bin/env python3
"""Group the original quoted/unquoted argument scanner loops in linked AArch64.

From proven x64 original game-main->CALL->0x136120, translate original
0x13619f CMP AL,0x22/JE, 0x1361a3 INC RDX/CMP [RDX],R9B/JNE,
0x1361e4 CMP AL,0x7E/JG and 0x1361e8 MOV AL,[RCX+1]/INC RCX/
TEST AL,AL/JNE. These converge on bounded future loop entries, without
inventing a full function return or boot result.
"""
from pathlib import Path
import hashlib,json,subprocess,sys,tempfile
import mxbikes_main_callee_branch_pair_native as pair
import mxbikes_main_callee_branch_pair_map as mapping
import mxbikes_main_callee_three_branches_native as before
import mxbikes_main_callee_next_pair_native as prev
import mxbikes_main_callee_arg_group_native as argv
import mxbikes_main_callee_quote_jne_native as quote
import mxbikes_main_callee_followup_native as followup
import mxbikes_main_callee_third_jle_native as third
import mxbikes_main_callee_second_jge_native as second
import mxbikes_main_joined_callee_native as joined
from mxbikes_main_callee_native_branch import INPUT
from mxbikes_whole_game_map import INPUT_SHA

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/"arm64-lab"))
from tools.pe_probe import PE
from tools.import_aot_smoke import execute_arm64_elf

QUOTE_CMP=0x13619f
QUOTE_SCAN=0x1361a3
UNQUOTED_CMP=0x1361e4
UNQUOTED_SCAN=0x1361e8
QUOTE_DONE=0x1361ad
QUOTE_JUMP=0x1361ab
QUOTE_JOIN=0x1361b9
QUOTE_BACKEDGE=0x136194
UNQUOTED_BACKEDGE=0x1361e0
UNQUOTED_DONE=0x1361f2
STOPPED=(QUOTE_DONE,QUOTE_BACKEDGE,QUOTE_JOIN,UNQUOTED_BACKEDGE,UNQUOTED_DONE)


def verify_original_loops(pe):
    steps=(
        (QUOTE_CMP,[("cmp","al, 0x22")],0x1361a1,"je",QUOTE_DONE,QUOTE_SCAN),
        (QUOTE_SCAN,[("inc","rdx"),("cmp","byte ptr [rdx], r9b")],
         0x1361a9,"jne",QUOTE_BACKEDGE,QUOTE_JUMP),
        (QUOTE_JUMP,[],0x1361ab,"jmp",QUOTE_JOIN,QUOTE_DONE),
        (UNQUOTED_CMP,[("cmp","al, 0x7e")],
         0x1361e6,"jg",UNQUOTED_DONE,UNQUOTED_SCAN),
        (UNQUOTED_SCAN,[("mov","al, byte ptr [rcx + 1]"),
                        ("inc","rcx"),("test","al, al")],
         0x1361f0,"jne",UNQUOTED_BACKEDGE,UNQUOTED_DONE))
    rows=[]
    for entry,forms,pc,kind,taken,fall in steps:
        row=mapping.first_control(pe,entry)
        if ([(x["mnemonic"],x["op_str"]) for x in row["instruction_forms"]]!=forms or
            row["control_rva"]!=hex(pc) or row["control_kind"]!=kind or
            row["control_direct_target_rva"]!=hex(taken) or
            row["control_next_rva"]!=hex(fall)):
            raise ValueError("SHA-pinned original quote/argument scanner loop changed")
        rows.append(row)
    return rows


def extend_native(source):
    """Hook established JG/JLE stages into one bounded loop dispatcher."""
    mark="static int native_three_controls(mx_crt_cluster_state*s,mx_cfg_memory*m){"
    if source.count(mark)!=1:raise ValueError("Original three-control translator missing")
    helper=f"""
static int native_loop_edges(mx_crt_cluster_state*s,mx_cfg_memory*m){{
 if(!s||!m||s->fault)return MX_GAME_PREFIX_BAD_STATE;
 if(s->rip==UINT64_C({joined.BASE+QUOTE_CMP})){{
   /* Original CMP AL,0x22 / JE. */
   const uint8_t v=(uint8_t)s->rax;
   const uint8_t d=(uint8_t)(v-34U);
   s->cf=(uint8_t)(v<34U);s->zf=(uint8_t)(d==0U);
   s->sf=(uint8_t)(d>>7U);
   s->rip=s->zf?UINT64_C({joined.BASE+QUOTE_DONE}):
                 UINT64_C({joined.BASE+QUOTE_SCAN});
   s->instructions+=2U;
   if(s->zf)return MX_NATIVE_LINK_FRONTIER_REACHED;
 }}
 if(s->rip==UINT64_C({joined.BASE+QUOTE_SCAN})){{
   /* Original INC RDX, CMP BYTE PTR [RDX],R9B; JNE. */
   if(s->rdx==UINT64_MAX)return MX_GAME_PREFIX_BAD_STATE;
   s->rdx+=1U;
   uint8_t v=0U;
   if(!mx_cfg_transfer(m,s->rdx,&v,1U,0))
      return MX_GAME_PREFIX_UNMAPPED;
   const uint8_t r=(uint8_t)s->r9;
   const uint8_t d=(uint8_t)(v-r);
   s->cf=(uint8_t)(v<r);s->zf=(uint8_t)(d==0U);
   s->sf=(uint8_t)(d>>7U);
   s->rip=s->zf?UINT64_C({joined.BASE+QUOTE_JUMP}):
                 UINT64_C({joined.BASE+QUOTE_BACKEDGE});
   s->instructions+=3U;
   if(s->zf){{
      s->rip=UINT64_C({joined.BASE+QUOTE_JOIN});
      s->instructions+=1U;
   }}
   return MX_NATIVE_LINK_FRONTIER_REACHED;
 }}
 if(s->rip==UINT64_C({joined.BASE+UNQUOTED_CMP})){{
   /* Original CMP AL,0x7E; signed JG. */
   uint8_t v=(uint8_t)s->rax,d=(uint8_t)(v-126U);
   uint8_t of=(uint8_t)((((v^126U)&(v^d))>>7U)&1U);
   s->cf=(uint8_t)(v<126U);s->zf=(uint8_t)(d==0U);
   s->sf=(uint8_t)(d>>7U);
   s->rip=(!s->zf&&s->sf==of)?
       UINT64_C({joined.BASE+UNQUOTED_DONE}):
       UINT64_C({joined.BASE+UNQUOTED_SCAN});
   s->instructions+=2U;
   if(s->rip==UINT64_C({joined.BASE+UNQUOTED_DONE}))
      return MX_NATIVE_LINK_FRONTIER_REACHED;
 }}
 if(s->rip==UINT64_C({joined.BASE+UNQUOTED_SCAN})){{
   /* Original MOV AL,[RCX+1]; INC RCX; TEST AL,AL; JNE. */
   if(s->rcx==UINT64_MAX)return MX_GAME_PREFIX_BAD_STATE;
   uint8_t value=0U;
   if(!mx_cfg_transfer(m,s->rcx+1U,&value,1U,0))
      return MX_GAME_PREFIX_UNMAPPED;
   s->rax=(s->rax&~UINT64_C(255))|(uint64_t)value;
   s->rcx+=1U;
   s->cf=0U;s->zf=(uint8_t)(value==0U);s->sf=(uint8_t)(value>>7U);
   s->rip=s->zf?UINT64_C({joined.BASE+UNQUOTED_DONE}):
                 UINT64_C({joined.BASE+UNQUOTED_BACKEDGE});
   s->instructions+=4U;
   return MX_NATIVE_LINK_FRONTIER_REACHED;
 }}
 return MX_GAME_PREFIX_BAD_STATE;
}}
"""
    source=source.replace(mark,helper+mark)
    old=f"""   if(s->rip==UINT64_C({joined.BASE+before.JG_TAKEN}))
       return native_arg_store(s,m);
   return MX_NATIVE_LINK_FRONTIER_REACHED;"""
    new=f"""   if(s->rip==UINT64_C({joined.BASE+before.JG_TAKEN}))
       return native_arg_store(s,m);
   return native_loop_edges(s,m);"""
    if source.count(old)!=1:raise ValueError("Original quote-JG frontier missing")
    source=source.replace(old,new)
    old=f"""   if(s->rip==UINT64_C({joined.BASE+before.JE_ROOT}))
       return native_three_controls(s,m);
   return MX_NATIVE_LINK_FRONTIER_REACHED;"""
    new=f"""   if(s->rip==UINT64_C({joined.BASE+before.JE_ROOT}))
       return native_three_controls(s,m);
   return native_loop_edges(s,m);"""
    if source.count(old)!=1:raise ValueError("Original unquoted-JLE frontier missing")
    source=source.replace(old,new)
    old=(f"const uint64_t proven_frontiers[4]={{UINT64_C({joined.BASE+before.JG_FALL}),"
         f"UINT64_C({joined.BASE+before.JLE_FALL}),"
         f"UINT64_C({joined.BASE+before.JE_FALL}),"
         f"UINT64_C({joined.BASE+before.JE_TAKEN})}};")
    new=(f"const uint64_t proven_frontiers[5]={{UINT64_C({joined.BASE+QUOTE_DONE}),"
         f"UINT64_C({joined.BASE+QUOTE_BACKEDGE}),"
         f"UINT64_C({joined.BASE+QUOTE_JOIN}),"
         f"UINT64_C({joined.BASE+UNQUOTED_BACKEDGE}),"
         f"UINT64_C({joined.BASE+UNQUOTED_DONE})}};")
    if source.count(old)!=1:raise ValueError("Strict prior four-frontier set moved")
    source=source.replace(old,new)
    old_count="r,s,m,CALLEE,AFTER_CALL,proven_frontiers,4U);"
    if source.count(old_count)!=1:
        raise ValueError("Verified guest CALL branch count unexpectedly changed")
    return source.replace(old_count,"r,s,m,CALLEE,AFTER_CALL,proven_frontiers,5U);")


def run(original,out):
    pe=PE(original)
    if hashlib.sha256(pe.b).hexdigest()!=INPUT_SHA:
        raise ValueError("Original owned MX Bikes executable SHA differs")
    joined.verify_main(original)
    second.verify_second_branch(pe);third.verify_third_branch(pe)
    pair.verified_pair(pe);followup.verify_original_followup(pe)
    quote.original_branch(pe)
    layout,_,_=joined.inspect_original(pe)
    argv.verify_original_blocks(pe,layout)
    prev.verify_original_next_pair(pe)
    before.verify_original_controls(pe)
    verify_original_loops(pe)
    isolated=before.original_memory_je_proof(pe)
    obs=[pair.reference(pe,layout,i,arg_group=True,next_branches=True,
            three_branches=True,parser_loops=True) for i in range(len(INPUT))]
    locs={}
    for _,state,_,status in obs:
        pc=hex(state["rip"]-joined.BASE)
        if pc not in {hex(x) for x in STOPPED} | {hex(joined.AFTER_CALL)}:
            raise ValueError("Authentic original joined parser left known bounded loop frontier")
        locs[pc]=locs.get(pc,0)+1
    print("Original joined main/CALL quoted-unquoted backedge outcomes:",
          sorted(locs.items()),flush=True)
    if not locs.get(hex(QUOTE_DONE)) or not (
        locs.get(hex(UNQUOTED_BACKEDGE)) or locs.get(hex(UNQUOTED_DONE))):
        raise ValueError("Original quote and unquoted loop coverage missing")
    source,_=joined.generate(layout,[(before,state) for before,state,_,_ in obs])
    statuses=[s for _,_,_,s in obs]
    steps=[k for _,_,k,_ in obs]
    second_bytes=[
        0x22 if i==10 else 0x7f if i==5 else 0x10 if i==3 else
        0x51 if i==12 else 0 if i==7 else pair.next_byte(i)
        for i in range(len(INPUT))]
    source=third.extend_third_jle(second.extend_joined_source(
        source,second.verify_second_branch(pe)))
    source=pair.extend_native_pair(source,second_bytes,statuses,steps)
    source=followup.extend_joined_native_followup(source)
    source=quote.extend_quote_native(source)
    source=argv.extend_native_argument_blocks(source,
       [state["argument_slot_before"] for _,state,_,_ in obs],
       [state["argument_slot_after"] for _,state,_,_ in obs],steps)
    source=prev.append_native_pair(source)
    source=before.append_native(source,isolated)
    source=extend_native(source)
    original_assert="if(actual[j]!=f->expected[j])return 4;"
    if source.count(original_assert)!=1:
        raise ValueError("Original guest nine-register differential assertion changed")
    # Encode both case and register in a deterministic process exit code.
    # This is a strictly stronger failure report, never a suppressed assertion.
    source=source.replace("#include <stdint.h>", """#include <stdint.h>
#ifdef HOST
#include <stdio.h>
#endif""")
    detailed=r'''if(actual[j]!=f->expected[j]){
#ifdef HOST
fprintf(stderr, "case=%u register=%u actual=%llx expected=%llx rip=%llx rcx=%llx expected_rcx=%llx first=%u second=%u\\n",
        i,j,(unsigned long long)actual[j],
        (unsigned long long)f->expected[j],(unsigned long long)s.rip,
        (unsigned long long)s.rcx,(unsigned long long)f->expected[2],
        (unsigned)input_data[0x100U],(unsigned)input_data[0x101U]);
#endif
return 10+(int)(i*9U+j);
}'''
    source=source.replace(original_assert,detailed)
    with tempfile.TemporaryDirectory(prefix="mxb-authentic-guest-parser-loop-") as td:
        folder=Path(td);file=folder/"original-private-scanner-arm64.c"
        file.write_text(source)
        options=["-O2","-std=c11","-Wall","-Wextra","-Werror",
                 "-I",str(ROOT/"arm64-lab"/"runtime"),
                 "-I",str(ROOT/"scripts")]
        host=folder/"host"
        p=subprocess.run(["cc",*options,"-DHOST",str(file),"-o",str(host)],
                         capture_output=True,text=True)
        if p.returncode:raise RuntimeError("Native guest parser loop host compile: "+p.stderr[-2600:])
        p=subprocess.run([str(host)],capture_output=True,text=True)
        if p.returncode:raise RuntimeError("Authentic x64 / host scanner differential: "+str(p.returncode)+" "+p.stderr[-900:])
        arm=folder/"real-scanner-aarch64.elf"
        p=subprocess.run(["clang","--target=aarch64-unknown-linux-gnu",
          "-fuse-ld=lld","-nostdlib","-static","-ffreestanding",
          "-fno-builtin","-fno-stack-protector",*options,
          "-Wl,-e,smoke","-Wl,-z,max-page-size=4096",
          "-Wl,--build-id=none",str(file),"-o",str(arm)],
          capture_output=True,text=True)
        if p.returncode:raise RuntimeError("Original scanner ARM64 compile: "+p.stderr[-2600:])
        result=execute_arm64_elf(arm,instruction_budget=2800000,timeout_us=15000000)
        if result["arm64_smoke_exit"]!=0:
            raise RuntimeError("Authentic x64 / ARM64 loop guest-state mismatch: "+
                               str(result["arm64_smoke_exit"]))
    out.mkdir(parents=True,exist_ok=True)
    data={
       "original_sha256":INPUT_SHA,
       "joined_main_x64_host_aarch64_matching_cases":len(INPUT),
       "original_argv_table_before_after_matching_cases":len(INPUT),
       "further_bounded_original_memory_je_cases":len(isolated),
       "original_scanner_backedge_rvas":[hex(QUOTE_BACKEDGE),hex(UNQUOTED_BACKEDGE)],
       "actual_aarch64_control_outcomes":locs,
       "complete_first_callee_return_all_paths":False,
       "engine_menu_or_ios_game_started":False,
       "original_binary_or_lifted_code_exported":False}
    (out/"joined-parser-loop-native.json").write_text(json.dumps(data,indent=2)+"\n")
    lines=["# MX Bikes grouped original quote/unquoted scanner loop ARM64 differential","",
       "- Authentic x64 -> native host -> executed ARM64: **16/16**",
       "- Real guest argv memory before/after: **16/16**",
       "- Standalone original memory zero-JE: **3/3**","",
       "## Joined original game main CALL execution endpoints"]
    lines+=["- "+k+": **"+str(v)+" cases**" for k,v in sorted(locs.items())]
    lines+=["","Native full original callee, complete executable, engine/menu/iOS boot: **NO**",""]
    (out/"joined-parser-loop-native.md").write_text("\n".join(lines))
    print("\n".join(lines))
    return data


if __name__=="__main__":
    if len(sys.argv)!=3:raise SystemExit("usage: parser_loop.py original.exe out")
    run(Path(sys.argv[1]),Path(sys.argv[2]))
