#!/usr/bin/env python3
"""Two original MX Bikes callee branches after the verified argv-table write.

Execute from the original x64 game-main CALL, compare original x64 full guest
state and argv-table slot with compiled host and executed AArch64 (16 cases).
Includes both quoted-string JL outcomes with real source bytes and unquoted
NUL TEST/JE. This is bounded native execution, not complete game startup.
"""
from pathlib import Path
import hashlib,json,subprocess,sys,tempfile
import mxbikes_main_callee_branch_pair_native as pair
import mxbikes_main_callee_branch_pair_map as static
import mxbikes_main_callee_arg_group_native as argv
import mxbikes_main_callee_quote_jne_native as quote
import mxbikes_main_callee_followup_native as followup
import mxbikes_main_callee_third_jle_native as third
import mxbikes_main_callee_second_jge_native as second
import mxbikes_main_joined_callee_native as joined
from mxbikes_main_callee_native_branch import INPUT as INPUTS
from mxbikes_whole_game_map import INPUT_SHA as SHA

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/"arm64-lab"))
from tools.pe_probe import PE
from tools.import_aot_smoke import execute_arm64_elf

QUOTE=0x136194
UNQUOTE=0x1361d5
JL=0x136199
JE=0x1361da
QUOTE_LT=0x1361b9
QUOTE_GE=0x13619b
NUL=0x1361f2
NON_NUL=0x1361dc


def verify_original_next_pair(pe):
    a=static.first_control(pe,QUOTE)
    b=static.first_control(pe,UNQUOTE)
    if ([(v["mnemonic"],v["op_str"]) for v in a["instruction_forms"]]!=[
            ("movzx","eax, byte ptr [rdx]"),
            ("cmp","al, 0x20")] or
        a["control_rva"]!=hex(JL) or
        a["control_kind"]!="jl" or
        a["control_direct_target_rva"]!=hex(QUOTE_LT) or
        a["control_next_rva"]!=hex(QUOTE_GE) or
        [(v["mnemonic"],v["op_str"]) for v in b["instruction_forms"]]!=[
            ("movzx","eax, byte ptr [rcx]"),
            ("test","al, al")] or
        b["control_rva"]!=hex(JE) or
        b["control_kind"]!="je" or
        b["control_direct_target_rva"]!=hex(NUL) or
        b["control_next_rva"]!=hex(NON_NUL)):
        raise ValueError("Authentic original quote JL / unquoted JE shapes changed")
    return a,b


def append_native_pair(source):
    """Extend BOTH original parser paths using checked guest memory."""
    old=f""" s->rip=UINT64_C({joined.BASE+argv.STORE_TAKEN});
 s->instructions+=6U;
 return MX_NATIVE_LINK_FRONTIER_REACHED;"""
    replacement=f""" s->rip=UINT64_C({joined.BASE+argv.STORE_TAKEN});
 s->instructions+=6U;
 return native_comparison_pair(s,m);"""
    if source.count(old)!=1:
        raise ValueError("Previously verified original argument-table store absent")
    source=source.replace(old,replacement)
    old_quote="""    if(!s->zf)return MX_NATIVE_LINK_FRONTIER_REACHED;"""
    if source.count(old_quote)!=1:
        raise ValueError("Previously verified original quoted-byte JE absent")
    source=source.replace(old_quote,
      """    if(!s->zf)return native_comparison_pair(s,m);""")
    helper=f"""
static int native_comparison_pair(mx_crt_cluster_state*s,mx_cfg_memory*m){{
 if(!s||!m||s->fault)return MX_GAME_PREFIX_BAD_STATE;
 if(s->rip==UINT64_C({joined.BASE+QUOTE})){{
   /* Original MOVZX EAX,[RDX]; CMP AL,0x20; signed JL. */
   uint8_t v=0U;
   if(!mx_cfg_transfer(m,s->rdx,&v,1U,0))return MX_GAME_PREFIX_UNMAPPED;
   s->rax=(uint64_t)v;
   uint8_t diff=(uint8_t)(v-32U);
   uint8_t of=(uint8_t)((((v^32U)&(v^diff))>>7U)&1U);
   s->cf=(uint8_t)(v<32U);
   s->zf=(uint8_t)(diff==0U);
   s->sf=(uint8_t)(diff>>7U);
   s->rip=s->sf!=of?UINT64_C({joined.BASE+QUOTE_LT}):
                     UINT64_C({joined.BASE+QUOTE_GE});
   s->instructions+=3U;
   return MX_NATIVE_LINK_FRONTIER_REACHED;
 }}
 if(s->rip==UINT64_C({joined.BASE+UNQUOTE})){{
   /* Original MOVZX EAX,[RCX]; TEST AL,AL; JE. */
   uint8_t v=0U;
   if(!mx_cfg_transfer(m,s->rcx,&v,1U,0))return MX_GAME_PREFIX_UNMAPPED;
   s->rax=(uint64_t)v;
   s->cf=0U;
   s->zf=(uint8_t)(v==0U);
   s->sf=(uint8_t)(v>>7U);
   s->rip=s->zf?UINT64_C({joined.BASE+NUL}):
                 UINT64_C({joined.BASE+NON_NUL});
   s->instructions+=3U;
   return MX_NATIVE_LINK_FRONTIER_REACHED;
 }}
 return MX_GAME_PREFIX_BAD_STATE;
}}
"""
    anchor="static int native_arg_store(mx_crt_cluster_state*s,mx_cfg_memory*m){"
    if source.count(anchor)!=1:
        raise ValueError("Original unquoted argument-table stage missing")
    source=source.replace(anchor,helper+anchor)
    existing=(f"r,s,m,CALLEE,AFTER_CALL,UINT64_C({joined.BASE+argv.QUOTE_FALL}),"
              f"UINT64_C({joined.BASE+argv.STORE_TAKEN}));")
    updated=(f"r,s,m,CALLEE,AFTER_CALL,UINT64_C({joined.BASE+QUOTE_LT}),"
             f"UINT64_C({joined.BASE+NON_NUL}));")
    if source.count(existing)!=1:
        raise ValueError("Authentic original Win64 CALL frontier changed")
    source=source.replace(existing,updated)
    # The existing native linker only permits two unfinished CALL endpoints.
    # This authenticated original parser has THREE. Use a strict set rather
    # than discarding outcomes or pretending an unfinished CALL returned.
    include='#include "mx_native_guest_linker.h"'
    if source.count(include)!=1:
        raise ValueError("Original native guest linker header not found")
    source=source.replace(include,include+'\n#include "mxbikes_native_multifrontier.h"')
    old_call=(f"return mx_native_link_call_until_return_or_frontier(\n"
              f"     r,s,m,CALLEE,AFTER_CALL,UINT64_C({joined.BASE+QUOTE_LT}),"
              f"UINT64_C({joined.BASE+NON_NUL}));")
    new_call=(f"const uint64_t proven_frontiers[4]={{"
              f"UINT64_C({joined.BASE+QUOTE_LT}),"
              f"UINT64_C({joined.BASE+QUOTE_GE}),"
              f"UINT64_C({joined.BASE+NON_NUL}),"
              f"UINT64_C({joined.BASE+NUL})}};\n"
              " return mx_native_link_call_frontier_set(\n"
              "     r,s,m,CALLEE,AFTER_CALL,proven_frontiers,4U);")
    if source.count(old_call)!=1:
        raise ValueError("Authenticated four-frontier native callsite missing")
    return source.replace(old_call,new_call)


def run(original,out):
    pe=PE(original)
    if hashlib.sha256(pe.b).hexdigest()!=SHA:
        raise ValueError("Original owned game executable does not match verified SHA")
    joined.verify_main(original)
    second.verify_second_branch(pe)
    third.verify_third_branch(pe)
    pair.verified_pair(pe)
    followup.verify_original_followup(pe)
    quote.original_branch(pe)
    layout,_,_=joined.inspect_original(pe)
    argv.verify_original_blocks(pe,layout)
    verify_original_next_pair(pe)
    references=[pair.reference(pe,layout,i,arg_group=True,next_branches=True)
                for i in range(len(INPUTS))]
    exits={}
    for i,(_,state,_,_) in enumerate(references):
        rva=hex(state["rip"]-joined.BASE)
        exits[rva]=exits.get(rva,0)+1
        if rva not in (hex(joined.AFTER_CALL),hex(QUOTE_LT),hex(QUOTE_GE),
                       hex(NUL),hex(NON_NUL)):
            raise RuntimeError("Original x64 continued past expected branch boundary")
        if i==3 and rva!=hex(QUOTE_LT):
            raise RuntimeError("Original low ASCII quoted byte did not take JL")
        if i==12 and rva!=hex(QUOTE_GE):
            raise RuntimeError("Original printable quoted byte did not fall through JL")
    print("Authenticated original x64 JL/JE endpoint distribution:",
          sorted(exits.items()),flush=True)
    if (not exits.get(hex(QUOTE_LT)) or not exits.get(hex(QUOTE_GE)) or
        not (exits.get(hex(NUL)) or exits.get(hex(NON_NUL)))):
        raise RuntimeError("Insufficient original x64 native-JL/JE branch fixture coverage")
    records=[(before,state) for before,state,_,_ in references]
    statuses=[s for _,_,_,s in references]
    steps=[n for _,_,n,_ in references]
    second_bytes=[0x10 if i==3 else 0x51 if i==12 else
                  0 if i==7 else pair.next_byte(i) for i in range(len(INPUTS))]
    src,_=joined.generate(layout,records)
    src=third.extend_third_jle(second.extend_joined_source(
        src,second.verify_second_branch(pe)))
    src=pair.extend_native_pair(src,second_bytes,statuses,steps)
    src=followup.extend_joined_native_followup(src)
    src=quote.extend_quote_native(src)
    src=argv.extend_native_argument_blocks(
        src,[v["argument_slot_before"] for _,v,_,_ in references],
        [v["argument_slot_after"] for _,v,_,_ in references],steps)
    src=append_native_pair(src)
    with tempfile.TemporaryDirectory(prefix="mx-original-two-JL-JE-") as td:
        directory=Path(td)
        source=directory/"original-joined-parser-two-branches.c"
        source.write_text(src)
        opts=["-O2","-std=c11","-Wall","-Wextra","-Werror",
              "-I",str(ROOT/"arm64-lab"/"runtime"),
              "-I",str(ROOT/"scripts")]
        host=directory/"host"
        p=subprocess.run(["cc",*opts,"-DHOST",str(source),"-o",str(host)],
                         capture_output=True,text=True)
        if p.returncode:
            raise RuntimeError("Original paired native branch host compile: "+p.stderr[-2600:])
        p=subprocess.run([str(host)],capture_output=True,text=True)
        if p.returncode:
            raise RuntimeError("Original x64 vs host full guest-state mismatch: "+str(p.returncode))
        arm=directory/"original-linked-branches-aarch64.elf"
        p=subprocess.run(["clang","--target=aarch64-unknown-linux-gnu",
            "-fuse-ld=lld","-nostdlib","-static","-ffreestanding",
            "-fno-builtin","-fno-stack-protector",*opts,
            "-Wl,-e,smoke","-Wl,-z,max-page-size=4096",
            "-Wl,--build-id=none",str(source),"-o",str(arm)],
            capture_output=True,text=True)
        if p.returncode:
            raise RuntimeError("Original branch native ARM64 compile: "+p.stderr[-2600:])
        result=execute_arm64_elf(arm,instruction_budget=2200000,timeout_us=15000000)
        if result["arm64_smoke_exit"]!=0:
            raise RuntimeError("Original x64 vs real AArch64 branch differential: "+
                               str(result["arm64_smoke_exit"]))
    out.mkdir(parents=True,exist_ok=True)
    result={
       "original_sha256":SHA,
       "real_arm64_verified_joined_main_first_callee":True,
       "original_x64_host_arm64_guest_cases":len(INPUTS),
       "original_memory_before_after_checked_cases":len(INPUTS),
       "new_original_compared_control_rvas":[hex(JL),hex(JE)],
       "executed_guest_pc_outcomes":exits,
       "complete_original_callee_function_proven":False,
       "native_game_menu_or_ios_app_running":False,
       "original_game_or_generated_code_exported":False,
    }
    (out/"joined-argv-next-branches-native.json").write_text(json.dumps(result,indent=2)+"\n")
    lines=["# MX Bikes original main/CALL joined next two ARM64 branches","",
      "- Exact original x64 versus native host versus executed ARM64 cases: **16/16**",
      "- Original guest argument-table before/after: **16/16 verified**",
      "- Both quoted signed JL outcomes tested: **YES**",
      "- Original unquoted JE tested: **YES**","",
      "## Authenticated execution endpoints"]
    lines.extend("- "+k+": **"+str(n)+" cases**" for k,n in sorted(exits.items()))
    lines+=["","Original function fully proven, engine startup, graphics, menu, IPA: **NO**",""]
    (out/"joined-argv-next-branches-native.md").write_text("\n".join(lines))
    print("\n".join(lines))
    return result


if __name__=="__main__":
    if len(sys.argv)!=3:
        raise SystemExit("usage: next_pair.py original-game.exe metadata-directory")
    run(Path(sys.argv[1]),Path(sys.argv[2]))
