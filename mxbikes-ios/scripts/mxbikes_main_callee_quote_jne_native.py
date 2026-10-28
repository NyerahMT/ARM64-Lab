#!/usr/bin/env python3
"""Execute original MX Bikes first-callee quote-detection JNE in joined ARM64.

Existing authentic main/CALL/RET + command parser traces remain intact.
This verifies XOR R9D,R9D / CMP AL,0x22 / JNE 0x1361b9 at 0x136183.
A controlled first-byte quote case ensures BOTH branch outcomes execute on
the original x64, compiled native host and executed native AArch64.
The nonempty callee is not yet fully translated or bootable.
"""
from pathlib import Path
import hashlib,json,subprocess,sys,tempfile
import mxbikes_main_callee_branch_pair_native as pair
import mxbikes_main_callee_branch_pair_map as mapping
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

ENTRY=0x136183
JNE=0x136188
FALLTHROUGH=0x13618a
NOT_QUOTE=0x1361b9
QUOTE_CASE=3


def original_branch(pe):
    """Reject any changed original opcode layout, transfer length or target."""
    row=mapping.first_control(pe,ENTRY)
    expected=[("xor","r9d, r9d"),("cmp","al, 0x22")]
    if ([(x["mnemonic"],x["op_str"]) for x in row["instruction_forms"]]!=expected
        or row["control_rva"]!=hex(JNE)
        or row["control_kind"]!="jne"
        or row["control_direct_target_rva"]!=hex(NOT_QUOTE)
        or row["control_next_rva"]!=hex(FALLTHROUGH)):
        raise ValueError("Authentic game callee quote-JNE source identity changed")
    return row


def extend_quote_native(source):
    """Continue only at verified 0x136183, preserve exact CALL frontier."""
    old=(f"r,s,m,CALLEE,AFTER_CALL,UINT64_C({joined.BASE+followup.SHARED}),"
         f"UINT64_C({joined.BASE+0x136168}));")
    new=(f"r,s,m,CALLEE,AFTER_CALL,UINT64_C({joined.BASE+NOT_QUOTE}),"
         f"UINT64_C({joined.BASE+FALLTHROUGH}));")
    if source.count(old)!=1:
        raise ValueError("Authentic game-main CALL linker was not at shared frontier")
    source=source.replace(old,new)
    prior=(f" s->rip=ch?UINT64_C({joined.BASE+followup.SHARED}):\n"
           f"            UINT64_C({joined.BASE+0x136207});\n"
           " if(!ch)\n    return mx_game_main_callee_finish_empty(s,m,&callee_layout);\n"
           " return MX_NATIVE_LINK_FRONTIER_REACHED;")
    after=(f" s->rip=ch?UINT64_C({joined.BASE+followup.SHARED}):\n"
           f"            UINT64_C({joined.BASE+0x136207});\n"
           " if(!ch)\n    return mx_game_main_callee_finish_empty(s,m,&callee_layout);\n"
           " return native_quote_branch(s,m);")
    if source.count(prior)!=1:
        raise ValueError("Original signed-byte follow-up body moved")
    helper=f"""
static int native_quote_branch(mx_crt_cluster_state*s,mx_cfg_memory*m){{
 (void)m;
 if(!s||s->fault||s->rip!=UINT64_C({joined.BASE+ENTRY}))
    return MX_GAME_PREFIX_BAD_STATE;
 /* Original XOR R9D,R9D zero-extends, CMP AL,0x22 updates flags,
    JNE selects original branch when ZF==0. */
 s->r9=0U;
 uint8_t lhs=(uint8_t)s->rax;
 uint8_t result=(uint8_t)(lhs-34U);
 s->cf=(uint8_t)(lhs<34U);
 s->sf=(uint8_t)(result>>7U);
 s->zf=(uint8_t)(result==0U);
 s->rip=s->zf?UINT64_C({joined.BASE+FALLTHROUGH}):
              UINT64_C({joined.BASE+NOT_QUOTE});
 s->instructions+=3U;
 return MX_NATIVE_LINK_FRONTIER_REACHED;
}}
"""
    original="static int native_followup(mx_crt_cluster_state*s,mx_cfg_memory*m){"
    if source.count(original)!=1:
        raise ValueError("Joined original follow-up callee missing")
    source=source.replace(original,helper+original)
    return source.replace(prior,after)


def run(original,out):
    pe=PE(original)
    if hashlib.sha256(pe.b).hexdigest()!=SHA:
        raise ValueError("Original owned MX Bikes executable SHA changed")
    original_branch(pe)
    second.verify_second_branch(pe)
    third.verify_third_branch(pe)
    pair.verified_pair(pe)
    followup.verify_original_followup(pe)
    joined.verify_main(original)
    layout,_,_=joined.inspect_original(pe)
    observations=[pair.reference(pe,layout,i,quote_branch=True)
                  for i in range(len(INPUTS))]
    refs=[(before,state) for before,state,_,_ in observations]
    statuses=[status for _,_,_,status in observations]
    steps=[n for _,_,n,_ in observations]
    if any(n<18 or n>54 for n in steps):
        raise RuntimeError("Quote JNE original x64 bounded instruction count invalid")
    exits={}
    for i,(_,state,_,_) in enumerate(observations):
        k=hex(state["rip"]-joined.BASE)
        exits[k]=exits.get(k,0)+1
        if i==QUOTE_CASE and k!=hex(FALLTHROUGH):
            raise RuntimeError("Original quoted command input never took JNE fallthrough")
    if not exits.get(hex(NOT_QUOTE)) or not exits.get(hex(FALLTHROUGH)):
        raise RuntimeError("Both real original JNE results not exercised")
    src,_=joined.generate(layout,refs)
    src=third.extend_third_jle(second.extend_joined_source(
        src,second.verify_second_branch(pe)))
    src=pair.extend_native_pair(src,[pair.next_byte(i) for i in range(len(INPUTS))],
                                statuses,steps)
    src=followup.extend_joined_native_followup(src)
    src=extend_quote_native(src)
    with tempfile.TemporaryDirectory(prefix="mxb-original-quote-jne-") as td:
        directory=Path(td);file=directory/"original-callee-quote-jnz-arm64.c"
        file.write_text(src)
        flags=["-O2","-std=c11","-Wall","-Wextra","-Werror",
               "-I",str(ROOT/"arm64-lab"/"runtime")]
        host=directory/"host"
        t=subprocess.run(["cc",*flags,"-DHOST",str(file),"-o",str(host)],
                         capture_output=True,text=True)
        if t.returncode:
            raise RuntimeError("Joined quote branch native host compile: "+t.stderr[-3000:])
        t=subprocess.run([str(host)],capture_output=True,text=True)
        if t.returncode:
            raise RuntimeError("Real x64/host quote-JNE full-state differential "+
                               str(t.returncode))
        arm=directory/"joined-quote-native-arm64.elf"
        t=subprocess.run(["clang","--target=aarch64-unknown-linux-gnu",
             "-fuse-ld=lld","-nostdlib","-static","-ffreestanding",
             "-fno-builtin","-fno-stack-protector",*flags,
             "-Wl,-e,smoke","-Wl,-z,max-page-size=4096",
             "-Wl,--build-id=none",str(file),"-o",str(arm)],
             capture_output=True,text=True)
        if t.returncode:
            raise RuntimeError("Joined quote-JNE native ARM64 compile: "+t.stderr[-3000:])
        res=execute_arm64_elf(arm,instruction_budget=2100000,timeout_us=15000000)
        if res["arm64_smoke_exit"]!=0:
            raise RuntimeError("Original x64/ARM64 quote branch mismatch "+
                               str(res["arm64_smoke_exit"]))
    out.mkdir(parents=True,exist_ok=True)
    report={
        "original_sha256":SHA,
        "joined_original_main_rva":hex(joined.MAIN),
        "joined_original_callee_rva":hex(joined.CALLEE),
        "original_quote_branch_rva":hex(JNE),
        "original_quote_input_byte":hex(0x22),
        "controlled_original_quote_input_case":QUOTE_CASE,
        "differential_x64_host_executed_aarch64_cases":len(INPUTS),
        "result_original_guest_rva_counts":exits,
        "original_native_win64_call_return_verified":True,
        "full_original_callee_verified":False,
        "native_game_menu_or_ipa_launched":False,
        "original_code_or_pe_exported":False,
    }
    (out/"joined-quote-jne-native.json").write_text(json.dumps(report,indent=2)+"\n")
    lines=["# MX Bikes original joined native quote JNE","",
       "- Real x64 / native host / executed ARM64 guest-state cases: **16/16**",
       "- Both genuine signed quote comparison JNE successors: **executed**",
       "- Controlled quote byte: **0x22**","",
       "## Original game-main/callee resulting RVAs"]
    lines += ["- "+rva+": **"+str(n)+" cases**" for rva,n in sorted(exits.items())]
    lines += ["","Complete original callee, engine, game menu or IPA: **NO**",""]
    (out/"joined-quote-jne-native.md").write_text("\n".join(lines))
    print("\n".join(lines))
    return report


if __name__=="__main__":
    if len(sys.argv)!=3:
        raise SystemExit("usage: quote_native.py original-owned-exe metadata-output-dir")
    run(Path(sys.argv[1]),Path(sys.argv[2]))
