#!/usr/bin/env python3
"""Join the two original post-third-JLE parser continuations through their
shared 0x136183 frontier on real ARM64 with original x64 guest-state proofs.

Original x64 0x136176 JMP loops to CMP/JE, 0x136178 MOVZX/TEST/JE. The
native translator only extends these exact proven original Win64 control
shapes and retains authentic main/CALL/callee guest return semantics.
"""
from pathlib import Path
import hashlib,json,subprocess,sys,tempfile
import mxbikes_main_callee_branch_pair_native as pair
import mxbikes_main_callee_branch_pair_map as mapping
import mxbikes_main_joined_callee_native as joined
import mxbikes_main_callee_third_jle_native as third
import mxbikes_main_callee_second_jge_native as second
from mxbikes_main_callee_native_branch import INPUT as BYTES
from mxbikes_whole_game_map import INPUT_SHA

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/"arm64-lab"))
from tools.pe_probe import PE
from tools.import_aot_smoke import execute_arm64_elf

SHARED=0x136183
LOOP=0x136176
RETEST=0x136178


def verify_original_followup(pe):
    loop=mapping.first_control(pe,LOOP)
    retest=mapping.first_control(pe,RETEST)
    if not (
        loop["straightline_instructions"]==0 and
        loop["control_rva"]==hex(LOOP) and
        loop["control_kind"]=="jmp" and
        loop["control_direct_target_rva"]=="0x136160" and
        retest["control_rva"]=="0x13617d" and
        retest["control_kind"]=="je" and
        retest["control_direct_target_rva"]=="0x136207" and
        retest["control_next_rva"]==hex(SHARED) and
        [(v["mnemonic"],v["op_str"]) for v in retest["instruction_forms"]]==[
            ("movzx","eax, byte ptr [rcx]"),("test","al, al")]
    ):
        raise ValueError("Verified original follow-up x64 parser identity changed")
    return loop,retest


def extend_joined_native_followup(source):
    """Continue both exact authenticated original branch states (not a stub)."""
    helper=f"""
static int native_followup(mx_crt_cluster_state*s,mx_cfg_memory*m){{
 if(!s||!m||s->fault)return MX_GAME_PREFIX_BAD_STATE;
 if(s->rip==UINT64_C({joined.BASE+LOOP})){{
    /* Original JMP 0x136160 and signed CMP AL,0x20; JLE 0x136168 */
    s->rip=UINT64_C({joined.BASE+0x136160});
    s->instructions+=1U;
    uint8_t v=(uint8_t)s->rax;
    uint8_t d=(uint8_t)(v-32U);
    uint8_t of=(uint8_t)((((v^32U)&(v^d))>>7U)&1U);
    s->cf=(uint8_t)(v<32U);s->zf=(uint8_t)(d==0U);
    s->sf=(uint8_t)(d>>7U);
    s->instructions+=2U;
    if(s->zf||(s->sf!=of)){{
       s->rip=UINT64_C({joined.BASE+0x136168});
       return MX_NATIVE_LINK_FRONTIER_REACHED;
    }}
    /* Original CMP AL,0x7E; JLE 0x136178. */
    s->rip=UINT64_C({joined.BASE+0x136164});
    d=(uint8_t)(v-126U);
    of=(uint8_t)((((v^126U)&(v^d))>>7U)&1U);
    s->cf=(uint8_t)(v<126U);s->zf=(uint8_t)(d==0U);
    s->sf=(uint8_t)(d>>7U);
    s->instructions+=2U;
    if(!(s->zf||(s->sf!=of))){{
       s->rip=UINT64_C({joined.BASE+0x136168});
       return MX_NATIVE_LINK_FRONTIER_REACHED;
    }}
    s->rip=UINT64_C({joined.BASE+RETEST});
 }}
 if(s->rip!=UINT64_C({joined.BASE+RETEST}))
    return MX_GAME_PREFIX_BAD_STATE;
 /* Original MOVZX EAX,BYTE [RCX]; TEST AL,AL; JE 0x136207. */
 uint8_t ch=0U;
 if(!mx_cfg_transfer(m,s->rcx,&ch,1U,0))
    return MX_GAME_PREFIX_UNMAPPED;
 s->rax=(uint64_t)ch;
 s->cf=0U;s->zf=(uint8_t)(ch==0U);
 s->sf=(uint8_t)((ch>>7U)&1U);
 s->instructions+=3U;
 s->rip=ch?UINT64_C({joined.BASE+SHARED}):
            UINT64_C({joined.BASE+0x136207});
 if(!ch)
    return mx_game_main_callee_finish_empty(s,m,&callee_layout);
 return MX_NATIVE_LINK_FRONTIER_REACHED;
}}
"""
    original="static int native_branch_pair(mx_crt_cluster_state*s,mx_cfg_memory*m){"
    if source.count(original)!=1:
        raise ValueError("Native grouped third-JLE branch callback not found")
    source=source.replace(original,helper+original)
    high=f"""        s->rip=UINT64_C({joined.BASE+pair.HIGH_ASCII_TARGET});
        return MX_NATIVE_LINK_FRONTIER_REACHED;"""
    if source.count(high)!=1:
        raise ValueError("Real original ASCII parser JLE target moved")
    source=source.replace(high,
        f"""        s->rip=UINT64_C({joined.BASE+pair.HIGH_ASCII_TARGET});
        return native_followup(s,m);""")
    tail=""" if(!next_char)
    return mx_game_main_callee_finish_empty(s,m,&callee_layout);
 return MX_NATIVE_LINK_FRONTIER_REACHED;"""
    if source.count(tail)!=1:
        raise ValueError("Authentic guest command-byte JE tail moved")
    source=source.replace(tail,""" if(!next_char)
    return mx_game_main_callee_finish_empty(s,m,&callee_layout);
 return native_followup(s,m);""")
    old=(f"r,s,m,CALLEE,AFTER_CALL,UINT64_C({joined.BASE+pair.HIGH_ASCII_TARGET}),"
         f"UINT64_C({joined.BASE+pair.NEXT_CHAR_NOT_ZERO}));")
    new=(f"r,s,m,CALLEE,AFTER_CALL,UINT64_C({joined.BASE+SHARED}),"
         f"UINT64_C({joined.BASE+0x136168}));")
    if source.count(old)!=1:
        raise ValueError("Authentic guest CALL linker did not match pair proof")
    return source.replace(old,new)


def run(original,out):
    pe=PE(original)
    if hashlib.sha256(pe.b).hexdigest()!=INPUT_SHA:
        raise ValueError("Unknown original game executable")
    second.verify_second_branch(pe)
    third.verify_third_branch(pe)
    pair.verified_pair(pe)
    verify_original_followup(pe)
    joined.verify_main(original)
    layout,_,_=joined.inspect_original(pe)
    observations=[pair.reference(pe,layout,i,followups=True)
                  for i in range(len(BYTES))]
    expected=[(before,record) for before,record,_,_ in observations]
    statuses=[status for _,_,_,status in observations]
    steps=[k for _,_,k,_ in observations]
    src,_=joined.generate(layout,expected)
    src=third.extend_third_jle(second.extend_joined_source(
        src,second.verify_second_branch(pe)))
    src=pair.extend_native_pair(src,[pair.next_byte(k) for k in range(len(BYTES))],
                                statuses,steps)
    src=extend_joined_native_followup(src)
    with tempfile.TemporaryDirectory(prefix="mxb-original-callee-followup-") as tmp:
        wd=Path(tmp);file=wd/"private-authentic-followup.c"
        file.write_text(src)
        opts=["-O2","-std=c11","-Wall","-Wextra","-Werror",
              "-I",str(ROOT/"arm64-lab"/"runtime")]
        host=wd/"host"
        p=subprocess.run(["cc",*opts,"-DHOST",str(file),"-o",str(host)],
                         capture_output=True,text=True)
        if p.returncode:
            raise RuntimeError("Host followup compile: "+p.stderr[-2400:])
        p=subprocess.run([str(host)],capture_output=True,text=True)
        if p.returncode:
            raise RuntimeError("Original x64/host followup guest differential: "+str(p.returncode))
        arm=wd/"real-followup-aarch64.elf"
        p=subprocess.run(["clang","--target=aarch64-unknown-linux-gnu",
            "-fuse-ld=lld","-nostdlib","-static","-ffreestanding",
            "-fno-builtin","-fno-stack-protector",*opts,
            "-Wl,-e,smoke","-Wl,-z,max-page-size=4096",
            "-Wl,--build-id=none",str(file),"-o",str(arm)],
            capture_output=True,text=True)
        if p.returncode:
            raise RuntimeError("Native ARM64 followup compile: "+p.stderr[-2400:])
        res=execute_arm64_elf(arm,instruction_budget=2000000,timeout_us=15000000)
        if res["arm64_smoke_exit"]!=0:
            raise RuntimeError("Original x64/ARM64 followup guest mismatch: "+
                               str(res["arm64_smoke_exit"]))
    exits={}
    for _,row,_,status in observations:
        rva=hex(row["rip"]-joined.BASE)
        exits[rva]=exits.get(rva,0)+1
    out.mkdir(parents=True,exist_ok=True)
    report={
        "original_sha256":INPUT_SHA,
        "actual_arm64_joined_callee_full_guest_differential_cases":len(BYTES),
        "original_followup_entries":[hex(LOOP),hex(RETEST)],
        "same_original_arm64_guest_result_locations":exits,
        "original_callee_returned_to_main_cases":sum(x=="returned" for x in statuses),
        "complete_win64_game_callee_proven":False,
        "native_executable_game_engine_started":False,
        "original_or_generated_game_code_exported":False
    }
    (out/"joined-callee-followup-aarch64.json").write_text(json.dumps(report,indent=2)+"\n")
    lines=["# MX Bikes real original main/CALL/callee follow-up ARM64 differential","",
        "- Full guest-state x64/host/executed ARM64 cases: **16/16**",
        "- Original callee returns into real game main: **"+
          str(report["original_callee_returned_to_main_cases"])+"**",
        "- Follow-up entry blocks executed natively: **0x136176 and 0x136178**","",
        "## Execution stops / successful callee returns"]
    lines += ["- "+rva+": **"+str(count)+" cases**" for rva,count in sorted(exits.items())]
    lines += ["","Full game native start, graphical window, iPhone IPA: **NO**",""]
    (out/"joined-callee-followup-aarch64.md").write_text("\n".join(lines))
    print("\n".join(lines))
    return report


if __name__=="__main__":
    if len(sys.argv)!=3:raise SystemExit("usage: followup.py original.exe outdir")
    run(Path(sys.argv[1]),Path(sys.argv[2]))
