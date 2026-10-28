#!/usr/bin/env python3
"""Bounded authentic x64 -> native ARM64 parser termination and Win64 CALL RET.

The original owned PE is SHA checked. No original/translated bytes exported.
"""
from pathlib import Path
import hashlib,json,subprocess,sys,tempfile
import mxbikes_main_callee_branch_pair_map as mapping
import mxbikes_main_callee_branch_pair_native as pair
import mxbikes_main_callee_parser_loop_native as loop
import mxbikes_main_callee_three_branches_native as triple
import mxbikes_main_callee_next_pair_native as previous
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
ARM64_INSTRUCTION_BUDGET=2900000
ARM64_TIMEOUT_US=15000000
CHECK=0x1361f2
WRITE=0x1361f7
RELOAD=0x1361fd
JNE=0x136201
LOOP=0x136152
RETURN=0x136207

def verify(pe):
    for start,inst,control,kind,target,fall in [
      (CHECK,[("cmp","byte ptr [rcx], 0")],0x1361f5,"je",RELOAD,WRITE),
      (WRITE,[("mov","byte ptr [rcx], 0"),("inc","rcx"),
              ("mov","al, byte ptr [rcx]"),("test","al, al")],
       JNE,"jne",LOOP,RETURN),
      (RELOAD,[("mov","al, byte ptr [rcx]"),("test","al, al")],
       JNE,"jne",LOOP,RETURN),
      (JNE,[],JNE,"jne",LOOP,RETURN),
      (RETURN,[("xor","eax, eax")],0x136209,"ret",None,0x13620a),
      (LOOP,[("cmp","r10d, 0x80")],0x136159,"jge",RETURN,0x13615f)]:
        row=mapping.first_control(pe,start)
        if ([(x["mnemonic"],x["op_str"]) for x in row["instruction_forms"]]!=inst or
            row["control_rva"]!=hex(control) or row["control_kind"]!=kind or
            row["control_direct_target_rva"]!=(hex(target) if target is not None else None) or
            row["control_next_rva"]!=hex(fall)):
            raise ValueError("Original SHA-pinned parser tail identity changed")

def extend(source,after_first,after_second):
    if len(after_first)!=len(INPUT) or len(after_second)!=len(INPUT):
        raise ValueError("Original input-memory fixture count mismatch")
    anchor="static int native_loop_edges(mx_crt_cluster_state*s,mx_cfg_memory*m){"
    if source.count(anchor)!=1:raise ValueError("Original verified scanner missing")
    helper=f"""
static int native_parser_tail(mx_crt_cluster_state*s,mx_cfg_memory*m){{
 if(!s||!m||s->fault)return MX_GAME_PREFIX_BAD_STATE;
 if(s->rip==UINT64_C({joined.BASE+CHECK})){{
   /* CMP BYTE [RCX],0; JE 0x1361fd. */
   uint8_t ch=0U;
   if(!mx_cfg_transfer(m,s->rcx,&ch,1U,0))return MX_GAME_PREFIX_UNMAPPED;
   s->cf=0U;s->zf=(uint8_t)(ch==0U);s->sf=(uint8_t)(ch>>7U);
   s->rip=s->zf?UINT64_C({joined.BASE+RELOAD}):
                 UINT64_C({joined.BASE+WRITE});
   s->instructions+=2U;
 }}
 if(s->rip==UINT64_C({joined.BASE+WRITE})){{
   if(s->rcx==UINT64_MAX)return MX_GAME_PREFIX_BAD_STATE;
   uint8_t zero=0U;
   if(!mx_cfg_transfer(m,s->rcx,&zero,1U,1))return MX_GAME_PREFIX_UNMAPPED;
   s->rcx+=1U;s->rip=UINT64_C({joined.BASE+RELOAD});
   s->instructions+=2U;
 }}
 if(s->rip!=UINT64_C({joined.BASE+RELOAD}))
    return MX_GAME_PREFIX_BAD_STATE;
 /* MOV AL,[RCX]; TEST AL,AL; JNE 0x136152. */
 uint8_t ch=0U;
 if(!mx_cfg_transfer(m,s->rcx,&ch,1U,0))return MX_GAME_PREFIX_UNMAPPED;
 s->rax=(s->rax&~UINT64_C(255))|(uint64_t)ch;
 s->cf=0U;s->zf=(uint8_t)(ch==0U);s->sf=(uint8_t)(ch>>7U);
 s->rip=ch?UINT64_C({joined.BASE+LOOP}):
           UINT64_C({joined.BASE+RETURN});
 s->instructions+=3U;
 if(ch)return MX_NATIVE_LINK_FRONTIER_REACHED;
 return mx_game_main_callee_finish_empty(s,m,&callee_layout);
}}
"""
    source=source.replace(anchor,helper+anchor)
    old=f"""   if(s->rip==UINT64_C({joined.BASE+triple.JE_ROOT}))
       return native_three_controls(s,m);
   return native_loop_edges(s,m);"""
    new=f"""   if(s->rip==UINT64_C({joined.BASE+triple.JE_ROOT}))
       return native_parser_tail(s,m);
   return native_loop_edges(s,m);"""
    if source.count(old)!=1:raise ValueError("Original JLE JE dispatch moved")
    source=source.replace(old,new)
    old=f"""   if(s->rip==UINT64_C({joined.BASE+loop.UNQUOTED_DONE}))
      return MX_NATIVE_LINK_FRONTIER_REACHED;"""
    new=f"""   if(s->rip==UINT64_C({joined.BASE+loop.UNQUOTED_DONE}))
      return native_parser_tail(s,m);"""
    if source.count(old)!=1:raise ValueError("Original JG->JE dispatch moved")
    source=source.replace(old,new)
    old=f"""   s->rip=s->zf?UINT64_C({joined.BASE+loop.UNQUOTED_DONE}):
                 UINT64_C({joined.BASE+loop.UNQUOTED_BACKEDGE});
   s->instructions+=4U;
   return MX_NATIVE_LINK_FRONTIER_REACHED;"""
    new=f"""   s->rip=s->zf?UINT64_C({joined.BASE+loop.UNQUOTED_DONE}):
                 UINT64_C({joined.BASE+loop.UNQUOTED_BACKEDGE});
   s->instructions+=4U;
   if(s->zf)return native_parser_tail(s,m);
   return MX_NATIVE_LINK_FRONTIER_REACHED;"""
    if source.count(old)!=1:raise ValueError("Original argument scanner exit moved")
    source=source.replace(old,new)
    old=(f"const uint64_t proven_frontiers[5]={{UINT64_C({joined.BASE+loop.QUOTE_DONE}),"
        f"UINT64_C({joined.BASE+loop.QUOTE_BACKEDGE}),"
        f"UINT64_C({joined.BASE+loop.QUOTE_JOIN}),"
        f"UINT64_C({joined.BASE+loop.UNQUOTED_BACKEDGE}),"
        f"UINT64_C({joined.BASE+loop.UNQUOTED_DONE})}};")
    new=(f"const uint64_t proven_frontiers[5]={{UINT64_C({joined.BASE+loop.QUOTE_DONE}),"
        f"UINT64_C({joined.BASE+loop.QUOTE_BACKEDGE}),"
        f"UINT64_C({joined.BASE+loop.QUOTE_JOIN}),"
        f"UINT64_C({joined.BASE+loop.UNQUOTED_BACKEDGE}),"
        f"UINT64_C({joined.BASE+LOOP})}};")
    if source.count(old)!=1:raise ValueError("Proven Win64 CALL endpoints moved")
    source=source.replace(old,new)
    marker="static uint64_t read_guest(mx_cfg_memory*m,uint64_t addr,unsigned size){"
    if source.count(marker)!=1:raise ValueError("No guest-memory reader")
    arrays=("static const uint8_t first_after[CASES]={"+
            ",".join(str(x)+"U" for x in after_first)+"};\n"+
            "static const uint8_t second_after[CASES]={"+
            ",".join(str(x)+"U" for x in after_second)+"};\n")
    source=source.replace(marker,arrays+marker)
    assert_slot="   if(read_guest(&mem,CALLEE_G0+8U,8U)!=expected_arg_slot_after[i])"
    if source.count(assert_slot)!=1:raise ValueError("Preexisting argument-memory proof changed")
    source=source.replace(assert_slot,
        """   if(read_guest(&mem,TEST_INPUT,1U)!=first_after[i]||
      read_guest(&mem,TEST_INPUT+1U,1U)!=second_after[i])return 54+(int)i;
"""+assert_slot)
    return source

def run(exe,out,*,native_extension=None):
    pe=PE(exe)
    if hashlib.sha256(pe.b).hexdigest()!=INPUT_SHA:
        raise ValueError("Not the SHA-pinned original owned executable")
    joined.verify_main(exe)
    second.verify_second_branch(pe);third.verify_third_branch(pe)
    pair.verified_pair(pe);followup.verify_original_followup(pe)
    quote.original_branch(pe)
    layout,_,_=joined.inspect_original(pe)
    argv.verify_original_blocks(pe,layout)
    previous.verify_original_next_pair(pe)
    triple.verify_original_controls(pe);loop.verify_original_loops(pe)
    verify(pe)
    standalone=triple.original_memory_je_proof(pe)
    cases=[pair.reference(pe,layout,i,arg_group=True,next_branches=True,
          three_branches=True,parser_loops=True,parser_tail=True)
          for i in range(len(INPUT))]
    outcome={}
    for _,row,_,_ in cases:
        pc=hex(row["rip"]-joined.BASE)
        if pc not in {hex(joined.AFTER_CALL),hex(loop.QUOTE_DONE),
                      hex(loop.QUOTE_BACKEDGE),hex(loop.QUOTE_JOIN),
                      hex(loop.UNQUOTED_BACKEDGE),hex(LOOP)}:
            raise RuntimeError("Unverified original x64 parser tail successor "+pc)
        outcome[pc]=outcome.get(pc,0)+1
    print("Original x64 parser tail actual endpoints:",sorted(outcome.items()),flush=True)
    if outcome.get(hex(joined.AFTER_CALL),0)<=9:
        raise ValueError("Original x64 parser tail did not return additional cases")
    source,_=joined.generate(layout,[(p,r) for p,r,_,_ in cases])
    status=[s for _,_,_,s in cases]
    steps=[n for _,_,n,_ in cases]
    second_bytes=[0x22 if i==10 else 0x7f if i==5 else
        0x10 if i==3 else 0x51 if i==12 else 0 if i==7
        else pair.next_byte(i) for i in range(len(INPUT))]
    source=third.extend_third_jle(second.extend_joined_source(
          source,second.verify_second_branch(pe)))
    source=pair.extend_native_pair(source,second_bytes,status,steps)
    source=followup.extend_joined_native_followup(source)
    source=quote.extend_quote_native(source)
    source=argv.extend_native_argument_blocks(source,
       [r["argument_slot_before"] for _,r,_,_ in cases],
       [r["argument_slot_after"] for _,r,_,_ in cases],steps)
    source=previous.append_native_pair(source)
    source=triple.append_native(source,standalone)
    source=loop.extend_native(source)
    source=extend(source,
       [r["parser_input_first_after"] for _,r,_,_ in cases],
       [r["parser_input_second_after"] for _,r,_,_ in cases])
    if native_extension is not None:
        source=native_extension(pe,source,cases)
    with tempfile.TemporaryDirectory(prefix="mxb-owned-original-parser-tail-") as t:
        wd=Path(t);file=wd/"joined-guest-tail-native.c"
        file.write_text(source)
        options=["-O2","-std=c11","-Wall","-Wextra","-Werror",
                 "-I",str(ROOT/"arm64-lab"/"runtime"),"-I",str(ROOT/"scripts")]
        host=wd/"host"
        p=subprocess.run(["cc",*options,"-DHOST",str(file),"-o",str(host)],
                         capture_output=True,text=True)
        if p.returncode:raise RuntimeError("Original tail host compile: "+p.stderr[-2500:])
        p=subprocess.run([str(host)],capture_output=True,text=True)
        if p.returncode:raise RuntimeError("Original x64/host tail differential "+str(p.returncode))
        arm=wd/"original-parser-tail-aarch64.elf"
        p=subprocess.run(["clang","--target=aarch64-unknown-linux-gnu",
              "-fuse-ld=lld","-nostdlib","-static","-ffreestanding",
              "-fno-builtin","-fno-stack-protector",*options,
              "-Wl,-e,smoke","-Wl,-z,max-page-size=4096",
              "-Wl,--build-id=none",str(file),"-o",str(arm)],
              capture_output=True,text=True)
        if p.returncode:raise RuntimeError("Native ARM64 tail compiler: "+p.stderr[-2500:])
        result=execute_arm64_elf(arm,instruction_budget=ARM64_INSTRUCTION_BUDGET,timeout_us=ARM64_TIMEOUT_US)
        if result["arm64_smoke_exit"]!=0:
            raise RuntimeError("Original x64/AArch64 tail differential "+str(result["arm64_smoke_exit"]))
    out.mkdir(parents=True,exist_ok=True)
    report={"original_sha256":INPUT_SHA,
        "joined_x64_host_arm64_guest_cases":len(INPUT),
        "native_input_memory_byte_checks":2*len(INPUT),
        "original_parser_returned_to_main":outcome.get(hex(joined.AFTER_CALL),0),
        "original_parser_loop_backedges":outcome.get(hex(LOOP),0),
        "original_execution_endpoints":outcome,
        "complete_original_callee_verified":False,
        "engine_menu_or_ios_booted":False,
        "machine_or_original_bytes_exported":False}
    (out/"joined-parser-tail-native.json").write_text(json.dumps(report,indent=2)+"\n")
    md=["# MX Bikes original parser tail through real guest CALL on AArch64","",
        "- Original x64/native host/executed ARM64 state: **16/16**",
        "- Original input buffer byte checks: **32/32**","",
        "## Authenticated joined execution endpoints"]
    md += ["- "+k+": **"+str(v)+" cases**" for k,v in sorted(outcome.items())]
    md += ["","Original complete callee, engine, menu and IPA: **NO**",""]
    (out/"joined-parser-tail-native.md").write_text("\n".join(md))
    print("\n".join(md))
    return report

if __name__=="__main__":
    if len(sys.argv)!=3:raise SystemExit("usage: tail_native.py original.exe metadata-dir")
    run(Path(sys.argv[1]),Path(sys.argv[2]))
