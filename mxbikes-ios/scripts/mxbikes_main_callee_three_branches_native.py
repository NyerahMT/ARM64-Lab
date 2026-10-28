#!/usr/bin/env python3
"""Original MX Bikes parser JG/JLE/JE grouped into verified ARM64 guest model.

16 full guest main/CALL scenarios; 3 additional original-x64 signed-memory
zero-test entry fixtures, real ARM64 executed, not misclaimed as full startup.
"""
from pathlib import Path
import hashlib,json,subprocess,sys,tempfile
from unicorn.x86_const import UC_X86_REG_RIP,UC_X86_REG_RCX,UC_X86_REG_RAX,UC_X86_REG_EFLAGS
import mxbikes_main_callee_branch_pair_native as pair
import mxbikes_main_callee_branch_pair_map as mapping
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
JG_ROOT=0x13619b
JLE_ROOT=0x1361dc
JE_ROOT=0x1361f2
JG_FALL=0x13619f
JG_TAKEN=0x1361b9
JLE_FALL=0x1361e4
JLE_TAKEN=0x1361f2
JE_FALL=0x1361f7
JE_TAKEN=0x1361fd

def verify_original_controls(pe):
    rows=[mapping.first_control(pe,x) for x in (JG_ROOT,JLE_ROOT,JE_ROOT)]
    shapes=(
        ([("cmp","al, 0x7e")],0x13619d,"jg",JG_TAKEN,JG_FALL),
        ([("nop","dword ptr [rax]"),("cmp","al, 0x20")],0x1361e2,"jle",JLE_TAKEN,JLE_FALL),
        ([("cmp","byte ptr [rcx], 0")],0x1361f5,"je",JE_TAKEN,JE_FALL))
    for row,(forms,pc,kind,target,fall) in zip(rows,shapes):
        if ([(i["mnemonic"],i["op_str"]) for i in row["instruction_forms"]]!=forms or
            row["control_rva"]!=hex(pc) or row["control_kind"]!=kind or
            row["control_direct_target_rva"]!=hex(target) or
            row["control_next_rva"]!=hex(fall)):
            raise ValueError("SHA-pinned original parser control identity changed")
    return rows

def original_memory_je_proof(pe):
    out=[]
    for b in (0,0x51,0x81):
        cpu=joined.new_cpu(pe)
        cpu.mem_write(joined.TEST_INPUT,bytes([b]))
        cpu.reg_write(UC_X86_REG_RIP,joined.BASE+JE_ROOT)
        cpu.reg_write(UC_X86_REG_RCX,joined.TEST_INPUT)
        cpu.reg_write(UC_X86_REG_RAX,0x123456789ABCDEF0)
        cpu.reg_write(UC_X86_REG_EFLAGS,0x202)
        cpu.emu_start(joined.BASE+JE_ROOT,0,timeout=1000000,count=2)
        f=cpu.reg_read(UC_X86_REG_EFLAGS)
        rip=cpu.reg_read(UC_X86_REG_RIP)
        if rip not in (joined.BASE+JE_TAKEN,joined.BASE+JE_FALL):
            raise ValueError("Original x64 standalone memory-JE escaped")
        out.append((b,rip,int(bool(f&1)),int(bool(f&64)),int(bool(f&128))))
    if {r[1]-joined.BASE for r in out}!={JE_TAKEN,JE_FALL}:
        raise ValueError("Original isolated JE must cover both outcomes")
    return out

def append_native(source,isolated):
    anchor="static int native_comparison_pair(mx_crt_cluster_state*s,mx_cfg_memory*m){"
    if source.count(anchor)!=1:raise ValueError("Previously verified comparison pair missing")
    helper=f"""
static int native_arg_store(mx_crt_cluster_state*s,mx_cfg_memory*m);
static int native_three_controls(mx_crt_cluster_state*s,mx_cfg_memory*m){{
 if(!s||!m||s->fault)return MX_GAME_PREFIX_BAD_STATE;
 if(s->rip==UINT64_C({joined.BASE+JG_ROOT})){{
   /* Original 8-bit CMP AL,0x7E and signed JG. */
   uint8_t a=(uint8_t)s->rax,d=(uint8_t)(a-126U);
   uint8_t ov=(uint8_t)((((a^126U)&(a^d))>>7U)&1U);
   s->cf=(uint8_t)(a<126U);s->zf=(uint8_t)(d==0U);s->sf=(uint8_t)(d>>7U);
   s->instructions+=2U;
   s->rip=(!s->zf&&s->sf==ov)?
       UINT64_C({joined.BASE+JG_TAKEN}):UINT64_C({joined.BASE+JG_FALL});
   if(s->rip==UINT64_C({joined.BASE+JG_TAKEN}))
       return native_arg_store(s,m);
   return MX_NATIVE_LINK_FRONTIER_REACHED;
 }}
 if(s->rip==UINT64_C({joined.BASE+JLE_ROOT})){{
   /* Original NOP, CMP AL,0x20, signed JLE. */
   uint8_t a=(uint8_t)s->rax,d=(uint8_t)(a-32U);
   uint8_t ov=(uint8_t)((((a^32U)&(a^d))>>7U)&1U);
   s->cf=(uint8_t)(a<32U);s->zf=(uint8_t)(d==0U);s->sf=(uint8_t)(d>>7U);
   s->instructions+=3U;
   s->rip=(s->zf||s->sf!=ov)?
       UINT64_C({joined.BASE+JLE_TAKEN}):UINT64_C({joined.BASE+JLE_FALL});
   if(s->rip==UINT64_C({joined.BASE+JE_ROOT}))
       return native_three_controls(s,m);
   return MX_NATIVE_LINK_FRONTIER_REACHED;
 }}
 if(s->rip==UINT64_C({joined.BASE+JE_ROOT})){{
   /* Original CMP BYTE PTR [RCX],0; JE, preserve non-flag registers. */
   uint8_t a=0U;
   if(!mx_cfg_transfer(m,s->rcx,&a,1U,0))return MX_GAME_PREFIX_UNMAPPED;
   s->cf=0U;s->zf=(uint8_t)(a==0U);s->sf=(uint8_t)(a>>7U);
   s->rip=s->zf?UINT64_C({joined.BASE+JE_TAKEN}):
                 UINT64_C({joined.BASE+JE_FALL});
   s->instructions+=2U;
   return MX_NATIVE_LINK_FRONTIER_REACHED;
 }}
 return MX_GAME_PREFIX_BAD_STATE;
}}
"""
    source=source.replace(anchor,helper+anchor)
    a=f"""   s->rip=s->sf!=of?UINT64_C({joined.BASE+prev.QUOTE_LT}):
                     UINT64_C({joined.BASE+prev.QUOTE_GE});
   s->instructions+=3U;
   return MX_NATIVE_LINK_FRONTIER_REACHED;"""
    b=f"""   s->rip=s->sf!=of?UINT64_C({joined.BASE+prev.QUOTE_LT}):
                     UINT64_C({joined.BASE+prev.QUOTE_GE});
   s->instructions+=3U;
   if(s->rip==UINT64_C({joined.BASE+prev.QUOTE_LT}))
      return native_arg_store(s,m);
   return native_three_controls(s,m);"""
    if source.count(a)!=1:raise ValueError("Quote JL stage identity missing")
    source=source.replace(a,b)
    a=f"""   s->rip=s->zf?UINT64_C({joined.BASE+prev.NUL}):
                 UINT64_C({joined.BASE+prev.NON_NUL});
   s->instructions+=3U;
   return MX_NATIVE_LINK_FRONTIER_REACHED;"""
    b=f"""   s->rip=s->zf?UINT64_C({joined.BASE+prev.NUL}):
                 UINT64_C({joined.BASE+prev.NON_NUL});
   s->instructions+=3U;
   return native_three_controls(s,m);"""
    if source.count(a)!=1:raise ValueError("Unquoted JE stage identity missing")
    source=source.replace(a,b)
    old=(f"const uint64_t proven_frontiers[4]={{UINT64_C({joined.BASE+prev.QUOTE_LT}),"
         f"UINT64_C({joined.BASE+prev.QUOTE_GE}),UINT64_C({joined.BASE+prev.NON_NUL}),"
         f"UINT64_C({joined.BASE+prev.NUL})}};")
    new=(f"const uint64_t proven_frontiers[4]={{UINT64_C({joined.BASE+JG_FALL}),"
         f"UINT64_C({joined.BASE+JLE_FALL}),UINT64_C({joined.BASE+JE_FALL}),"
         f"UINT64_C({joined.BASE+JE_TAKEN})}};")
    if source.count(old)!=1:raise ValueError("Pinned multi-frontier linker missing")
    source=source.replace(old,new)
    marker=" /* Unknown functions cannot fabricate a successful frontier. */"
    if source.count(marker)!=1:raise ValueError("Native smoke final test hook moved")
    eb=",".join(str(v[0])+"U" for v in isolated)
    ep=",".join("UINT64_C("+str(v[1])+")" for v in isolated)
    flags=lambda index:",".join(str(v[index])+"U" for v in isolated)
    smoke=f""" const uint8_t proof_bytes[3]={{{eb}}};
 const uint64_t proof_targets[3]={{{ep}}};
 const uint8_t proof_cf[3]={{{flags(2)}}}, proof_zf[3]={{{flags(3)}}},proof_sf[3]={{{flags(4)}}};
 for(unsigned k=0;k<3U;k++){{
   mx_crt_cluster_state proof={{0}};
   input_data[0x100U]=proof_bytes[k];
   proof.rip=UINT64_C({joined.BASE+JE_ROOT});
   proof.rcx=TEST_INPUT;
   proof.rax=UINT64_C(0x123456789ABCDEF0);
   if(native_three_controls(&proof,&mem)!=MX_NATIVE_LINK_FRONTIER_REACHED||
      proof.rip!=proof_targets[k]||proof.cf!=proof_cf[k]||
      proof.zf!=proof_zf[k]||proof.sf!=proof_sf[k]||
      proof.rax!=UINT64_C(0x123456789ABCDEF0)||proof.instructions!=2U)
      return 220+(int)k;
 }}
"""
    return source.replace(marker,smoke+marker)

def run(original,out):
    pe=PE(original)
    if hashlib.sha256(pe.b).hexdigest()!=INPUT_SHA:
        raise ValueError("Original owned executable SHA mismatch")
    joined.verify_main(original)
    second.verify_second_branch(pe);third.verify_third_branch(pe)
    pair.verified_pair(pe);followup.verify_original_followup(pe)
    quote.original_branch(pe)
    layout,_,_=joined.inspect_original(pe)
    argv.verify_original_blocks(pe,layout)
    prev.verify_original_next_pair(pe)
    verify_original_controls(pe)
    isolated=original_memory_je_proof(pe)
    samples=[pair.reference(pe,layout,i,arg_group=True,
                            next_branches=True,three_branches=True)
             for i in range(len(INPUT))]
    stops={}
    for i,(_,state,_,_) in enumerate(samples):
        rva=hex(state["rip"]-joined.BASE)
        if rva not in (hex(joined.AFTER_CALL),hex(JG_FALL),
                       hex(JLE_FALL),hex(JE_FALL),hex(JE_TAKEN)):
            raise ValueError("Original main/CALL escaped authenticated parser control")
        stops[rva]=stops.get(rva,0)+1
    if not stops.get(hex(JG_FALL)) or not stops.get(hex(JLE_FALL)):
        raise ValueError("Original JG fallthrough/JLE fallthrough not both covered")
    states=[(pre,result) for pre,result,_,_ in samples]
    statuses=[status for _,_,_,status in samples]
    steps=[n for _,_,n,_ in samples]
    bytes2=[0x7f if i==5 else 0x10 if i==3 else
            0x51 if i==12 else 0 if i==7 else pair.next_byte(i)
            for i in range(len(INPUT))]
    source,_=joined.generate(layout,states)
    source=third.extend_third_jle(second.extend_joined_source(
        source,second.verify_second_branch(pe)))
    source=pair.extend_native_pair(source,bytes2,statuses,steps)
    source=followup.extend_joined_native_followup(source)
    source=quote.extend_quote_native(source)
    source=argv.extend_native_argument_blocks(source,
        [x["argument_slot_before"] for _,x,_,_ in samples],
        [x["argument_slot_after"] for _,x,_,_ in samples],steps)
    source=prev.append_native_pair(source)
    source=append_native(source,isolated)
    with tempfile.TemporaryDirectory(prefix="mxb-original-three-branches-") as tmp:
        wd=Path(tmp);file=wd/"private-real-game-parser-arm64.c"
        file.write_text(source)
        flags=["-O2","-std=c11","-Wall","-Wextra","-Werror",
               "-I",str(ROOT/"arm64-lab"/"runtime"),"-I",str(ROOT/"scripts")]
        host=wd/"host"
        p=subprocess.run(["cc",*flags,"-DHOST",str(file),"-o",str(host)],
                         capture_output=True,text=True)
        if p.returncode:raise RuntimeError("Host native triple compile: "+p.stderr[-2400:])
        p=subprocess.run([str(host)],capture_output=True,text=True)
        if p.returncode:raise RuntimeError("Original x64/host guest mismatch: "+str(p.returncode))
        arm=wd/"private-game-parser-aarch64.elf"
        p=subprocess.run(["clang","--target=aarch64-unknown-linux-gnu",
            "-fuse-ld=lld","-nostdlib","-static","-ffreestanding",
            "-fno-builtin","-fno-stack-protector",*flags,
            "-Wl,-e,smoke","-Wl,-z,max-page-size=4096",
            "-Wl,--build-id=none",str(file),"-o",str(arm)],
            capture_output=True,text=True)
        if p.returncode:raise RuntimeError("ARM64 native triple compile: "+p.stderr[-2400:])
        result=execute_arm64_elf(arm,instruction_budget=2500000,timeout_us=15000000)
        if result["arm64_smoke_exit"]!=0:
            raise RuntimeError("Original x64/AArch64 guest mismatch: "+str(result["arm64_smoke_exit"]))
    out.mkdir(parents=True,exist_ok=True)
    record={"original_sha256":INPUT_SHA,"joined_x64_host_aarch64_proof_cases":len(INPUT),
            "isolated_original_je_x64_aarch64_proof_cases":len(isolated),
            "argv_before_after_checked":len(INPUT),"original_stops":stops,
            "complete_callee_proven":False,"engine_or_ipa_launched":False,
            "original_binary_or_lifted_code_exported":False}
    (out/"joined-parser-three-branches-native.json").write_text(json.dumps(record,indent=2)+"\n")
    lines=["# Original MX Bikes native JG/JLE/JE parser group","",
      "- Joined game-main/CALL original x64/host/ARM64: **16/16**",
      "- Full guest argument-table comparisons: **16/16**",
      "- Original x64/ARM64 bounded standalone memory-JE: **3/3**","",
      "## Real main/CALL endpoints"]
    lines.extend("- "+key+": **"+str(n)+" cases**" for key,n in sorted(stops.items()))
    lines+=["","Neither entire callee nor game engine/menu/IPA has booted.",""]
    (out/"joined-parser-three-branches-native.md").write_text("\n".join(lines))
    print("\n".join(lines))
    return record

if __name__=="__main__":
    if len(sys.argv)!=3:raise SystemExit("usage: triple.py original.exe metadata-dir")
    run(Path(sys.argv[1]),Path(sys.argv[2]))
