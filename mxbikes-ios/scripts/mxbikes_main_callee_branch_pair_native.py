#!/usr/bin/env python3
"""Translate both authenticated post-third-JLE successors within ONE ARM64
game-main -> original Win64 CALL -> original first-callee guest execution.

This adds CMP AL,0x7E; JLE and MOV AL,[RCX+1]; INC RCX; TEST AL,AL; JE.
Original game binary stays SHA-pinned/private. All 16 cases x64/host/AArch64
compare final guest register/flag/global/call-frame state, including both
frontier branches and authentic RETs when the next command byte is NUL.
"""
from pathlib import Path
import hashlib
import json
import struct
import subprocess
import sys
import tempfile

from unicorn import UC_HOOK_CODE
from unicorn.x86_const import (
    UC_X86_REG_RIP,UC_X86_REG_RSP,UC_X86_REG_RAX,UC_X86_REG_RBX,
    UC_X86_REG_RCX,UC_X86_REG_RDX,UC_X86_REG_R8,UC_X86_REG_R9,
    UC_X86_REG_RDI,UC_X86_REG_RSI,UC_X86_REG_R11,UC_X86_REG_R10,
    UC_X86_REG_EFLAGS
)
import mxbikes_main_joined_callee_native as joined
import mxbikes_main_callee_second_jge_native as second
import mxbikes_main_callee_third_jle_native as third
import mxbikes_main_callee_branch_pair_map as mapping
from mxbikes_main_callee_native_branch import INPUT as BYTES
from mxbikes_whole_game_map import INPUT_SHA

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/"arm64-lab"))
from tools.pe_probe import PE
from tools.import_aot_smoke import execute_arm64_elf

AFTER_RETURN=joined.AFTER_CALL # 0x136746 after original callee RET
HIGH_ASCII_TARGET=0x136178
NEXT_CHAR_NOT_ZERO=0x136176
NEXT_CHAR_ZERO=0x136207
NULL_TEST_CASES=frozenset((3,7,10))  # nonzero second-byte tests, independent of first byte
FRONTIERS=frozenset((AFTER_RETURN,HIGH_ASCII_TARGET,NEXT_CHAR_NOT_ZERO))


def next_byte(case):
    return 0x51 if case in NULL_TEST_CASES else 0


def verified_pair(pe):
    a=mapping.first_control(pe,third.FALLTHROUGH)
    b=mapping.first_control(pe,third.TAKEN)
    if not (
        [(v["mnemonic"],v["op_str"]) for v in a["instruction_forms"]]==
        [("cmp","al, 0x7e")] and
        a["control_rva"]=="0x136166" and a["control_kind"]=="jle" and
        a["control_direct_target_rva"]==hex(HIGH_ASCII_TARGET) and
        [(v["mnemonic"],v["op_str"]) for v in b["instruction_forms"]]==
        [("mov","al, byte ptr [rcx + 1]"),("inc","rcx"),("test","al, al")] and
        b["control_rva"]=="0x136170" and b["control_kind"]=="je" and
        b["control_direct_target_rva"]==hex(NEXT_CHAR_ZERO) and
        b["control_next_rva"]==hex(NEXT_CHAR_NOT_ZERO)
    ):
        raise RuntimeError("Exact original grouped callee successor shapes changed")
    return a,b


def reaches_authenticated_frontier(rva,stops,trace,next_branches,parser_loops=False,parser_tail=False):
    """Edge-sensitive stop rules, without regressing older verified stages."""
    if rva not in stops:
        return False
    if parser_tail and rva==0x136152:
        return len(trace)>1 and trace[-2]==joined.BASE+0x136201
    if parser_loops and rva==0x1361e0:
        # 0x1361dc NOP enters the previously proven 0x1361e0 CMP.
        # Only the later x64 JNE at 0x1361f0 is a new loop backedge.
        return len(trace)>1 and trace[-2]==joined.BASE+0x1361f0
    if parser_loops and rva==0x1361f2:
        # Original earlier JLE at 0x1361e2 already executes its zero test;
        # only the later JG/JNE arrivals are new bounded frontiers.
        return len(trace)>1 and trace[-2] in (
            joined.BASE+0x1361e6,joined.BASE+0x1361f0)
    if parser_loops and rva==0x136194:
        # Only stop on the scan's JNE backedge, not at the older 0x136192
        # fallthrough that the native guest already executes.
        return len(trace)>1 and trace[-2]==joined.BASE+0x1361a9
    if next_branches and rva==0x1361b9:
        if len(trace)<2:
            return False
        predecessor=trace[-2]-joined.BASE
        if parser_loops:
            # The prior JL/JG arrivals are already translated through argv
            # storage; only the new quoted scan JMP remains a frontier.
            return predecessor==0x1361ab
        return predecessor in (0x136199,0x13619d,0x1361ab)
    return True


def reference(pe,layout,case,*,followups=False,quote_branch=False,arg_group=False,next_branches=False,three_branches=False,parser_loops=False,parser_tail=False):
    before,_=joined.original_run(pe,layout,case)
    first_byte=(0x22 if (arg_group and case in (3,7)) or
                (next_branches and case==12) or (three_branches and case==5) or (parser_loops and case==10) else
                0x22 if quote_branch and case==3 else BYTES[case])
    second_byte=(0x22 if parser_loops and case==10 else
                 0x7f if three_branches and case==5 else
                 0x10 if next_branches and case==3 else
                 0x51 if next_branches and case==12 else
                 0 if arg_group and case==7 else next_byte(case))
    if first_byte==0:
        _,state=joined.original_run(pe,layout,case)
        if arg_group:
            original_mem=joined.new_cpu(pe)
            value=int.from_bytes(original_mem.mem_read(
                layout["callee_global0"]+8,8),"little")
            state["argument_slot_before"]=value
            state["argument_slot_after"]=value
        if parser_tail:
            state["parser_input_first_after"]=0
            state["parser_input_second_after"]=0
        return before,state,18,"returned"
    uc=joined.new_cpu(pe)
    table_slot=layout["callee_global0"]+8
    table_initial=int.from_bytes(uc.mem_read(table_slot,8),"little")
    uc.mem_write(joined.TEST_INPUT,bytes((first_byte,second_byte)))
    uc.mem_write(joined.ENTRY_SP,struct.pack("<Q",joined.BASE+0x777777))
    initial={
        UC_X86_REG_RIP:joined.BASE+joined.MAIN,
        UC_X86_REG_RSP:joined.ENTRY_SP,
        UC_X86_REG_RAX:0x888876543210+case,
        UC_X86_REG_RBX:joined.SEED_RBX,
        UC_X86_REG_RCX:joined.BASE,
        UC_X86_REG_RDX:0,
        UC_X86_REG_R8:joined.TEST_INPUT,
        UC_X86_REG_R9:10,
        UC_X86_REG_RDI:joined.SEED_RDI,
        UC_X86_REG_RSI:joined.SEED_RSI,
        UC_X86_REG_R11:joined.SEED_R11,
        UC_X86_REG_R10:0x78123456789,
        UC_X86_REG_EFLAGS:0x202|[0,1,0x40,0x80,0xc1,0x41,0x200,0x81][case%8]
    }
    for reg,value in initial.items():
        uc.reg_write(reg,value)
    visited=[]
    stops=(frozenset((AFTER_RETURN,0x1361ad,0x136194,0x1361b9,0x1361e0,0x136152))
           if parser_tail else
           frozenset((AFTER_RETURN,0x1361ad,0x136194,0x1361b9,0x1361e0,0x1361f2)) if parser_loops else
           frozenset((AFTER_RETURN,0x13619f,0x1361e4,0x1361f7,0x1361fd)) if three_branches else
           frozenset((AFTER_RETURN,0x13619b,0x1361b9,0x1361dc,0x1361f2))
           if next_branches else
           frozenset((AFTER_RETURN,0x136194,0x1361d5)) if arg_group
           else frozenset((AFTER_RETURN,0x13618a,0x1361b9)) if quote_branch
           else frozenset((AFTER_RETURN,0x136183)) if followups else FRONTIERS)
    budget=180 if parser_tail else 145 if parser_loops else 110 if three_branches else 76 if next_branches else 64 if arg_group else 54 if quote_branch else 48 if followups else 40
    def stop_at_next_authentic_boundary(cpu,pc,_size,_context):
        visited.append(pc)
        if (reaches_authenticated_frontier(pc-joined.BASE,stops,visited,next_branches,parser_loops,parser_tail)
            or len(visited)>budget):
            cpu.emu_stop()
    uc.hook_add(UC_HOOK_CODE,stop_at_next_authentic_boundary)
    uc.emu_start(joined.BASE+joined.MAIN,0,timeout=4000000,count=budget)
    pc=uc.reg_read(UC_X86_REG_RIP)
    if (not visited or visited[0]!=joined.BASE+joined.MAIN or
        visited[8]!=joined.BASE+joined.CALL_SITE or
        visited[9]!=joined.BASE+joined.CALLEE or
        visited[-1]!=pc or pc-joined.BASE not in stops or
        joined.BASE+third.JLE not in visited):
        raise RuntimeError("Original CALL/third-JLE/pair path escaped bounded trace")
    steps=len(visited)-1
    rsp=uc.reg_read(UC_X86_REG_RSP)
    if rsp!=(joined.ENTRY_SP-0x288 if pc-joined.BASE==AFTER_RETURN else
              joined.ENTRY_SP-0x288-8):
        raise RuntimeError("Original guest CALL stack changed unexpectedly")
    flags=uc.reg_read(UC_X86_REG_EFLAGS)
    result={
       **{name:uc.reg_read(reg) for name,reg in joined.REGISTER_IDS},
       "r10":uc.reg_read(UC_X86_REG_R10),
       "rsp":rsp,"rip":pc,
       "cf":int(bool(flags&1)),"zf":int(bool(flags&64)),
       "sf":int(bool(flags&128)),
       "ret_at_guest_rsp":struct.unpack("<Q",bytes(
           uc.mem_read(joined.ENTRY_SP-0x288-8,8)))[0],
       "saved_cookie":struct.unpack("<Q",bytes(
           uc.mem_read(joined.ENTRY_SP-0x288+0x250,8)))[0],
       "arg0_global":struct.unpack("<Q",bytes(uc.mem_read(layout["arg0_va"],8)))[0],
       "arg1_global":struct.unpack("<Q",bytes(uc.mem_read(layout["arg1_va"],8)))[0],
       "show_global":struct.unpack("<I",bytes(uc.mem_read(layout["show_va"],4)))[0],
       "callee_global0":struct.unpack("<Q",bytes(
           uc.mem_read(layout["callee_global0"],8)))[0],
       "callee_global1":struct.unpack("<I",bytes(
           uc.mem_read(layout["callee_global1"],4)))[0],
       "input_byte":first_byte,
    }
    if arg_group:
        result["argument_slot_before"]=table_initial
        result["argument_slot_after"]=int.from_bytes(uc.mem_read(table_slot,8),"little")
    if parser_tail:
        result["parser_input_first_after"]=int.from_bytes(
            uc.mem_read(joined.TEST_INPUT,1),"little")
        result["parser_input_second_after"]=int.from_bytes(
            uc.mem_read(joined.TEST_INPUT+1,1),"little")
    expected_count=(2 if arg_group and (
        pc-joined.BASE in (0x1361d5,0x1361dc,0x1361f2,0x1361e4,
                          0x1361f7,0x1361fd,0x1361e0,0x136152)
        or (parser_tail and pc-joined.BASE==AFTER_RETURN
            and first_byte!=0 and int.from_bytes(
                uc.mem_read(layout["callee_global1"],4),"little")==2))
        else 1)
    if (result["ret_at_guest_rsp"]!=layout["return_va"] or
        result["r10"]!=expected_count or
        steps<24 or
        steps>(180 if parser_tail else 145 if parser_loops else 110 if three_branches else 76 if next_branches else 64 if arg_group else 54 if quote_branch else 46 if followups else 34)):
        raise RuntimeError("Original nonempty guest proof incomplete")
    status="returned" if pc-joined.BASE==AFTER_RETURN else "frontier"
    return before,result,steps,status


def extend_native_pair(source,second_bytes,statuses,steps):
    """Patch ONLY proven x64 identities into the existing linked ARM64 guest."""
    if len(second_bytes)!=16 or len(statuses)!=16 or len(steps)!=16:
        raise ValueError("Original fixture count changed")
    old=""" s->rip=jle?UINT64_C(5369987432):UINT64_C(5369987428);
 s->instructions+=3U;
 return MX_NATIVE_LINK_FRONTIER_REACHED;"""
    # Avoid an ungrounded constant: produce exact original VA spellings.
    old=(f" s->rip=jle?UINT64_C({joined.BASE+third.TAKEN}):"
         f"UINT64_C({joined.BASE+third.FALLTHROUGH});\n"
         " s->instructions+=3U;\n"
         " return MX_NATIVE_LINK_FRONTIER_REACHED;")
    new=(f" s->rip=jle?UINT64_C({joined.BASE+third.TAKEN}):"
         f"UINT64_C({joined.BASE+third.FALLTHROUGH});\n"
         " s->instructions+=3U;\n"
         " return native_branch_pair(s,m);")
    if source.count(old)!=1:
        raise ValueError("Previously verified native third JLE source identity moved")
    helper=f"""
static int native_branch_pair(mx_crt_cluster_state*s,mx_cfg_memory*m){{
 if(!s||!m||s->fault)return MX_GAME_PREFIX_BAD_STATE;
 if(s->rip==UINT64_C({joined.BASE+third.FALLTHROUGH})){{
    /* Original CMP AL,0x7e; JLE 0x136178. */
    const uint8_t lhs=(uint8_t)s->rax;
    const uint8_t diff=(uint8_t)(lhs-126U);
    const uint8_t of=(uint8_t)((((lhs^126U)&(lhs^diff))>>7U)&1U);
    s->cf=(uint8_t)(lhs<126U);
    s->zf=(uint8_t)(diff==0U);
    s->sf=(uint8_t)(diff>>7U);
    s->instructions+=2U;
    if(s->zf||(s->sf!=of)){{
        s->rip=UINT64_C({joined.BASE+HIGH_ASCII_TARGET});
        return MX_NATIVE_LINK_FRONTIER_REACHED;
    }}
    s->rip=UINT64_C({joined.BASE+third.TAKEN});
 }}
 if(s->rip!=UINT64_C({joined.BASE+third.TAKEN}))
    return MX_GAME_PREFIX_BAD_STATE;
 /* Original MOV AL,[RCX+1]; INC RCX; TEST AL,AL; JE 0x136207. */
 if(s->rcx==UINT64_MAX)return MX_GAME_PREFIX_BAD_STATE;
 uint8_t next_char=0U;
 if(!mx_cfg_transfer(m,s->rcx+1U,&next_char,1U,0))
    return MX_GAME_PREFIX_UNMAPPED;
 s->rax=(s->rax&~UINT64_C(255))|(uint64_t)next_char;
 s->rcx+=1U;
 s->zf=(uint8_t)(next_char==0U);
 s->sf=(uint8_t)((next_char>>7U)&1U);
 s->cf=0U;
 s->rip=next_char?UINT64_C({joined.BASE+NEXT_CHAR_NOT_ZERO}):
                   UINT64_C({joined.BASE+NEXT_CHAR_ZERO});
 s->instructions+=4U;
 if(!next_char)
    return mx_game_main_callee_finish_empty(s,m,&callee_layout);
 return MX_NATIVE_LINK_FRONTIER_REACHED;
}}
"""
    caller="static int native_nonempty_jge(mx_crt_cluster_state*s,mx_cfg_memory*m){"
    if source.count(caller)!=1:
        raise ValueError("Linked nonempty successor callback missing")
    source=source.replace(caller,helper+caller)
    source=source.replace(old,new)
    source=source.replace(
        f"r,s,m,CALLEE,AFTER_CALL,UINT64_C({joined.BASE+third.TAKEN}),"
        f"UINT64_C({joined.BASE+third.FALLTHROUGH}));",
        f"r,s,m,CALLEE,AFTER_CALL,UINT64_C({joined.BASE+HIGH_ASCII_TARGET}),"
        f"UINT64_C({joined.BASE+NEXT_CHAR_NOT_ZERO}));")
    replacement="s.instructions!=(f->in_byte==0U?18U:23U)"
    if source.count(replacement)!=1:
        raise ValueError("Original third-JLE instruction count assertion moved")
    source=source.replace(replacement,"s.instructions!=expected_steps[i]")
    compare="int result=main_to_callee(&s,&mem,&r);\n   if(result!=(f->in_byte==0U?MX_NATIVE_LINK_OK:\n                 MX_NATIVE_LINK_FRONTIER_REACHED))return 3;"
    if source.count(compare)!=1:
        raise ValueError("Original native linker return assertion moved")
    source=source.replace(compare,
        "int result=main_to_callee(&s,&mem,&r);\n   if(result!=expected_status[i])return 3;")
    source=source.replace("input_data[0x100U]=f->in_byte;",
        "input_data[0x100U]=f->in_byte;input_data[0x101U]=second_chars[i];")
    old_count="r.calls_completed!=taken)"
    if source.count(old_count)!=1:
        raise ValueError("Original link registry call count assertion moved")
    source=source.replace(old_count,
        "r.calls_completed!="+str(sum(x=="returned" for x in statuses))+"U)")
    anchor="static uint64_t read_guest(mx_cfg_memory*m,uint64_t addr,unsigned size){"
    if source.count(anchor)!=1:
        raise ValueError("Authentic guest read helper missing")
    arrays=(
        "static const uint8_t second_chars[CASES]={"+
            ",".join(str(x) for x in second_bytes)+"};\n"+
        "static const int expected_status[CASES]={"+
            ",".join("MX_NATIVE_LINK_OK" if x=="returned" else
                     "MX_NATIVE_LINK_FRONTIER_REACHED" for x in statuses)+"};\n"+
        "static const uint32_t expected_steps[CASES]={"+
            ",".join(str(x)+"U" for x in steps)+"};\n"
    )
    source=source.replace(anchor,arrays+anchor)
    old_assert="""   if(current_branch.r10!=f->r10 || s.rsp!=f->rsp ||
      s.rip!=f->rip || s.cf!=f->cf||s.zf!=f->zf||s.sf!=f->sf ||
      read_guest(&mem,ENTRY_SP-0x288U-8U,8U)!=f->ret_at_guest_rsp ||
      read_guest(&mem,ENTRY_SP-0x288U+0x250U,8U)!=f->saved_cookie)
       return 5;"""
    new_assert="""   if(current_branch.r10!=f->r10)return 50+(int)i;
   if(s.rsp!=f->rsp)return 70+(int)i;
   if(s.rip!=f->rip){
     if(s.rip==UINT64_C(5369979256))return 200+(int)i;
     if(s.rip==UINT64_C(5369979250))return 180+(int)i;
     if(s.rip==UINT64_C(5369979399))return 160+(int)i;
     if(s.rip==UINT64_C(5369979240))return 140+(int)i;
     if(s.rip==AFTER_CALL)return 120+(int)i;
     return 90+(int)i;
   }
   if(s.cf!=f->cf)return 110+(int)i;
   if(s.zf!=f->zf)return 130+(int)i;
   if(s.sf!=f->sf)return 150+(int)i;
   if(read_guest(&mem,ENTRY_SP-0x288U-8U,8U)!=f->ret_at_guest_rsp)
     return 170+(int)i;
   if(read_guest(&mem,ENTRY_SP-0x288U+0x250U,8U)!=f->saved_cookie)
     return 190+(int)i;"""
    if source.count(old_assert)!=1:
        raise ValueError("Original guest ABI strict state assertion changed")
    source=source.replace(old_assert,new_assert)
    if "return native_branch_pair(s,m);" not in source or (
        "r,s,m,CALLEE,AFTER_CALL,UINT64_C("+
        str(joined.BASE+HIGH_ASCII_TARGET)) not in source:
        raise ValueError("Native original branch CALL frontier not wired")
    return source


def run(original,out):
    pe=PE(original)
    if hashlib.sha256(pe.b).hexdigest()!=INPUT_SHA:
        raise RuntimeError("Original owned game SHA differs from verified revision")
    second.verify_second_branch(pe)
    third.verify_third_branch(pe)
    verified_pair(pe)
    joined.verify_main(original)
    layout,_,_=joined.inspect_original(pe)
    observations=[reference(pe,layout,i) for i in range(len(BYTES))]
    print("Original x64 expected successor RVAs and tested bytes:",
          [(i,hex(v["rip"]-joined.BASE),next_byte(i),status)
           for i,(_,v,_,status) in enumerate(observations)],flush=True)
    refs=[(pre,state) for pre,state,_,_ in observations]
    statuses=[status for _,_,_,status in observations]
    steps=[step for _,_,step,_ in observations]
    second_chars=[next_byte(i) for i in range(len(BYTES))]
    src,pages=joined.generate(layout,refs)
    src=third.extend_third_jle(second.extend_joined_source(
        src,second.verify_second_branch(pe)))
    src=extend_native_pair(src,second_chars,statuses,steps)
    with tempfile.TemporaryDirectory(prefix="mxb-original-jle-pair-") as td:
        root=Path(td);file=root/"original-main-joined-both-successors.c"
        file.write_text(src)
        flags=["-O2","-std=c11","-Wall","-Wextra","-Werror",
               "-I",str(ROOT/"arm64-lab"/"runtime")]
        host=root/"host"
        p=subprocess.run(["cc",*flags,"-DHOST",str(file),"-o",str(host)],
                         capture_output=True,text=True)
        if p.returncode:
            raise RuntimeError("Original native pair host compile: "+p.stderr[-2400:])
        p=subprocess.run([str(host)],capture_output=True,text=True)
        if p.returncode:
            raise RuntimeError("Original x64/host entire-state mismatch: "+str(p.returncode))
        arm=root/"original-native-pair-aarch64.elf"
        p=subprocess.run(["clang","--target=aarch64-unknown-linux-gnu",
                          "-fuse-ld=lld","-nostdlib","-static","-ffreestanding",
                          "-fno-builtin","-fno-stack-protector",*flags,
                          "-Wl,-e,smoke","-Wl,-z,max-page-size=4096",
                          "-Wl,--build-id=none",str(file),"-o",str(arm)],
                         capture_output=True,text=True)
        if p.returncode:
            raise RuntimeError("Original native pair ARM64 compile: "+p.stderr[-2400:])
        result=execute_arm64_elf(arm,instruction_budget=2000000,timeout_us=15000000)
        if result["arm64_smoke_exit"]!=0:
            raise RuntimeError("Original x64/AArch64 pair guest-state mismatch: "+
                               str(result["arm64_smoke_exit"]))
    labels={}
    for _,state,_,status in observations:
        key=hex(state["rip"]-joined.BASE)
        labels[key]=labels.get(key,0)+1
    out.mkdir(parents=True,exist_ok=True)
    report={
        "original_sha256":INPUT_SHA,
        "original_game_main_to_callee_rvas":[hex(joined.MAIN),hex(joined.CALLEE)],
        "matched_x64_native_host_and_aarch64_cases":len(BYTES),
        "original_branch_pair_entries":[hex(third.FALLTHROUGH),hex(third.TAKEN)],
        "completed_original_callee_ret_cases":sum(x=="returned" for x in statuses),
        "native_original_frontier_distribution":labels,
        "original_nonempty_callee_all_paths_verified":False,
        "original_win64_call_stack_return_verified":True,
        "native_game_boot":False,
        "exported_game_binary_or_translated_code":False,
    }
    (out/"main-callee-both-successors-native.json").write_text(json.dumps(report,indent=2)+"\n")
    lines=["# MX Bikes real ARM64 original game-main joined two JLE successors","",
        "- x64/host/executed ARM64 full guest-state fixtures: **"+str(len(BYTES))+
         "/"+str(len(BYTES))+"**",
        "- Original callee Win64 CALL/RET cases: **"+
         str(report["completed_original_callee_ret_cases"])+"**",
        "- Original command-byte successor RVAs: **0x136164, 0x136168**","",
        "## Executed original final frontiers"]
    lines += ["- "+k+": **"+str(v)+" cases**" for k,v in sorted(labels.items())]
    lines += ["","Native full game main, full command parser, graphics, menu, and iOS IPA: **NO**",""]
    (out/"main-callee-both-successors-native.md").write_text("\n".join(lines))
    print("\n".join(lines))
    return report


if __name__=="__main__":
    if len(sys.argv)!=3:
        raise SystemExit("usage: pair_native.py original-owned.exe output-directory")
    run(Path(sys.argv[1]),Path(sys.argv[2]))
