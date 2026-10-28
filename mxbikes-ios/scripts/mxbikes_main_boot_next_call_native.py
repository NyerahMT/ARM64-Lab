#!/usr/bin/env python3
"""Cumulative original MX Bikes Win64 guest boot until next game-main CALL.

After completing original command parser, filename scan, helper RET and
modeled CWD API, execute actual original 0x136772 MOV ECX,global and
0x136778 LEA RDX,constant on native AArch64; stop exactly before original
0x13677f CALL 0x133e80. The SHA-pinned x64 original runs both instructions
independently as a guest-state differential. No game engine or iOS boot.
"""
import json,sys
from pathlib import Path
from capstone import Cs,CS_ARCH_X86,CS_MODE_64,CS_GRP_CALL
from capstone.x86 import X86_OP_IMM
from unicorn.x86_const import UC_X86_REG_RIP,UC_X86_REG_RCX,UC_X86_REG_RDX,UC_X86_REG_RSP
import mxbikes_main_boot_cwd_native as parent
import mxbikes_main_joined_callee_native as joined

BASE=joined.BASE
ENTRY=0x136772
CALLSITE=0x13677f
NEXT=0x133e80
GLOBAL_RVA=0x136778+0xd14678
CONSTANT_RVA=0x13677f+0xd146a1
COUNT=parent.COUNT

def original_x64_next(pe, post_parser_dword=None):
    cs=Cs(CS_ARCH_X86,CS_MODE_64);cs.detail=True
    seen=list(cs.disasm(pe.read_rva(ENTRY,CALLSITE+5-ENTRY),ENTRY))
    forms=[
        ("mov","ecx, dword ptr [rip + 0xd14678]"),
        ("lea","rdx, [rip + 0xd146a1]"),
        ("call","0x133e80")]
    if(len(seen)!=3 or [(x.mnemonic,x.op_str) for x in seen]!=forms or
       seen[2].address!=CALLSITE or
       not seen[2].group(CS_GRP_CALL) or
       seen[2].operands[0].type!=X86_OP_IMM or
       seen[2].operands[0].imm!=NEXT):
        raise ValueError("Original game-main post-CWD guest source changed")
    cpu=joined.new_cpu(pe)
    cpu.reg_write(UC_X86_REG_RIP,BASE+ENTRY)
    cpu.reg_write(UC_X86_REG_RSP,joined.ENTRY_SP-0x288)
    cpu.reg_write(UC_X86_REG_RCX,0x5a5a5a5a)
    cpu.reg_write(UC_X86_REG_RDX,0xa5a5a5a5)
    if post_parser_dword is not None:
        if not isinstance(post_parser_dword,int) or not 0<=post_parser_dword<=0xffffffff:
            raise ValueError("Original parser global is not a valid DWORD")
        # The prior real x64 parser sets this same image global; replay its
        # measured output, not the pristine executable's .data value.
        cpu.mem_write(BASE+GLOBAL_RVA,post_parser_dword.to_bytes(4,"little"))
    cpu.emu_start(BASE+ENTRY,0,timeout=1000000,count=2)
    value=int.from_bytes(bytes(cpu.mem_read(BASE+GLOBAL_RVA,4)),"little")
    if(cpu.reg_read(UC_X86_REG_RIP)!=BASE+CALLSITE or
       cpu.reg_read(UC_X86_REG_RCX)!=value or
       cpu.reg_read(UC_X86_REG_RDX)!=BASE+CONSTANT_RVA):
        raise ValueError("Original Win64 global/constant x64 instructions mismatch")
    return value

def append_next(pe,source,cases):
    parent.verify_cwd_original(pe)
    layout,_,_=joined.inspect_original(pe)
    # The 0x136772 global aliases the parser's output flag global.
    # A pristine PE DWORD is the wrong oracle after that parser ran.
    if layout["callee_global1"]!=BASE+GLOBAL_RVA:
        raise ValueError("Original post-CWD global does not alias parser output")
    if len(cases)!=16:
        raise ValueError("Original parser fixture count changed")
    returned=[row for _,row,_,kind in cases
              if kind=="returned" and row["rip"]==BASE+joined.AFTER_CALL]
    if len(returned)!=COUNT:
        raise ValueError("Complete original helper return coverage changed")
    # Cases have genuine, distinct x64 parse results. Never assume that
    # pristine PE .data or a single fixture represents every command line.
    expected_values=[]
    for _,row,_,kind in cases:
        valid=kind=="returned" and row["rip"]==BASE+joined.AFTER_CALL
        value=row["callee_global1"] if valid else 0
        if not isinstance(value,int) or not 0<=value<=0xffffffff:
            raise ValueError("Original parser produced invalid next-call DWORD")
        expected_values.append(value)
    for value in set(row["callee_global1"] for row in returned):
        if original_x64_next(pe,post_parser_dword=value)!=value:
            raise ValueError("Original post-parser x64 MOV/LEA replay diverged")
    field="static int main_to_callee(mx_crt_cluster_state*s,mx_cfg_memory*m,"
    if source.count(field)!=1:
        raise ValueError("Native original game entrypoint moved")
    array=("static const uint32_t original_next_dword[CASES]={"+
           ",".join(str(v)+"U" for v in expected_values)+"};\n")
    source=source.replace(field,array+field)
    count=" unsigned genuine_directory_returns=0U;"
    if source.count(count)!=1:raise ValueError("Previous authentic directory counter missing")
    source=source.replace(count,count+"\n unsigned next_call_frontiers=0U;")
    point="      genuine_directory_returns++;"
    if source.count(point)!=1:raise ValueError("Original CWD API proof anchor missing")
    snippet=f"""
      /* Original guest main: MOV ECX,[RIP+0xd14678]; LEA RDX,[RIP+0xd146a1].
       * Do NOT execute unregistered original CALL 0x133e80. */
      const unsigned before_next=s.instructions;
      if(mx_game_main_after_cwd_prepare(&s,&mem,
          UINT64_C({BASE+ENTRY}),UINT64_C({BASE+GLOBAL_RVA}),
          UINT64_C({BASE+CONSTANT_RVA}),UINT64_C({BASE+CALLSITE}))!=
          MX_GAME_CWD_OK)
         return 222;
      if(s.rip!=UINT64_C({BASE+CALLSITE}))return 225;
      if(s.rcx!=(uint64_t)original_next_dword[i])return 226;
      if(s.rdx!=UINT64_C({BASE+CONSTANT_RVA}))return 227;
      if(s.imports!=3U)return 228;
      if(s.instructions!=before_next+2U)return 229;
      next_call_frontiers++;
"""
    source=source.replace(point,point+"\n"+snippet)
    gate=" if(genuine_directory_returns!=12U)return 221;"
    if source.count(gate)!=1:raise ValueError("Cumulative native CWD gate changed")
    source=source.replace(gate,gate+"\n if(next_call_frontiers!=12U)return 224;")
    return source

def run(executable,out,*,native_extension=None):
    from tools.pe_probe import PE
    pe=PE(executable)
    global_value=original_x64_next(pe)
    def combined_extension(pe,source,cases):
        source=append_next(pe,source,cases)
        return native_extension(pe,source,cases) if native_extension is not None else source
    earlier=parent.run(executable,out,native_extension=combined_extension)
    if earlier["full_original_filename_helper_win64_native_ret_cases"]!=COUNT:
        raise ValueError("Previous complete helper native proof regressed")
    report={
        "original_sha256":earlier["original_sha256"],
        "native_arm64_command_parser_cases":16,
        "native_arm64_full_helper_cwd_main_args_cases":COUNT,
        "original_next_global_initial_dword":global_value,
        "original_game_main_next_callsite":hex(CALLSITE),
        "original_next_untranslated_callee":hex(NEXT),
        "next_callee_not_executed":True,
        "game_engine_or_ios_app_booted":False
    }
    (out/"joined-native-boot-nextcall.json").write_text(json.dumps(report,indent=2)+"\n")
    summary=["# MX Bikes native game-main startup: next internal CALL frontier","",
      "- Authentic original startup/parser ARM64: **16/16**",
      "- Filename helper RET / CWD / next original argument load: **12/12**",
      "- Original x64 guest MOV/LEA register differential: **PASS**",
      "- Next untranslated original CALL: **"+hex(CALLSITE)+
         " -> "+hex(NEXT)+"**","",
      "Stop before executing unregistered game callee. No game boot or IPA.",""]
    (out/"joined-native-boot-nextcall.md").write_text("\n".join(summary))
    print("\n".join(summary))
    return report

if __name__=="__main__":
    if len(sys.argv)!=3:raise SystemExit("usage: boot-nextcall.py original.exe output")
    run(Path(sys.argv[1]),Path(sys.argv[2]))
