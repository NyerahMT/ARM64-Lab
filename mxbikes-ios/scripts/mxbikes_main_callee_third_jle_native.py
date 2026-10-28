#!/usr/bin/env python3
"""Verify original joined main/first callee through the third branch on ARM64.

Completes 23 original x64 instructions on nonempty command path, including
the exactly SHA-checked 0x13615f NOP; CMP AL,0x20; JLE 0x136168.
The original Win64 call remains outstanding at this frontier. Both real JLE
successors are tested under original Unicorn and native AArch64 execution.
"""
from pathlib import Path
import hashlib
import json
import subprocess
import sys
import tempfile

from capstone import Cs,CS_ARCH_X86,CS_MODE_64,CS_GRP_JUMP
from capstone.x86 import X86_OP_IMM

import mxbikes_main_joined_callee_native as joined
import mxbikes_main_callee_second_jge_native as second
from mxbikes_main_callee_native_branch import INPUT as BYTE_CASES
from mxbikes_whole_game_map import INPUT_SHA

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/"arm64-lab"))
from tools.pe_probe import PE
from tools.import_aot_smoke import execute_arm64_elf

START=0x13615f
CMP=0x136160
JLE=0x136162
TAKEN=0x136168
FALLTHROUGH=0x136164


def verify_third_branch(pe):
    md=Cs(CS_ARCH_X86,CS_MODE_64);md.detail=True
    source=bytes(pe.read_rva(START,FALLTHROUGH-START))
    instructions=list(md.disasm(source,START))
    shapes=[("nop","",START),("cmp","al, 0x20",CMP),
            ("jle","0x136168",JLE)]
    if (len(instructions)!=3 or
        [(i.mnemonic,i.op_str,i.address) for i in instructions]!=shapes or
        sum(i.size for i in instructions)!=len(source) or
        not instructions[-1].group(CS_GRP_JUMP) or
        instructions[-1].operands[0].type!=X86_OP_IMM or
        instructions[-1].operands[0].imm!=TAKEN):
        raise ValueError("Original callee signed-byte third-JLE identity changed")
    return len(instructions)


def extend_third_jle(source):
    """Append real signed-byte x64 CMP/JLE to native joined CALL callback."""
    start=""" s->rip=ge?SECOND_JGE_TAKEN:SECOND_JGE_FALLTHROUGH;
 s->instructions+=4U;
 return MX_NATIVE_LINK_FRONTIER_REACHED;
}"""
    end=f""" s->instructions+=4U;
 if(ge){{
   s->rip=SECOND_JGE_TAKEN;
   return MX_NATIVE_LINK_FRONTIER_REACHED;
 }}
 /* Original NOP, CMP AL,0x20, JLE signed. */
 const uint8_t al=(uint8_t)s->rax;
 const uint8_t rhs8=32U;
 const uint8_t subtract=(uint8_t)(al-rhs8);
 const uint8_t of=(uint8_t)((((al^rhs8)&(al^subtract))>>7U)&1U);
 s->cf=(uint8_t)(al<rhs8);
 s->sf=(uint8_t)((subtract>>7U)&1U);
 s->zf=(uint8_t)(subtract==0U);
 const uint8_t jle=(uint8_t)(s->zf || (s->sf!=of));
 s->rip=jle?UINT64_C({joined.BASE+TAKEN}):UINT64_C({joined.BASE+FALLTHROUGH});
 s->instructions+=3U;
 return MX_NATIVE_LINK_FRONTIER_REACHED;
}}"""
    if source.count(start)!=1:
        raise ValueError("Proven second-JGE source stage not linked")
    source=source.replace(start,end)
    old="r,s,m,CALLEE,AFTER_CALL,TAKEN,SECOND_JGE_FALLTHROUGH);"
    new=f"r,s,m,CALLEE,AFTER_CALL,UINT64_C({joined.BASE+TAKEN}),UINT64_C({joined.BASE+FALLTHROUGH}));"
    if source.count(old)!=1:
        raise ValueError("Original Win64 linker frontier identity changed")
    source=source.replace(old,new)
    old_count="s.instructions!=(f->in_byte==0U?18U:20U)"
    if source.count(old_count)!=1:
        raise ValueError("Second-JGE instruction counter changed")
    return source.replace(old_count,"s.instructions!=(f->in_byte==0U?18U:23U)")


def run(original,out):
    pe=PE(original)
    if hashlib.sha256(pe.b).hexdigest()!=INPUT_SHA:
        raise ValueError("Original owned MX Bikes executable SHA changed")
    second.verify_second_branch(pe)
    verify_third_branch(pe)
    joined.verify_main(original)
    layout,_,_=joined.inspect_original(pe)
    evidence=[second.original_reference(pe,layout,k,through_third_jle=True)
              for k in range(len(BYTE_CASES))]
    src,pages=joined.generate(layout,evidence)
    lea_va=second.verify_second_branch(pe)
    src=extend_third_jle(second.extend_joined_source(src,lea_va))
    with tempfile.TemporaryDirectory(prefix="mxb-original-third-jle-") as td:
        root=Path(td);code=root/"original-guest-second-third-jle.c"
        code.write_text(src)
        opts=["-O2","-std=c11","-Wall","-Wextra","-Werror",
              "-I",str(ROOT/"arm64-lab"/"runtime")]
        host=root/"host"
        p=subprocess.run(["cc",*opts,"-DHOST",str(code),"-o",str(host)],
                         capture_output=True,text=True)
        if p.returncode:
            raise RuntimeError("Native host third-JLE compile: "+p.stderr[-2400:])
        p=subprocess.run([str(host)],capture_output=True,text=True)
        if p.returncode:
            raise RuntimeError("Original x64/host third-JLE state mismatch "+str(p.returncode))
        arm=root/"joined-original-third-jle-aarch64.elf"
        p=subprocess.run(["clang","--target=aarch64-unknown-linux-gnu",
            "-fuse-ld=lld","-nostdlib","-static","-ffreestanding",
            "-fno-builtin","-fno-stack-protector",*opts,
            "-Wl,-e,smoke","-Wl,-z,max-page-size=4096",
            "-Wl,--build-id=none",str(code),"-o",str(arm)],
            capture_output=True,text=True)
        if p.returncode:
            raise RuntimeError("Native ARM64 third-JLE compiler: "+p.stderr[-2400:])
        res=execute_arm64_elf(arm,instruction_budget=1950000,timeout_us=15000000)
        if res["arm64_smoke_exit"]!=0:
            raise RuntimeError("Original x64/AArch64 third-JLE differential: "+
                               str(res["arm64_smoke_exit"]))
    empty=sum(v==0 for v in BYTE_CASES)
    nonempty=[v for v in BYTE_CASES if v!=0]
    taken=sum(((v&0x80)!=0 or v<=0x20) for v in nonempty)
    report={
      "original_sha256":INPUT_SHA,
      "original_main_rva":hex(joined.MAIN),
      "original_callee_rva":hex(joined.CALLEE),
      "original_nonempty_third_jle_rva":hex(JLE),
      "full_guest_state_x64_host_arm64_differential_cases":len(BYTE_CASES),
      "nonempty_original_instructions_through_jle":23,
      "original_instructions_since_first_nonempty_je":7,
      "nonempty_original_jle_taken_cases":taken,
      "nonempty_original_jle_fallthrough_cases":len(nonempty)-taken,
      "empty_original_return_cases":empty,
      "original_win64_call_stack_verified":True,
      "untranslated_successor_roots":[hex(TAKEN),hex(FALLTHROUGH)],
      "nonempty_original_function_returned":False,
      "complete_game_main_or_engine_started":False,
      "original_game_or_generated_code_exported":False
    }
    out.mkdir(parents=True,exist_ok=True)
    (out/"joined-main-third-jle-native.json").write_text(json.dumps(report,indent=2)+"\n")
    text=["# MX Bikes native joined main through third original callee JLE","",
      "- Original x64 / compiled host / executed ARM64 fixtures: **"+
        str(len(BYTE_CASES))+"/"+str(len(BYTE_CASES))+"**",
      "- Nonempty original instructions advanced: **7** beyond first JE",
      "- Nonempty total original joined instructions: **23**",
      "- Signed-byte JLE taken/fallthrough fixtures: **"+
        str(taken)+"/"+str(len(nonempty)-taken)+"**",
      "- Original Win64 call-return slot verified: **YES**",
      "- New native frontier branch targets: **"+hex(TAKEN)+" and "+
        hex(FALLTHROUGH)+"**",
      "- Full game function, native executable, menu or iOS IPA: **NO**",""]
    (out/"joined-main-third-jle-native.md").write_text("\n".join(text))
    print("\n".join(text))
    return report


if __name__=="__main__":
    if len(sys.argv)!=3:
        raise SystemExit("usage: third_jle.py original-mxbikes.exe metadata-dir")
    run(Path(sys.argv[1]),Path(sys.argv[2]))
