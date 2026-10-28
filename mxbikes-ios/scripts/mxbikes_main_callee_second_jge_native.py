#!/usr/bin/env python3
"""Advance authentic game-main -> original CALL -> callee through second JGE.

The original 0x136120 callee's nonempty JE-fallthrough at 0x136146 contains
MOV RDX,[RSP+8], LEA R11,[RIP+disp], CMP R10D,0x80, JGE 0x136207.
Execute the full joined main/first-JE/second-JGE under original x64 Unicorn,
compile the equivalent guest-state code for host and real AArch64, and compare
all 16 full-state fixtures. No full callee, game boot or guessed code accepted.
"""
from pathlib import Path
import hashlib
import json
import struct
import subprocess
import sys
import tempfile

from capstone import Cs,CS_ARCH_X86,CS_MODE_64,CS_GRP_JUMP,CS_GRP_CALL,CS_GRP_RET
from capstone.x86 import X86_OP_IMM
from unicorn import Uc,UC_ARCH_X86,UC_MODE_64,UC_HOOK_CODE
from unicorn.x86_const import (
    UC_X86_REG_RIP,UC_X86_REG_RSP,UC_X86_REG_RAX,UC_X86_REG_RBX,
    UC_X86_REG_RCX,UC_X86_REG_RDX,UC_X86_REG_R8,UC_X86_REG_R9,
    UC_X86_REG_RDI,UC_X86_REG_RSI,UC_X86_REG_R11,UC_X86_REG_R10,
    UC_X86_REG_EFLAGS
)

import mxbikes_main_joined_callee_native as joined
from mxbikes_main_callee_native_branch import INPUT as BYTE_CASES
from mxbikes_whole_game_map import INPUT_SHA

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/"arm64-lab"))
from tools.pe_probe import PE
from tools.import_aot_smoke import execute_arm64_elf

ENTRY=0x136146
JGE=0x136159
JGE_FALLTHROUGH=0x13615f
JGE_TAKEN=0x136207
MOV=ENTRY
LEA=0x13614b
CMP=0x136152
MAX_CASES=16


def verify_second_branch(pe):
    md=Cs(CS_ARCH_X86,CS_MODE_64);md.detail=True
    body=bytes(pe.read_rva(ENTRY,JGE_FALLTHROUGH-ENTRY))
    instructions=list(md.disasm(body,ENTRY))
    shapes=[
        ("mov","rdx, qword ptr [rsp + 8]",MOV),
        ("lea","r11, [rip + 0xd14cce]",LEA),
        ("cmp","r10d, 0x80",CMP),
        ("jge","0x136207",JGE),
    ]
    if (len(instructions)!=4 or
        [(x.mnemonic,x.op_str,x.address) for x in instructions]!=shapes or
        sum(x.size for x in instructions)!=len(body) or
        not instructions[-1].group(CS_GRP_JUMP) or
        instructions[-1].operands[0].type!=X86_OP_IMM or
        instructions[-1].operands[0].imm!=JGE_TAKEN):
        raise ValueError("Original nonempty 0x136146..0x136159 opcode identity changed")
    lea=LEA+instructions[1].size+instructions[1].operands[1].mem.disp
    if not 0<lea<128*1024*1024:
        raise ValueError("Original RIP-LEA destination outside bounded module image")
    return joined.BASE+lea


def original_reference(pe,layout,case,*,through_third_jle=False):
    # Start with the same original x64 Win64 call frame, original global memory
    # and deterministic inputs as the separately proven first-branch test.
    pre,original=joined.original_run(pe,layout,case)
    if BYTE_CASES[case]==0:
        return pre,original
    uc=joined.new_cpu(pe)
    uc.mem_write(joined.TEST_INPUT,bytes([BYTE_CASES[case]]))
    uc.mem_write(joined.ENTRY_SP,struct.pack("<Q",joined.BASE+0x777777))
    seed={
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
    for k,v in seed.items():uc.reg_write(k,v)
    trace=[]
    uc.hook_add(UC_HOOK_CODE,lambda _u,address,_size,_ctx:trace.append(address))
    count=23 if through_third_jle else 20
    uc.emu_start(joined.BASE+joined.MAIN,0,timeout=3000000,count=count)
    expected=[MOV,LEA,CMP,JGE]+([0x13615f,0x136160,0x136162]
                                   if through_third_jle else [])
    branch_target=(
        0x136168 if (BYTE_CASES[case]&0x80 or BYTE_CASES[case]<=0x20)
        else 0x136164
    ) if through_third_jle else JGE_FALLTHROUGH
    if (len(trace)!=count or trace[0]!=joined.BASE+joined.MAIN or
        trace[8]!=joined.BASE+joined.CALL_SITE or
        trace[9]!=joined.BASE+joined.CALLEE or
        trace[-len(expected):]!=[joined.BASE+x for x in expected] or
        uc.reg_read(UC_X86_REG_RIP)!=joined.BASE+branch_target or
        uc.reg_read(UC_X86_REG_RSP)!=joined.ENTRY_SP-0x288-8):
        raise RuntimeError("Original x64 nonempty main/second JGE execution escaped")
    flags=uc.reg_read(UC_X86_REG_EFLAGS)
    expected={
        **{key:uc.reg_read(register) for key,register in joined.REGISTER_IDS},
        "r10":uc.reg_read(UC_X86_REG_R10),
        "rsp":uc.reg_read(UC_X86_REG_RSP),
        "rip":uc.reg_read(UC_X86_REG_RIP),
        "cf":int(bool(flags&1)),
        "zf":int(bool(flags&64)),
        "sf":int(bool(flags&128)),
        "ret_at_guest_rsp":struct.unpack("<Q",bytes(
            uc.mem_read(joined.ENTRY_SP-0x288-8,8)))[0],
        "saved_cookie":struct.unpack("<Q",bytes(
            uc.mem_read(joined.ENTRY_SP-0x288+0x250,8)))[0],
        "arg0_global":struct.unpack("<Q",bytes(
            uc.mem_read(layout["arg0_va"],8)))[0],
        "arg1_global":struct.unpack("<Q",bytes(
            uc.mem_read(layout["arg1_va"],8)))[0],
        "show_global":struct.unpack("<I",bytes(
            uc.mem_read(layout["show_va"],4)))[0],
        "callee_global0":struct.unpack("<Q",bytes(
            uc.mem_read(layout["callee_global0"],8)))[0],
        "callee_global1":struct.unpack("<I",bytes(
            uc.mem_read(layout["callee_global1"],4)))[0],
        "input_byte":BYTE_CASES[case]
    }
    if expected["ret_at_guest_rsp"]!=layout["return_va"] or expected["r10"]!=1:
        raise RuntimeError("Original Win64 callee stack or R10 invariant broken")
    return pre,expected


def extend_joined_source(source,lea_va):
    """Attach the second original branch to the existing verified native CALL."""
    if not 0<lea_va<1<<64:
        raise ValueError("Missing authentic RIP-address evidence")
    before="static int native_callee_prefix(mx_crt_cluster_state*s,mx_cfg_memory*m,void*ctx){"
    continuation=""" return MX_NATIVE_LINK_FRONTIER_REACHED;
}
static const mx_native_link_entry callable[]"""
    if source.count(before)!=1 or source.count(continuation)!=1:
        raise ValueError("Existing joined original CALL/Callee source identity changed")
    native=f"""
#define SECOND_JGE_FALLTHROUGH UINT64_C({joined.BASE+JGE_FALLTHROUGH})
#define SECOND_JGE_TAKEN UINT64_C({joined.BASE+JGE_TAKEN})
static int native_nonempty_jge(mx_crt_cluster_state*s,mx_cfg_memory*m){{
 if(!s||!m||s->fault||s->rip!=FALLTHROUGH ||
    (s->rsp&15U)!=8U||s->rsp>UINT64_MAX-8U ||
    current_branch.branch_taken||current_branch.input_first_byte==0U ||
    current_branch.r10!=1U)return MX_GAME_PREFIX_BAD_STATE;
 uint64_t original_arg=0U;
 if(!mx_cfg_transfer(m,s->rsp+8U,&original_arg,8U,0))
    return MX_GAME_PREFIX_UNMAPPED;
 /* MOV RDX,[RSP+8]; LEA R11,[RIP+0xd14cce] */
 s->rdx=original_arg;
 s->r11=UINT64_C({lea_va});
 /* Signed 32-bit CMP R10D,0x80; x86 JGE uses SF==OF. */
 const uint32_t lhs=(uint32_t)current_branch.r10;
 const uint32_t rhs=128U;
 const uint32_t difference=lhs-rhs;
 const uint32_t overflow=((lhs^rhs)&(lhs^difference))>>31U;
 s->cf=(uint8_t)(lhs<rhs);
 s->zf=(uint8_t)(difference==0U);
 s->sf=(uint8_t)(difference>>31U);
 const uint8_t ge=(uint8_t)(s->sf==(uint8_t)(overflow&1U));
 s->rip=ge?SECOND_JGE_TAKEN:SECOND_JGE_FALLTHROUGH;
 s->instructions+=4U;
 return MX_NATIVE_LINK_FRONTIER_REACHED;
}}
"""
    source=source.replace(before,native+before)
    source=source.replace(continuation,
        """ return native_nonempty_jge(s,m);
}
static const mx_native_link_entry callable[]""")
    call="r,s,m,CALLEE,AFTER_CALL,TAKEN,FALLTHROUGH);"
    if source.count(call)!=1:
        raise ValueError("Joined native Win64 CALL frontier signature moved")
    source=source.replace(call,
        "r,s,m,CALLEE,AFTER_CALL,TAKEN,SECOND_JGE_FALLTHROUGH);")
    instruction_budget="s.instructions!=(f->in_byte==0U?18U:16U)"
    if source.count(instruction_budget)!=1:
        raise ValueError("Joined native fixture instruction accounting changed")
    source=source.replace(instruction_budget,
                          "s.instructions!=(f->in_byte==0U?18U:20U)")
    return source


def discover_next_control(pe,*,start=JGE_FALLTHROUGH,max_bytes=192,max_instructions=36):
    """Metadata-only next bounded original x64 execution frontier.

    Detect structural blockers as a GROUP; do not claim native translation of
    this suffix. Entry must be the separately verified second-JGE fallthrough.
    """
    if (start!=JGE_FALLTHROUGH or not 1<=max_bytes<=192 or
        not 1<=max_instructions<=36):
        raise ValueError("Unverified original next-frontier decode budget")
    md=Cs(CS_ARCH_X86,CS_MODE_64);md.detail=True
    decoded=[]
    control=None
    try:
        raw=bytes(pe.read_rva(start,max_bytes))
    except (ValueError,OverflowError):
        raise ValueError("Next original x64 frontier missing from owned PE")
    for instruction in md.disasm(raw,start):
        if instruction.group(CS_GRP_JUMP) or instruction.group(CS_GRP_CALL) or instruction.group(CS_GRP_RET):
            control=instruction
            break
        if (len(decoded)>=max_instructions or
            instruction.mnemonic in ("syscall","sysenter","hlt","ud2","int3")):
            raise ValueError("Unbounded or unsafe original x64 next frontier")
        decoded.append(instruction)
    if control is None:
        raise ValueError("No original control transfer inside next frontier bound")
    metadata={
        "entry_rva":hex(start),
        "original_straightline_instructions":len(decoded),
        "next_original_control_rva":hex(control.address),
        "next_original_control_kind":control.mnemonic,
        "next_original_control_operands":control.op_str,
        "original_bytes_span_to_control":control.address-start,
        "control_fallthrough_rva":hex(control.address+control.size),
        "next_target_rva":(
            hex(control.operands[0].imm)
            if control.operands and control.operands[0].type==X86_OP_IMM
            else None),
        "original_opcode_families":[{"rva":hex(i.address),"opcode":i.mnemonic,
                                     "operands":i.op_str} for i in decoded],
        "native_arm64_continuation_implemented":False,
        "native_arm64_continuation_tested":False
    }
    return metadata


def run(executable,out):
    pe=PE(executable)
    if hashlib.sha256(pe.b).hexdigest()!=INPUT_SHA:
        raise ValueError("Game binary differs from SHA-pinned original")
    lea_va=verify_second_branch(pe)
    next_frontier=discover_next_control(pe)
    joined.verify_main(executable)
    layout,_,_=joined.inspect_original(pe)
    originals=[original_reference(pe,layout,k) for k in range(MAX_CASES)]
    source,pages=joined.generate(layout,originals)
    source=extend_joined_source(source,lea_va)
    with tempfile.TemporaryDirectory(prefix="mxb-second-original-jge-") as td:
        folder=Path(td)
        file=folder/"private-original-second-JGE-arm64.c"
        file.write_text(source)
        compiler=["-O2","-std=c11","-Wall","-Wextra","-Werror",
                  "-I",str(ROOT/"arm64-lab"/"runtime")]
        host=folder/"host"
        proc=subprocess.run(["cc",*compiler,"-DHOST",str(file),"-o",str(host)],
                            text=True,capture_output=True)
        if proc.returncode:
            raise RuntimeError("Host native second-JGE compile failure: "+proc.stderr[-2000:])
        proc=subprocess.run([str(host)],text=True,capture_output=True)
        if proc.returncode:
            raise RuntimeError("Original x64 versus host second-JGE state mismatch: "+str(proc.returncode))
        arm=folder/"native-second-jge-aarch64.elf"
        proc=subprocess.run(["clang","--target=aarch64-unknown-linux-gnu",
            "-fuse-ld=lld","-nostdlib","-static","-ffreestanding",
            "-fno-builtin","-fno-stack-protector",*compiler,
            "-Wl,-e,smoke","-Wl,-z,max-page-size=4096",
            "-Wl,--build-id=none",str(file),"-o",str(arm)],
            text=True,capture_output=True)
        if proc.returncode:
            raise RuntimeError("AArch64 native second-JGE compile failure: "+proc.stderr[-2000:])
        result=execute_arm64_elf(arm,instruction_budget=1950000,timeout_us=15000000)
        if result["arm64_smoke_exit"]!=0:
            raise RuntimeError("Original x64 versus AArch64 second-JGE mismatch: "+
                               str(result["arm64_smoke_exit"]))
    out.mkdir(parents=True,exist_ok=True)
    taken=sum(BYTE_CASES[i]==0 for i in range(MAX_CASES))
    summary={
        "original_sha256":INPUT_SHA,
        "next_original_jge_fallthrough_control":next_frontier,
        "original_game_main_rva":hex(joined.MAIN),
        "original_first_callee_rva":hex(joined.CALLEE),
        "nonempty_second_jge_rva":hex(JGE),
        "empty_path_original_instructions":18,
        "nonempty_path_original_instructions":20,
        "nonempty_original_native_instructions_after_prior_frontier":4,
        "native_aarch64_original_full_state_differential_cases":MAX_CASES,
        "nonempty_original_jge_cases_executed":MAX_CASES-taken,
        "empty_original_return_cases":taken,
        "first_native_nonempty_control_reached":hex(JGE_FALLTHROUGH),
        "actual_original_callee_full_return_all_inputs":False,
        "native_engine_initialized":False,
        "native_game_executable_created":False,
        "copyrighted_original_or_native_code_exported":False,
    }
    (out/"joined-main-second-jge-native.json").write_text(json.dumps(summary,indent=2)+"\n")
    lines=["# MX Bikes real game-main joined CALL through second native JGE","",
        f"- Original x64/host/ARM64 matching scenarios: **{MAX_CASES}/{MAX_CASES}**",
        f"- Nonempty inputs through second original JGE: **{MAX_CASES-taken}**",
        f"- Authentic additional guest instructions: **4**",
        f"- Native frontier progressed from 0x136146 to **{hex(JGE_FALLTHROUGH)}**",
        "- Joined native Win64 CALL return slot: **verified**",
        "- Empty-input original function return still matches: **yes**",
        "- Whole nonempty callee/engine/menu/IPA launched: **NO**","",
        "## Grouped next original x64 frontier",
        "- Original RVAs: **"+next_frontier["entry_rva"]+" → "+
            next_frontier["next_original_control_rva"]+"**",
        "- Straight-line instruction count: **"+
            str(next_frontier["original_straightline_instructions"])+"**",
        "- Next control: **"+next_frontier["next_original_control_kind"]+" "+
            next_frontier["next_original_control_operands"]+"**","",
        "### Original opcode families (not yet translated on this path)"
    ]
    lines += ["- "+x["rva"]+": "+x["opcode"]+" "+x["operands"]
              for x in next_frontier["original_opcode_families"]]
    lines.append("")
    
    (out/"joined-main-second-jge-native.md").write_text("\n".join(lines))
    print("\n".join(lines))
    return summary


if __name__=="__main__":
    if len(sys.argv)!=3:
        raise SystemExit("usage: second_jge.py owned-original.exe metadata-dir")
    run(Path(sys.argv[1]),Path(sys.argv[2]))
