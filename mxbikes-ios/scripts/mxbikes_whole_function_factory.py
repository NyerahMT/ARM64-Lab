#!/usr/bin/env python3
"""Whole-executable, fail-closed original x64 -> native ARM64 function factory.

Sweeps EVERY SHA-pinned original .pdata interval (not just selected call roots).
All supported, exact entire function bodies translate to transient native C/AArch64;
original x64, host C, and executed AArch64 independently compare return PC, Win64
stack, GP registers, CF/ZF/SF, and a 1024-byte guest memory window.

Unsupported CALLs, jumps, RIP data reads, SIMD, unknown mnemonics, or missing
function boundaries are recorded in blocker families; no guessed stubs.
Each native batch must pass all differentials. A failed batch is recursively
bisected; failed individual functions are quarantined and never counted.
Commercial original bytes / generated C / ELF remain transient private CI data.
"""
from __future__ import annotations
import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile

from capstone import Cs, CS_ARCH_X86, CS_MODE_64, CS_GRP_CALL, CS_GRP_JUMP, CS_GRP_RET
from capstone.x86 import X86_OP_REG, X86_OP_IMM, X86_OP_MEM
from unicorn import Uc, UcError, UC_ARCH_X86, UC_MODE_64
from unicorn.x86_const import UC_X86_REG_RIP, UC_X86_REG_EFLAGS
from mxbikes_whole_game_map import INPUT_SHA
import mxbikes_native_prefix_wave as prefix

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/"arm64-lab"))
from tools.pe_probe import PE
from tools.import_aot_smoke import execute_arm64_elf

BASE=prefix.BASE
STACK=prefix.STACK
ENTRY=prefix.ENTRY
WINDOW_LO=prefix.WINDOW_LO
STACK_WINDOW=prefix.STACK_WINDOW
MAX_BODY_BYTES=256
MAX_BODY_OPS=64
MAX_NATIVE_BATCH=48
MAX_NATIVE_TESTED=4096
FULL_FIXTURES=4
SENTINEL=BASE+0x151515
RET_STATEMENT=(
    "uint64_t guest_ret=0U;"
    "if(!mx_cfg_transfer(&mem,s.rsp,&guest_ret,8U,0))return 11;"
    "s.rsp+=8U;"
)

def bounded_original_stack_effect(instructions):
    """Static Win64 entry-stack abstract interpreter for complete RET proof.

    Demand that every guest stack access is inside our 1024-byte differential
    window, and that RSP is restored before the original RET. Do not sample
    through unmapped/fabricated context or silently skip memory effects.
    """
    sp=0
    bp=None  # original frame pointer is unknown until tied to RSP
    low=-768
    high=256
    def fits(offset,width):
        return offset is not None and low<=offset and offset+width<=high
    for ins in instructions[:-1]:
        name=ins.mnemonic
        operands=ins.operands
        if name=="push":
            sp-=8
            if not fits(sp,8):
                return "unbounded_original_guest_stack_write"
        elif name=="pop":
            if not fits(sp,8):
                return "unbounded_original_guest_stack_read"
            sp+=8
        elif name in ("add","sub") and len(operands)==2:
            if (operands[0].type==X86_OP_REG and
                ins.reg_name(operands[0].reg)=="rsp" and
                operands[1].type==X86_OP_IMM):
                amount=operands[1].imm
                if amount<0 or amount>65536:
                    return "unbounded_original_rsp_arithmetic"
                sp+=amount if name=="add" else -amount
        elif name=="lea" and len(operands)==2:
            dst,src=operands
            if dst.type==X86_OP_REG and src.type==X86_OP_MEM:
                target=ins.reg_name(dst.reg)
                base=ins.reg_name(src.mem.base)
                if target in ("rbp","rsp"):
                    origin={"rsp":sp,"rbp":bp}.get(base)
                    if origin is None or src.mem.index:
                        return "unproven_original_stack_frame_pointer"
                    value=origin+src.mem.disp
                    if target=="rbp":bp=value
                    else:sp=value
        elif name=="mov" and len(operands)==2:
            dst,src=operands
            if dst.type==X86_OP_REG and ins.reg_name(dst.reg) in ("rsp","rbp"):
                target=ins.reg_name(dst.reg)
                origin=(ins.reg_name(src.reg) if src.type==X86_OP_REG else None)
                val={"rsp":sp,"rbp":bp}.get(origin)
                if val is None:
                    return "unproven_original_stack_frame_pointer"
                if target=="rsp":sp=val
                else:bp=val
        for op in operands:
            if op.type!=X86_OP_MEM or ins.mnemonic=="lea":
                continue
            base=ins.reg_name(op.mem.base)
            relative={"rsp":sp,"rbp":bp}.get(base)
            address=None if relative is None else relative+op.mem.disp
            if not fits(address,op.size):
                return "guest_memory_outside_compared_window"
    if sp!=0:
        return "original_function_stack_not_statistically_restored"
    return None

def whole_candidate(code,rva,unwind_length):
    """Accept only one exact fully bounded, straight-line return body."""
    if (not isinstance(code,bytes) or len(code)!=unwind_length
        or not 1<=len(code)<=MAX_BODY_BYTES):
        return None,"invalid_body_or_unwind_boundary"
    decoder=Cs(CS_ARCH_X86,CS_MODE_64)
    decoder.detail=True
    instructions=list(decoder.disasm(code,BASE+rva))
    if not instructions or sum(i.size for i in instructions)!=len(code):
        return None,"incomplete_decode"
    if len(instructions)>MAX_BODY_OPS:
        return None,"too_many_original_instructions"
    if instructions[-1].mnemonic!="ret" or instructions[-1].operands:
        return None,"no_exact_final_return"
    if sum(bool(i.group(CS_GRP_RET)) for i in instructions)!=1:
        return None,"multiple_or_indirect_returns"
    stack_error=bounded_original_stack_effect(instructions)
    if stack_error:
        return None,stack_error
    statements=[]
    for ins in instructions[:-1]:
        if ins.group(CS_GRP_CALL):
            return None,"nested_original_direct_or_import_calls"
        if ins.group(CS_GRP_JUMP) or ins.group(CS_GRP_RET):
            return None,"branch_or_control_flow"
        stmt=prefix.translate_instruction(ins)
        if stmt is None:
            if any(k in (ins.op_str or "").lower() for k in ("xmm","ymm","zmm","st(")):
                family="simd_or_fpu"
            elif ins.mnemonic in ("mov","lea","push","pop"):
                family="unmodeled_memory_or_register"
            elif ins.mnemonic in ("add","sub","and","or","cmp","inc","dec","imul"):
                family="arithmetic_or_flags"
            else:
                family="unsupported_instruction"
            return None,family
        statements.append(stmt)
    return {
        "rva":rva,"bytes":code,"callsite":SENTINEL,
        "statements":[*statements,RET_STATEMENT],
        "insns":len(instructions),
        "complete_function":True,
        "boundary":"exact_original_pdata_interval",
    },None

def iter_whole_candidates(pe,mapping,existing=None):
    if mapping.get("input_sha256")!=INPUT_SHA or mapping.get("original_file_verified") is not True:
        raise ValueError("Whole function factory requires exact SHA-verified original executable map")
    rows=mapping.get("interval_map")
    if not isinstance(rows,list) or not 1<=len(rows)<=600000:
        raise ValueError("Original function inventory missing or unbounded")
    excluded=set()
    for proof in existing or []:
        if proof.get("full_function_behavior_verified") is True and (
            proof.get("win64_guest_call_abi_verified") is True
        ):
            excluded.add(int(proof["original_rva"],16))
    callers=Counter(int(v,16) for children in mapping.get("direct_call_graph",{}).values()
                    for v in children)
    ordered=sorted(rows,key=lambda x:(
        x.get("depth_from_known_roots",99) if x.get("depth_from_known_roots") is not None else 99,
        -callers[int(x["rva"],16)],int(x["rva"],16)))
    candidates=[]
    blockers=Counter()
    for row in ordered:
        rva=int(row["rva"],16)
        if rva in excluded:
            blockers["already_whole_native_verified"]+=1
            continue
        if row.get("status")!="decoded_linear":
            blockers["unavailable_complete_linear_decode"]+=1
            continue
        length=row.get("bytes")
        if not isinstance(length,int) or not 1<=length<=MAX_BODY_BYTES:
            blockers["outside_supported_bounded_function_size"]+=1
            continue
        if row.get("direct_calls") or row.get("indirect_calls") or row.get("import_thunk_calls"):
            blockers["nested_original_direct_or_import_calls"]+=1
            continue
        if row.get("internal_branches") or row.get("escaping_branches") or row.get("indirect_jumps"):
            blockers["branch_or_control_flow"]+=1
            continue
        if row.get("ret_count")!=1:
            blockers["not_single_exact_return"]+=1
            continue
        body=pe.read_rva(rva,length)
        item,why=whole_candidate(body,rva,length)
        if item is None:
            blockers[why]+=1
        else:
            candidates.append(item)
    return candidates,blockers,len(rows)

def original_full_reference(item,case,failures=None):
    cpu=Uc(UC_ARCH_X86,UC_MODE_64)
    code=BASE+item["rva"]
    body=item["bytes"]
    lo=code&~4095
    hi=(code+len(body)-1)&~4095
    for va in range(lo,hi+1,4096):
        cpu.mem_map(va,4096)
    cpu.mem_write(code,body)
    cpu.mem_map(STACK,0x10000)
    state=prefix.initial_state(case)
    seeded=bytes((i*13+case*19+3)&255 for i in range(STACK_WINDOW))
    cpu.mem_write(WINDOW_LO,seeded)
    cpu.mem_write(ENTRY,SENTINEL.to_bytes(8,"little"))
    for name,reg in prefix.REGS:
        cpu.reg_write(reg,code if name=="rip" else state[name])
    flags=0x202|([0,1,0x40,0x80][case%4])
    cpu.reg_write(UC_X86_REG_EFLAGS,flags)
    try:
        cpu.emu_start(code,SENTINEL,timeout=1000000,count=MAX_BODY_OPS+2)
    except (UcError,ValueError) as error:
        if failures is not None:
            failures["x64_execution_fault_"+type(error).__name__+"_"+str(error)[:80]]+=1
            current_sp=cpu.reg_read(prefix.UC_X86_REG_RSP) if hasattr(prefix,"UC_X86_REG_RSP") else 0
            current_pc=cpu.reg_read(UC_X86_REG_RIP)
            if current_sp==ENTRY+8:
                failures["x64_fault_after_normal_return_stack_popped"]+=1
            elif current_sp==ENTRY:
                failures["x64_fault_original_entry_stack_pointer"]+=1
            else:
                failures["x64_fault_other_stack_pointer"]+=1
            if current_pc==SENTINEL:
                failures["x64_fault_at_expected_sentinel"]+=1
            elif BASE<=current_pc<BASE+0x4000000:
                failures["x64_fault_inside_original_image_address"]+=1
            else:
                failures["x64_fault_outside_original_image"]+=1
        return None
    if cpu.reg_read(UC_X86_REG_RIP)!=SENTINEL:
        if failures is not None:
            failures["x64_no_complete_return_to_sentinel"]+=1
        return None
    actual={name:cpu.reg_read(reg) for name,reg in prefix.REGS}
    if actual["rsp"]!=ENTRY+8:
        if failures is not None:
            failures["x64_function_stack_frame_did_not_restore"]+=1
        return None
    final_flags=cpu.reg_read(UC_X86_REG_EFLAGS)
    flag_tuple=(int(bool(final_flags&1)),int(bool(final_flags&0x40)),
                int(bool(final_flags&0x80)))
    return state,flags,actual,flag_tuple,bytes(cpu.mem_read(WINDOW_LO,STACK_WINDOW))

def generate_whole_native(batch,refs):
    """Reuse the proven native guest state/fixture generator, with true RET."""
    source=prefix.generate(batch,refs)
    # Exact native semantic difference from first-CALL prefix:
    # retrieve the original guest return VA and restore RSP.
    old=f"s.rip=UINT64_C({SENTINEL});*sp=s;return 0;"
    replacement="s.rip=guest_ret;*sp=s;return 0;"
    if source.count(old)!=len(batch):
        raise RuntimeError("Function factory lost generated native RET boundary")
    source=source.replace(old,replacement)
    marker="  struct cpu s={0};"
    # Original x64 reference has a real guest RET slot; replicate it in native.
    # NB f->stack already contains the original return bytes, but writing all
    # 1024 bytes from the original fixture would mask pre-RET memory effects.
    add=(f"  const uint64_t ret_address=UINT64_C({SENTINEL});\n"
         "  for(unsigned j=0;j<8U;j++)\n"
         "    stack_mem[ENTRY-STACK+j]=(uint8_t)(ret_address>>(8U*j));\n")
    if source.count(marker)!=1:
        raise RuntimeError("Native fixture return-slot insertion point moved")
    return source.replace(marker,add+marker)

def compile_and_execute(batch,refs):
    source=generate_whole_native(batch,refs)
    with tempfile.TemporaryDirectory(prefix="mxb-native-complete-body-") as td:
        root=Path(td)
        c=root/"private-complete-original-functions.c"
        c.write_text(source)
        flags=["-O2","-std=c11","-Wall","-Wextra","-Werror",
               "-I",str(ROOT/"arm64-lab"/"runtime")]
        host=root/"host"
        r=subprocess.run(["cc",*flags,"-DHOST",str(c),"-o",str(host)],
                         capture_output=True,text=True)
        if r.returncode:
            raise RuntimeError("host_compiler_error: "+r.stderr[-500:])
        r=subprocess.run([str(host)],capture_output=True,text=True)
        if r.returncode:
            raise RuntimeError("host_differential_error: "+str(r.returncode))
        elf=root/"native-aarch64.elf"
        r=subprocess.run(["clang","--target=aarch64-unknown-linux-gnu",
            "-fuse-ld=lld","-nostdlib","-static","-ffreestanding",
            "-fno-builtin","-fno-stack-protector",*flags,
            "-Wl,-e,smoke","-Wl,-z,max-page-size=4096",
            "-Wl,--build-id=none",str(c),"-o",str(elf)],
            capture_output=True,text=True)
        if r.returncode:
            raise RuntimeError("arm64_compiler_error: "+r.stderr[-500:])
        res=execute_arm64_elf(elf,instruction_budget=6000000,timeout_us=15000000)
        if res["arm64_smoke_exit"]!=0:
            raise RuntimeError("arm64_differential_error: "+str(res["arm64_smoke_exit"]))

def verify_wave(candidates,references,checker=compile_and_execute):
    """Auto-bisect failed native batches; individual failures are NOT accepted."""
    proved=[]
    quarantined=[]
    jobs=Counter()
    def check(batch):
        if not batch:
            return
        jobs["native_batch_attempts"]+=1
        try:
            checker(batch,references)
        except (RuntimeError,ValueError,subprocess.SubprocessError) as exc:
            if len(batch)>1:
                jobs["failed_batches_recursively_split"]+=1
                mid=len(batch)//2
                check(batch[:mid])
                check(batch[mid:])
            else:
                jobs["rejected_single_native_functions"]+=1
                # Only metadata leaves the private runner.
                category=str(exc).split(":",1)[0]
                if category not in (
                    "host_compiler_error","host_differential_error",
                    "arm64_compiler_error","arm64_differential_error",
                    "ARM64 instruction budget must be in [1000, 6000000]",
                    "ARM64 timeout must be in [1000000, 15000000] microseconds"):
                    category="native_or_emulator_error"
                quarantined.append({"rva":hex(batch[0]["rva"]),"reason":category})
        else:
            jobs["native_batches_passed"]+=1
            proved.extend(batch)
    for i in range(0,len(candidates),MAX_NATIVE_BATCH):
        check(candidates[i:i+MAX_NATIVE_BATCH])
    if len(proved)+len(quarantined)!=len(candidates):
        raise RuntimeError("Native verification accounting integrity failure")
    if len({x["rva"] for x in proved})!=len(proved):
        raise RuntimeError("Duplicate native function proof")
    return proved,quarantined,dict(jobs)

def run(original,map_path,prior_verified,output):
    pe=PE(original)
    if hashlib.sha256(pe.b).hexdigest()!=INPUT_SHA:
        raise RuntimeError("Unknown original executable hash")
    mapping=json.loads(map_path.read_text())
    verified=json.loads(prior_verified.read_text())
    if not isinstance(verified,list):
        raise ValueError("Existing native verified manifest malformed")
    eligible,blockers,total=iter_whole_candidates(pe,mapping,verified)
    if len(eligible)>MAX_NATIVE_TESTED:
        raise RuntimeError("Full-function candidates exceed bounded verification budget")
    attempted=[]
    refs={}
    rejected=Counter()
    original_fault_types=Counter()
    for item in eligible:
        samples=[original_full_reference(item,i,original_fault_types) for i in range(FULL_FIXTURES)]
        if any(v is None for v in samples):
            rejected["original_x64_full_return_fault_or_stack_mismatch"]+=1
            continue
        refs[item["rva"]]=samples
        attempted.append(item)
    proved,quarantine,jobs=verify_wave(attempted,refs)
    proven_rows=[{
        "original_rva":hex(v["rva"]),
        "whole_original_pdata_interval_native_arm64_differential":True,
        "all_original_instructions_translated_until_ret":True,
        "independent_original_x64_reference_fixture_cases":FULL_FIXTURES,
        "native_aarch64_execution_confirmed":True,
        "guest_return_abi_and_memory_compared":True,
        "not_yet_runtime_linked":True,
    } for v in proved]
    report={
        "schema":1,"original_sha256":INPUT_SHA,
        "original_unwind_intervals_scanned":total,
        "exact_whole_functions_matching_supported_instruction_families":len(eligible),
        "whole_functions_with_original_x64_valid_reference":len(attempted),
        "complete_original_functions_verified_through_native_arm64":len(proved),
        "original_x64_host_arm64_fixtures_verified":len(proved)*FULL_FIXTURES,
        "prior_original_native_function_registrations":len(verified),
        "new_native_executed_full_body_proofs":proven_rows,
        "rejected_by_original_shape":dict(sorted(blockers.items())),
        "rejected_by_x64_execution":dict(sorted(rejected.items())),
        "original_x64_fault_types":dict(sorted(original_fault_types.items())),
        "native_quarantines":quarantine,
        "native_execution_job_stats":jobs,
        "complete_original_function_runtime_linker_registration_added":False,
        "commercial_derived_executable_persisted":False,
        "native_game_engine_started":False,
        "original_function_bytes_exported":False,
    }
    output.mkdir(parents=True,exist_ok=True)
    (output/"whole-function-native-factory.json").write_text(json.dumps(report,indent=2)+"\n")
    rows=["# MX Bikes automatic whole-function native ARM64 factory","",
          "- Original SHA-pinned unwind function intervals swept: **"+str(total)+"**",
          "- New entire original game function bodies executed on ARM64: **"+str(len(proved))+"**",
          "- x64/host/ARM64 full-return differential cases passed: **"+str(len(proved)*FULL_FIXTURES)+"**",
          "- Valid original complete function candidates: **"+str(len(eligible))+"**",
          "- Native binaries: temporary only; full-game linking/boot: **NO**","",
          "## Native wave results",
          "- Native batches passed: **"+str(jobs.get("native_batches_passed",0))+"**",
          "- Native batch rejections: **"+str(len(quarantine))+"**",
          "",
          "## Most frequent blockers",
          "| Original blocker family | Intervals |","| --- | ---: |"]
    rows.extend("| "+key+" | "+str(n)+" |" for key,n in blockers.most_common(18))
    rows.extend(["","## Original x64 fixture failure classifications",
                 *["- "+name+": "+str(num) for name,num in original_fault_types.most_common()],
                 "", "**Every accepted new whole function required original x64, compiled host, executed AArch64 and full RET. Unsupported functions remain untranslated.**",""])
    (output/"whole-function-native-factory.md").write_text("\n".join(rows))
    print("\n".join(rows))
    return report

if __name__=="__main__":
    ap=argparse.ArgumentParser()
    ap.add_argument("sha_verified_original",type=Path)
    ap.add_argument("same_run_entire_original_map",type=Path)
    ap.add_argument("same_run_native_verified_manifest",type=Path)
    ap.add_argument("metadata_output",type=Path)
    args=ap.parse_args()
    run(args.sha_verified_original,args.same_run_entire_original_map,
        args.same_run_native_verified_manifest,args.metadata_output)
