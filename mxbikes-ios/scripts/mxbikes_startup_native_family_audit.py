#!/usr/bin/env python3
"""Audit exactly the ORIGINAL x64 functions executed in startup for ARM64 gates.

Decodes their SHA-verified original .pdata byte ranges privately and exports
only aggregate instruction-family counts. Linear decode is *not* a recovered
CFG, guest Win64 CALL/RET implementation, full native translation, or boot.
Provides actionable batch grouping without public machine bytes.
"""
from collections import Counter
from capstone import Cs,CS_ARCH_X86,CS_MODE_64,CS_GRP_CALL,CS_GRP_RET,CS_GRP_JUMP
from capstone.x86 import X86_OP_MEM,X86_OP_IMM,X86_OP_REG

MAX_AUDIT_FUNCTIONS=128
MAX_AUDIT_FUNCTION_BYTES=32768
MAX_TOTAL_AUDIT_BYTES=2*1024*1024
MAX_INSTRUCTIONS_PER_ENTRY=30000
MAX_VISIBLE_OPCODES=16
GATE_ORDER=("Win64 CALL/import closure","SIMD/FP state","guest data-memory model",
            "Win64 stack/frame control","scalar/branch semantics")

def analyze_original_native_gates(pe,original_priority,*,base):
    candidates=original_priority.get("prioritized_original_functions")
    if (not isinstance(candidates,list) or len(candidates)>MAX_AUDIT_FUNCTIONS
        or not isinstance(base,int) or base<0):
        raise ValueError("Unsafe dynamic native translation priority manifest")
    decoder=Cs(CS_ARCH_X86,CS_MODE_64)
    decoder.detail=True
    results=[]
    total_bytes=0
    for candidate in candidates:
        begin=int(candidate["original_function_entry_rva"],16)
        end=int(candidate["original_unwind_end_rva"],16)
        length=end-begin
        if length<=0 or length>MAX_AUDIT_FUNCTION_BYTES:
            results.append({"original_function_entry_rva":hex(begin),
                "audit_status":"invalid_or_oversized_unwind_interval",
                "fully_native_translated":False})
            continue
        total_bytes+=length
        if total_bytes>MAX_TOTAL_AUDIT_BYTES:
            raise ValueError("Original audited byte budget exceeded")
        try:blob=bytes(pe.read_rva(begin,length))
        except (ValueError,OverflowError):
            results.append({"original_function_entry_rva":hex(begin),
                "audit_status":"unreadable_original_PE_window",
                "fully_native_translated":False})
            continue
        if len(blob)!=length:
            results.append({"original_function_entry_rva":hex(begin),
                "audit_status":"original_PE_window_truncated",
                "fully_native_translated":False})
            continue
        instructions=list(decoder.disasm(blob,base+begin))
        if len(instructions)>MAX_INSTRUCTIONS_PER_ENTRY:
            raise ValueError("Unbounded original x64 instruction audit")
        opcode=Counter()
        classes=Counter()
        for inst in instructions:
            opcode[inst.mnemonic]+=1
            is_call=inst.group(CS_GRP_CALL)
            if is_call:
                if inst.operands and inst.operands[0].type==X86_OP_IMM:
                    classes["direct_CALL_sites"]+=1
                else:
                    classes["indirect_or_IAT_CALL_sites"]+=1
            if inst.group(CS_GRP_RET):classes["RET_sites"]+=1
            if inst.group(CS_GRP_JUMP):classes["JUMP_sites"]+=1
            for operand in inst.operands:
                if operand.type==X86_OP_MEM:
                    group=inst.reg_name(operand.mem.base)
                    if group in ("rsp","rbp"):
                        classes["stack_memory_operands"]+=1
                    elif group=="rip":
                        classes["RIP_relative_data_operands"]+=1
                    else:
                        classes["guest_pointer_memory_operands"]+=1
                    if operand.mem.index:
                        classes["indexed_address_operands"]+=1
                if operand.type==X86_OP_REG and inst.reg_name(operand.reg).startswith(
                    ("xmm","ymm","zmm","mm")):
                    classes["vector_register_operands"]+=1
            if (inst.mnemonic.startswith(("fld","fst","fadd","fsub","fmul","fdiv",
                                          "cvtt","cvtss","cvtsd","movss","movsd",
                                          "addss","addsd","mulss","mulsd","sqrtss",
                                          "sqrtsd","ucomis","comis"))):
                classes["floating_point_opcode_sites"]+=1
        decoded_bytes=sum(x.size for x in instructions)
        decoded=(decoded_bytes==length and bool(instructions))
        gates=[]
        if classes["direct_CALL_sites"] or classes["indirect_or_IAT_CALL_sites"]:
            gates.append("Win64 CALL/import closure")
        if classes["vector_register_operands"] or classes["floating_point_opcode_sites"]:
            gates.append("SIMD/FP state")
        if classes["RIP_relative_data_operands"] or classes["guest_pointer_memory_operands"]:
            gates.append("guest data-memory model")
        if classes["stack_memory_operands"]:
            gates.append("Win64 stack/frame control")
        if not gates:gates.append("scalar/branch semantics")
        gates.sort(key=GATE_ORDER.index)
        results.append({
            "original_function_entry_rva":hex(begin),
            "original_unwind_length_bytes":length,
            "original_instruction_linear_decode_count":len(instructions),
            "audit_status":"complete_linear_disassembly_not_CFG_proof" if decoded
                           else "partial_linear_disassembly_requires_recovery",
            "required_native_gate_families":gates,
            "first_native_gate_family":gates[0],
            "original_x64_instruction_families":dict(classes),
            "common_original_opcode_names_only":[n for n,_ in opcode.most_common(MAX_VISIBLE_OPCODES)],
            "observed_after_main_instruction_hits":candidate["post_main_instruction_hits"],
            "observed_after_main_unique_instruction_PCs":candidate["unique_post_main_pc_rvas"],
            "original_guest_runtime_executed":True,
            "complete_native_ARM64_executable_function_proved":False,
        })
    grouped=Counter(row["first_native_gate_family"] for row in results
                    if row.get("first_native_gate_family"))
    return {
        "schema":1,
        "source_original_x64_trace":"actual observed SHA-pinned original executable",
        "input_dynamic_source_function_count":len(candidates),
        "function_families_audited":len(results),
        "total_original_unwind_bytes_disassembled":total_bytes,
        "first_translation_blocker_family_counts":dict(grouped),
        "original_function_audits":results,
        "no_native_ARM64_function_proven_by_this_audit":True,
        "commercial_machine_bytes_exported":False,
    }
