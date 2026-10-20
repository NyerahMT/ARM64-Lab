"""Identify a bounded x64 PE imported-CALL handoff from an observed return RVA.

Read-only static analysis of a caller-provided Windows PE and its import-slot
metadata. Its output includes address and dependency metadata, but no source,
assembly, executable bytes, lifted IR or embedded proprietary code.

A guest stack return RVA is an *unexecuted continuation candidate*; finding
its static instruction or enclosing unwind function does not prove it will
execute, or that the imported Windows service can be implemented on iOS.
"""
from __future__ import annotations

from collections import Counter

from capstone import Cs, CS_ARCH_X86, CS_MODE_64
from capstone.x86 import X86_OP_IMM, X86_OP_MEM, X86_OP_REG

from .pe_call_clusters import unwind_functions

MAX_FUNC_BYTES = 16384


def _resolve_import_call(pe, ins, imports: dict, dis):
    if ins.mnemonic != "call" or len(ins.operands) != 1:
        return None
    op = ins.operands[0]
    if (op.type == X86_OP_MEM and ins.reg_name(op.mem.base) == "rip"
            and not op.mem.index):
        slot = ins.address + ins.size + op.mem.disp
        return {"kind": "iat_indirect_call", "iat_slot_rva": hex(slot),
                "symbol": imports.get(slot)}
    if op.type != X86_OP_IMM:
        return {"kind": "unresolved_indirect_call", "iat_slot_rva": None,
                "symbol": None}
    target = op.imm
    try:
        thunk = list(dis.disasm(pe.read_rva(target, 6), target))
    except (ValueError, OSError):
        return None
    if len(thunk) != 1 or thunk[0].size != 6 or thunk[0].mnemonic != "jmp":
        return None
    operand = thunk[0].operands[0]
    if (operand.type != X86_OP_MEM or
            thunk[0].reg_name(operand.mem.base) != "rip" or
            operand.mem.index):
        return None
    slot = thunk[0].address + thunk[0].size + operand.mem.disp
    return {"kind": "direct_call_via_iat_jmp_thunk",
            "thunk_rva": hex(target), "iat_slot_rva": hex(slot),
            "symbol": imports.get(slot)}


def find_handoff(pe, return_rva: int, imports: dict,
                 max_function_bytes: int = MAX_FUNC_BYTES) -> dict:
    """Validate the specific import CALL ending at a guest return address.

    Hard failures mean no claim of having identified the x64 handoff.
    When the return address belongs to a function with no unwind range or a
    nonstandard tail call, report the limitation; do not guess code boundaries.
    """
    if (not isinstance(return_rva, int) or isinstance(return_rva, bool) or
            return_rva <= 0 or return_rva > 0xffffffff):
        raise ValueError("Return RVA must be a 32-bit PE address")
    if (not isinstance(imports, dict) or len(imports) > 8192 or
            any(not isinstance(k, int) or k < 0 or k > 0xffffffff or
                not isinstance(v, str) or len(v) > 256
                for k, v in imports.items())):
        raise ValueError("Malformed or oversized import-slot inventory")
    if not 16 <= max_function_bytes <= MAX_FUNC_BYTES:
        raise ValueError("Invalid bounded unwind-function size")
    bounds = unwind_functions(pe)
    matches = [(start,end) for start,end in bounds.items()
               if start < return_rva <= end]
    if len(matches)!=1:
        raise ValueError("Guest return address has no unique unwind caller")
    start,end=matches[0]
    if end-start>max_function_bytes:
        raise ValueError("Unwind caller exceeds bounded instruction scan")
    dis=Cs(CS_ARCH_X86,CS_MODE_64)
    dis.detail=True
    raw=pe.read_rva(start,end-start)
    instructions=list(dis.disasm(raw,start))
    if not instructions or sum(x.size for x in instructions)!=end-start:
        raise ValueError("Original bounded caller is not fully decodable")
    matching=[x for x in instructions if
              x.address+x.size==return_rva and x.mnemonic=="call"]
    if len(matching)!=1:
        raise ValueError("No unique imported CALL ends at guest return address")
    call=matching[0]
    resolved=_resolve_import_call(pe,call,imports,dis)
    if not resolved or not resolved.get("symbol"):
        raise ValueError("Return-site CALL is not a verified imported service")
    before=[x for x in instructions if x.address < call.address]
    after=[x for x in instructions if x.address >= return_rva]
    name_counts=Counter()
    unresolved=0
    for item in instructions:
        if item.mnemonic!="call":
            continue
        edge=_resolve_import_call(pe,item,imports,dis)
        if edge and edge.get("symbol"):
            name_counts[edge["symbol"]]+=1
        elif edge and edge.get("kind")=="unresolved_indirect_call":
            unresolved+=1
    conditional_branches = sum(
        x.mnemonic.startswith("j") and x.mnemonic != "jmp"
        for x in instructions)
    immediate=after[:12]
    # Only accept immediately adjacent x64 TEST REG,REG or CMP REG,0
    # followed by JE/JNE. Anything more complicated stays unclassified;
    # these are *static* nonexecuted edges, not a successful Steam return.
    post_call_zero_branch = None
    if len(after) >= 2:
        predicate, jump=after[0],after[1]
        tested_register = None
        if len(predicate.operands)==2:
            a,b=predicate.operands
            if (predicate.mnemonic=="test" and
                a.type==X86_OP_REG and b.type==X86_OP_REG and
                a.reg==b.reg):
                tested_register=predicate.reg_name(a.reg)
            elif (predicate.mnemonic=="cmp" and
                  a.type==X86_OP_REG and b.type==X86_OP_IMM and
                  b.imm==0):
                tested_register=predicate.reg_name(a.reg)
        if (tested_register in {"al","ax","eax","rax"} and
            jump.mnemonic in {"je","jne"} and
            len(jump.operands)==1 and jump.operands[0].type==X86_OP_IMM and
            predicate.address+predicate.size==jump.address):
            taken=jump.operands[0].imm
            other=jump.address+jump.size
            if all(start<=x<end for x in (taken,other)):
                post_call_zero_branch={
                    "predicate_register":tested_register,
                    "zero_result_continuation_rva":hex(
                        taken if jump.mnemonic=="je" else other),
                    "nonzero_result_continuation_rva":hex(
                        other if jump.mnemonic=="je" else taken),
                    "both_continuations_unexecuted":True,
                }
    return {
        "mode": "unexecuted_return_address_static_recovery",
        "unwind_caller_rva": hex(start),
        "unwind_caller_end_rva": hex(end),
        "bounded_function_instructions": len(instructions),
        "original_import_call_site_rva": hex(call.address),
        "guest_return_rva": hex(return_rva),
        "import": resolved,
        "instructions_before_call":len(before),
        "static_instructions_after_call":len(after),
        "next_instruction_rva": hex(after[0].address) if after else None,
        "nearby_next_12_has_conditional_branch": any(
            x.mnemonic.startswith("j") and x.mnemonic!="jmp"
            for x in immediate),
        "post_import_accumulator_zero_branch":post_call_zero_branch,
        "static_conditional_branches_in_function": conditional_branches,
        "function_static_import_calls":[
            {"name": name, "sites": count}
            for name,count in sorted(name_counts.items())],
        "unresolved_indirect_calls_in_function": unresolved,
        "native_engine_execution": False,
        "supported_imported_service_executed": False,
        "unexecuted_return_site_only": True,
        "limitations": [
            "Static function boundary from x64 unwind data, not engine initialization.",
            "The guest return address was not executed after the unsupported import.",
            "Computed calls and dynamic import resolution may not be recovered.",
            "Imported Windows/Steam semantics, ARM64 behavior and rendering are not established.",
        ],
    }
