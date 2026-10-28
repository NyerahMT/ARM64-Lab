#!/usr/bin/env python3
"""Bounded original x64 entry-to-first-CALL audit for Win64 parent frames.

Only a control-flow-free, original executable instruction prefix can qualify.
The *first* encountered CALL must target an independently native-verified leaf.
This does not translate the caller or prove later CALL paths. Original bytes
and runtime register values are kept transient in the private CI runner.
"""
from __future__ import annotations

import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import sys

from capstone import Cs, CS_ARCH_X86, CS_MODE_64, CS_GRP_CALL, CS_GRP_JUMP, CS_GRP_RET
from capstone.x86 import X86_OP_IMM
from unicorn import Uc, UcError, UC_ARCH_X86, UC_MODE_64, UC_HOOK_CODE
from unicorn.x86_const import (
    UC_X86_REG_RIP, UC_X86_REG_RSP, UC_X86_REG_RBP, UC_X86_REG_EFLAGS,
    UC_X86_REG_RAX, UC_X86_REG_RBX, UC_X86_REG_RCX, UC_X86_REG_RDX,
    UC_X86_REG_R8, UC_X86_REG_R9, UC_X86_REG_RSI, UC_X86_REG_RDI,
)

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "arm64-lab"))
from tools.pe_probe import PE
from mxbikes_whole_game_map import INPUT_SHA
from mxbikes_win64_unwind_frame import (
    BASE, STACK_BASE, ENTRY_SP, MAX_PARENT_PROLOGUES,
    pdata_index, decode_unwind, validate_prologue,
)

MAX_PARENT_BYTES = 8192
MAX_PREFIX_INSNS = 128
STACK_SIZE = 131072
# Win64 function entry follows a pushed return address (RSP % 16 == 8).
GUEST_ENTRY_SP = ENTRY_SP - 8

def verified_targets(evidence):
    if not isinstance(evidence, list):
        raise ValueError("Expected same-run verified native registration list")
    return {
        int(row["original_rva"], 16)
        for row in evidence
        if row.get("full_function_behavior_verified") is True
        and row.get("win64_guest_call_abi_verified") is True
        and row.get("code_presence") == "ephemeral_ci_elf_only"
    }

def inspect_prefix(pe, begin, end, unwind, eligible_targets):
    """Trace a single fully decoded fallthrough prefix to its first CALL."""
    prologue = validate_prologue(pe, begin, end, unwind)
    if prologue not in (
        "original_x64_frameless_prologue_matches_unwind",
        "original_x64_rbp_prologue_matches_unwind",
    ):
        return {"outcome": prologue}
    length = min(MAX_PARENT_BYTES, end - begin)
    if length <= unwind["prologue_bytes"]:
        return {"outcome": "no_body_after_prologue"}
    code = pe.read_rva(begin, length)
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    md.detail = True
    cursor = BASE + begin
    prior = []
    first_call = None
    for ins in md.disasm(code, cursor):
        if ins.address != cursor:
            return {"outcome": "instruction_gap_before_first_call"}
        cursor += ins.size
        if ins.group(CS_GRP_CALL):
            first_call = ins
            break
        if ins.group(CS_GRP_JUMP) or ins.group(CS_GRP_RET):
            return {"outcome": "control_flow_before_first_call"}
        prior.append(ins)
        if len(prior) >= MAX_PREFIX_INSNS:
            return {"outcome": "prefix_instruction_budget_exceeded"}
    if first_call is None:
        return {"outcome": "no_first_call_within_bounded_prefix"}
    if (len(first_call.operands) != 1
        or first_call.operands[0].type != X86_OP_IMM):
        return {"outcome": "indirect_first_call"}
    target = first_call.operands[0].imm - BASE
    if target not in eligible_targets:
        return {"outcome": "first_call_target_not_verified_native"}
    boundary = BASE + begin + unwind["prologue_bytes"]
    if not (begin + unwind["prologue_bytes"] <= first_call.address - BASE
            and (boundary == first_call.address or
                 any(ins.address == boundary for ins in prior))):
        return {"outcome": "no_exact_post_prologue_instruction_boundary"}

    uc = Uc(UC_ARCH_X86, UC_MODE_64)
    first_page = (BASE + begin) & ~4095
    last_page = (BASE + begin + length - 1) & ~4095
    try:
        for addr in range(first_page, last_page + 1, 4096):
            uc.mem_map(addr, 4096)
        uc.mem_write(BASE + begin, code)
        uc.mem_map(STACK_BASE, STACK_SIZE)
        # Deliberately do NOT map arbitrary game heap, globals, imports or DLLs.
        # References to those services must fail closed, not become fake success.
        uc.mem_write(GUEST_ENTRY_SP, (BASE + 0xdead).to_bytes(8, "little"))
        uc.reg_write(UC_X86_REG_RSP, GUEST_ENTRY_SP)
        uc.reg_write(UC_X86_REG_RBP, STACK_BASE + 0x18000)
        uc.reg_write(UC_X86_REG_EFLAGS, 0x202)
        for reg, value in (
            (UC_X86_REG_RAX, 0x155155), (UC_X86_REG_RBX, 0x299299),
            (UC_X86_REG_RCX, 0x333333), (UC_X86_REG_RDX, 0x444444),
            (UC_X86_REG_R8, 0x555555), (UC_X86_REG_R9, 0x666666),
            (UC_X86_REG_RSI, 0x777777), (UC_X86_REG_RDI, 0x888888),
        ):
            uc.reg_write(reg, value)
        observed = []
        def at_instruction(engine, address, size, _user):
            if address == boundary:
                observed.append(engine.reg_read(UC_X86_REG_RSP))
        uc.hook_add(UC_HOOK_CODE, at_instruction)
        uc.emu_start(BASE + begin, first_call.address,
                     timeout=1000000, count=MAX_PREFIX_INSNS + 1)
    except (UcError, ValueError):
        return {"outcome": "entry_to_first_call_emulation_fault"}
    if uc.reg_read(UC_X86_REG_RIP) != first_call.address:
        return {"outcome": "did_not_reach_exact_original_callsite"}
    if boundary == first_call.address:
        observed.append(uc.reg_read(UC_X86_REG_RSP))
    if len(observed) != 1 or observed[0] != GUEST_ENTRY_SP - unwind["stack_decrement_bytes"]:
        return {"outcome": "original_pre_call_prologue_stack_disagrees_with_unwind"}
    rsp = uc.reg_read(UC_X86_REG_RSP)
    if not STACK_BASE + 4096 <= rsp < STACK_BASE + STACK_SIZE - 4096 or rsp & 15:
        return {"outcome": "pre_call_rsp_outside_bounded_guest_stack"}
    rbp = uc.reg_read(UC_X86_REG_RBP)
    if (unwind["has_declared_rbp_frame"] and
        rbp != observed[0] + unwind["frame_offset_bytes"]):
        return {"outcome": "declared_rbp_frame_not_preserved_to_call"}
    return {
        "outcome": "original_x64_entry_to_first_verified_native_call_reached",
        "parent_rva": hex(begin),
        "callsite_rva": hex(first_call.address - BASE),
        "native_verified_callee_rva": hex(target),
        "original_prefix_instructions_executed": len(prior),
        "declared_prologue_bytes": unwind["prologue_bytes"],
        "pre_call_rsp_decrement_from_entry": GUEST_ENTRY_SP - rsp,
        "declared_prologue_rsp_decrement": unwind["stack_decrement_bytes"],
        "rbp_frame_declared": bool(unwind["has_declared_rbp_frame"]),
        "pre_call_rbp_offset_from_entry_rsp": (
            rbp - GUEST_ENTRY_SP if unwind["has_declared_rbp_frame"] else None
        ),
        "native_parent_function_verified": False,
    }

def analyze(pe, mapping, verified):
    if (mapping.get("input_sha256") != INPUT_SHA or
        mapping.get("original_file_verified") is not True):
        raise ValueError("Cannot inspect an unpinned original x64 executable map")
    targets = verified_targets(verified)
    parents = sorted({
        int(parent, 16)
        for parent, children in mapping.get("direct_call_graph", {}).items()
        if any(int(child, 16) in targets for child in children)
    })
    if len(parents) > MAX_PARENT_PROLOGUES:
        raise RuntimeError("Too many original parents for bounded first-call audit")
    records = pdata_index(pe)
    outcomes = Counter()
    traces = []
    for begin in parents:
        if begin not in records:
            outcomes["missing_parent_unwind_record"] += 1
            continue
        end, metadata = records[begin]
        unwind = decode_unwind(pe, metadata)
        if not unwind.get("eligible"):
            outcomes[unwind["reason"]] += 1
            continue
        result = inspect_prefix(pe, begin, end, unwind, targets)
        outcomes[result["outcome"]] += 1
        if result["outcome"] == "original_x64_entry_to_first_verified_native_call_reached":
            traces.append(result)
    return {
        "schema": 1, "original_sha256": INPUT_SHA,
        "scope": "bounded_original_x64_first_call_trace_no_native_parent_registration",
        "parent_functions_considered": len(parents),
        "original_x64_entries_reaching_verified_leaf_as_first_call": len(traces),
        "outcomes": dict(sorted(outcomes.items())),
        "traces": traces,
        "full_parent_native_verified": 0,
        "engine_boot_verified": False,
        "original_code_or_guest_register_values_exported": False,
    }

def run(executable, mapping_path, verified_path, out):
    pe = PE(executable)
    if hashlib.sha256(pe.b).hexdigest() != INPUT_SHA:
        raise RuntimeError("Original game executable SHA mismatch")
    result = analyze(pe, json.loads(mapping_path.read_text()),
                     json.loads(verified_path.read_text()))
    out.mkdir(parents=True, exist_ok=True)
    (out / "original-entry-to-call-audit.json").write_text(
        json.dumps(result, indent=2) + "\n")
    lines = [
        "# MX Bikes original x64 entry-to-first-CALL audit", "",
        "- Parent functions considered: **" + str(result["parent_functions_considered"]) + "**",
        "- Original first-CALL sites reached from true function entry: **" +
        str(result["original_x64_entries_reaching_verified_leaf_as_first_call"]) + "**",
        "- Whole parent functions natively translated/registered: **0**", "",
        "| Exact outcome | Functions |", "| --- | ---: |",
    ]
    lines.extend("| " + k + " | " + str(n) + " |"
                 for k, n in result["outcomes"].items())
    lines += ["", "**Only bounded original x64 fallthrough to the first CALL was executed.**",
              "**Other paths, imported APIs, complete native callers, engine, and iOS remain unverified.**", ""]
    report = "\n".join(lines)
    (out / "original-entry-to-call-audit.md").write_text(report)
    print(report)
    return result

if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("sha_pinned_executable", type=Path)
    p.add_argument("same_run_original_map", type=Path)
    p.add_argument("same_run_native_manifest", type=Path)
    p.add_argument("report_directory", type=Path)
    a = p.parse_args()
    run(a.sha_pinned_executable, a.same_run_original_map,
        a.same_run_native_manifest, a.report_directory)
