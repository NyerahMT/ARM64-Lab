#!/usr/bin/env python3
"""Batch original x64 Win64 parent-entry -> first-CALL exploration.

Runs every parent of an independently x64/host/ARM64 verified native leaf
under multiple deterministic original x64 Unicorn register/flag fixtures.
Branches are followed dynamically, not linearized. It stops *before* the
first imported/local/direct/indirect CALL (never invents its return). A
fixture that reaches a verified leaf proves a bounded x64 edge only, NOT
native translated parent instructions or an uninterrupted game boot.

All original code and guest register fixtures are restricted to the
private runner; output is metadata-only, bounded, and reproducible.
"""
from __future__ import annotations
import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import sys

from capstone import Cs, CS_ARCH_X86, CS_MODE_64, CS_GRP_CALL
from capstone.x86 import X86_OP_IMM
from unicorn import (
    Uc, UcError, UC_ARCH_X86, UC_MODE_64, UC_HOOK_CODE,
    UC_HOOK_MEM_READ_UNMAPPED, UC_HOOK_MEM_WRITE_UNMAPPED,
)
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
    BASE, STACK_BASE, MAX_PARENT_PROLOGUES, pdata_index,
    decode_unwind, validate_prologue,
)
from mxbikes_parent_call_frontier import (
    GUEST_ENTRY_SP, STACK_SIZE, MAX_PARENT_BYTES, verified_targets,
)

MAX_CASES = 24
BASELINE_CASES = 12
GUEST_HEAP = 0x720000000
GUEST_HEAP_PAGES = 2
MAX_ORIGINAL_PE_PAGES_PER_FIXTURE = 24
PAGE = 4096
MAX_INSTRUCTIONS = 320
GUEST_STACK_MIN = STACK_BASE + 4096
GUEST_STACK_MAX = STACK_BASE + STACK_SIZE - 4096
GP_REGS = (
    UC_X86_REG_RAX, UC_X86_REG_RBX, UC_X86_REG_RCX,
    UC_X86_REG_RDX, UC_X86_REG_R8, UC_X86_REG_R9,
    UC_X86_REG_RSI, UC_X86_REG_RDI,
)
SEED_VALUES = (
    0, 1, 0xffffffffffffffff, 0x100000, 0x33333333,
    0x710005000, 0x710010000, 0x140000000, 0x80000000,
    0x7fffffff, 0xaaaaaaaa, 0x55555555,
)

def decode_frontier_unwind(pe, metadata):
    """Accept exact empty Win64 unwind headers without weakening other records.

    A zero-code/zero-prologue unwind record is legal for a frameless x64
    function without unwind operations. No chained, unknown-version or
    partial frame is upgraded; later dynamic x64 CALL alignment remains
    mandatory. This is not proof of full original function behavior.
    """
    normal = decode_unwind(pe, metadata)
    if normal.get("eligible") or normal.get("reason") != "unsupported_header":
        return normal
    try:
        hdr = pe.read_rva(metadata, 4)
    except ValueError:
        return normal
    version, flags = hdr[0] & 7, hdr[0] >> 3
    prologue, count = hdr[1], hdr[2]
    frame_register, frame_offset = hdr[3] & 15, hdr[3] >> 4
    if not (
        version in (1, 2) and flags == 0 and prologue == 0
        and count == 0 and frame_register == 0 and frame_offset == 0
    ):
        return normal
    return {
        "eligible": True,
        "prologue_bytes": 0,
        "stack_decrement_bytes": 0,
        "has_declared_rbp_frame": False,
        "frame_offset_bytes": None,
        "evidence": "exact_legal_zero_code_win64_unwind",
    }

def preflight(pe, begin, end, unwind):
    """Only proceed after the previously accepted true-original prologue oracle."""
    if unwind["prologue_bytes"] == 0 and (
        unwind.get("evidence") == "exact_legal_zero_code_win64_unwind"
    ):
        return None
    result = validate_prologue(pe, begin, end, unwind)
    if result not in (
        "original_x64_frameless_prologue_matches_unwind",
        "original_x64_rbp_prologue_matches_unwind",
    ):
        return result
    if end - begin > MAX_PARENT_BYTES:
        return "parent_interval_exceeds_bounded_mapping"
    return None

def run_fixture(pe, begin, end, unwind, targets, fixture):
    """Report x64 first-CALL reachability and exact ABI state, not native proof."""
    if not 0 <= fixture < MAX_CASES:
        raise ValueError("fixture index is out of bounds")
    if not (begin < end and end - begin <= MAX_PARENT_BYTES):
        return {"outcome": "parent_interval_out_of_bounds"}
    code = pe.read_rva(begin, end - begin)
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    md.detail = True
    uc = Uc(UC_ARCH_X86, UC_MODE_64)
    first_page = (BASE + begin) & ~4095
    last_page = (BASE + end - 1) & ~4095
    for page in range(first_page, last_page + 1, 4096):
        uc.mem_map(page, 4096)
    uc.mem_write(BASE + begin, code)
    uc.mem_map(STACK_BASE, STACK_SIZE)
    uc.mem_write(GUEST_ENTRY_SP, (BASE + 0xdead).to_bytes(8, "little"))
    uc.reg_write(UC_X86_REG_RSP, GUEST_ENTRY_SP)
    uc.reg_write(UC_X86_REG_RBP, STACK_BASE + 0x18000)
    uc.reg_write(UC_X86_REG_EFLAGS, 0x202 | ([0, 1, 0x40, 0x80][fixture % 4]))
    for index, reg in enumerate(GP_REGS):
        v = SEED_VALUES[(fixture + 3 * index) % len(SEED_VALUES)]
        uc.reg_write(reg, v)
    # Extended test-domain fixtures, never a claim about real game heap
    # state, run with deliberately constructed guest pointers.
    memory_profile = "stack_only" if fixture < BASELINE_CASES else "bounded_guest_heap_and_pe_snapshot"
    pages_loaded = set()
    if fixture >= BASELINE_CASES:
        uc.mem_map(GUEST_HEAP, PAGE * GUEST_HEAP_PAGES)
        for index, reg in enumerate(GP_REGS):
            # Reserve one page for referents and one for bounded indirection.
            addr = GUEST_HEAP + 0x100 + (index * 0x100)
            uc.reg_write(reg, addr)
            uc.mem_write(addr, (GUEST_HEAP + 0x100 + ((index + 1) % len(GP_REGS)) * 0x100).to_bytes(8, "little"))
        if (fixture - BASELINE_CASES) % 4 == 0:
            uc.reg_write(UC_X86_REG_RCX, 0)
        elif (fixture - BASELINE_CASES) % 4 == 1:
            uc.reg_write(UC_X86_REG_RCX, GUEST_HEAP + 0x100)
        elif (fixture - BASELINE_CASES) % 4 == 2:
            uc.reg_write(UC_X86_REG_RCX, STACK_BASE + 0x15000)
        else:
            uc.reg_write(UC_X86_REG_RCX, 0xffffffffffffffff)

        def map_backed_pe_data(engine, access, address, size, value, _user):
            if len(pages_loaded) >= MAX_ORIGINAL_PE_PAGES_PER_FIXTURE:
                return False
            aligned = address & ~(PAGE - 1)
            rva = aligned - BASE
            # Never execute new game code, generate Windows imports, or
            # manufacture invalid PE partial-page contents from zero padding.
            for name, vsize, start, rawsize, rawptr, flags in getattr(pe, "sections", ()):
                if (flags & 0x20000000) or not (
                    start <= rva and rva + PAGE <= start + rawsize
                ):
                    continue
                try:
                    original_page = pe.read_rva(rva, PAGE)
                    if len(original_page) != PAGE:
                        return False
                    engine.mem_map(aligned, PAGE)
                    engine.mem_write(aligned, original_page)
                except (UcError, ValueError):
                    return False
                pages_loaded.add(aligned)
                return True
            return False
        uc.hook_add(UC_HOOK_MEM_READ_UNMAPPED | UC_HOOK_MEM_WRITE_UNMAPPED,
                    map_backed_pe_data)
    # Each original x64 instruction is checked before executing; the
    # first CALL is intercepted, so no imaginary child/import is run.
    state = {
        "outcome": None, "instruction_count": 0, "branches": 0,
        "callsite": None, "target": None, "prologue_checked": False,
    }
    start = BASE + begin
    stop = BASE + end
    prologue_end = start + unwind["prologue_bytes"]

    def hook(engine, address, size, _data):
        if state["outcome"] is not None:
            engine.emu_stop()
            return
        if not start <= address < stop or address + size > stop:
            state["outcome"] = "control_flow_exits_original_parent_interval"
            engine.emu_stop()
            return
        if address == prologue_end:
            observed_rsp = engine.reg_read(UC_X86_REG_RSP)
            if observed_rsp != GUEST_ENTRY_SP - unwind["stack_decrement_bytes"]:
                state["outcome"] = "original_prologue_stack_differs_in_fixture"
                engine.emu_stop()
                return
            if unwind["has_declared_rbp_frame"] and (
                engine.reg_read(UC_X86_REG_RBP) !=
                observed_rsp + unwind["frame_offset_bytes"]
            ):
                state["outcome"] = "original_prologue_frame_pointer_differs"
                engine.emu_stop()
                return
            state["prologue_checked"] = True
        instruction = list(md.disasm(engine.mem_read(address, size), address, count=1))
        if len(instruction) != 1 or instruction[0].size != size:
            state["outcome"] = "dynamic_instruction_decode_disagrees"
            engine.emu_stop()
            return
        inst = instruction[0]
        state["instruction_count"] += 1
        if inst.group(CS_GRP_CALL):
            state["callsite"] = address - BASE
            if len(inst.operands) != 1 or inst.operands[0].type != X86_OP_IMM:
                state["outcome"] = "first_call_indirect_or_import"
            else:
                target = inst.operands[0].imm - BASE
                state["target"] = target
                if target not in targets:
                    state["outcome"] = "first_call_not_native_verified"
                elif not state["prologue_checked"]:
                    state["outcome"] = "first_call_before_validated_prologue"
                elif engine.reg_read(UC_X86_REG_RSP) & 15:
                    state["outcome"] = "pre_call_win64_stack_misaligned"
                elif not (
                    GUEST_STACK_MIN <= engine.reg_read(UC_X86_REG_RSP) <
                    GUEST_STACK_MAX
                ):
                    state["outcome"] = "pre_call_stack_outside_bounded_guest_memory"
                else:
                    state["outcome"] = "original_x64_first_verified_call_reached"
            engine.emu_stop()
        elif inst.mnemonic.startswith("j") or inst.mnemonic.startswith("loop"):
            state["branches"] += 1

    uc.hook_add(UC_HOOK_CODE, hook)
    try:
        uc.emu_start(start, 0, timeout=1000000, count=MAX_INSTRUCTIONS)
    except UcError:
        if state["outcome"] is None:
            state["outcome"] = "original_x64_guest_memory_or_execution_fault"
    if state["outcome"] is None:
        if state["instruction_count"] >= MAX_INSTRUCTIONS:
            state["outcome"] = "instruction_budget_exhausted"
        else:
            state["outcome"] = "escaped_before_first_call"
    result = {
        "fixture": fixture,
        "outcome": state["outcome"],
        "executed_x64_instructions": state["instruction_count"],
        "observed_branch_instructions": state["branches"],
        "fixture_memory_profile": memory_profile,
        "pe_snapshot_pages_backed_by_original_file": len(pages_loaded),
    }
    if state["outcome"] == "original_x64_first_verified_call_reached":
        result["callsite_rva"] = hex(state["callsite"])
        result["native_verified_target_rva"] = hex(state["target"])
        result["original_pre_call_rsp_decrement"] = (
            GUEST_ENTRY_SP - uc.reg_read(UC_X86_REG_RSP)
        )
        result["native_parent_function_verified"] = False
    return result

def analyze(pe, mapping, evidence, max_cases=MAX_CASES):
    if not isinstance(mapping, dict) or mapping.get("input_sha256") != INPUT_SHA or (
        mapping.get("original_file_verified") is not True
    ):
        raise ValueError("Only the SHA-pinned original same-run map is accepted")
    if not 1 <= max_cases <= MAX_CASES:
        raise ValueError("Out-of-bounds fixture count")
    targets = verified_targets(evidence)
    parents = sorted({
        int(parent, 16) for parent, children in
        mapping.get("direct_call_graph", {}).items()
        if any(int(child, 16) in targets for child in children)
    })
    if len(parents) > MAX_PARENT_PROLOGUES:
        raise RuntimeError("Unbounded parent-call traversal")
    pdata = pdata_index(pe)
    reasons = Counter()
    cases = Counter()
    profiles = Counter()
    distinct_sites = set()
    baseline_sites = set()
    covered_parents = set()
    parent_summary = []
    empty_unwind_entries_accepted = 0
    for begin in parents:
        if begin not in pdata:
            reasons["missing_parent_unwind"] += 1
            continue
        end, metadata = pdata[begin]
        unwind = decode_frontier_unwind(pe, metadata)
        if not unwind.get("eligible"):
            reasons[unwind["reason"]] += 1
            continue
        if unwind.get("evidence") == "exact_legal_zero_code_win64_unwind":
            empty_unwind_entries_accepted += 1
        blocked = preflight(pe, begin, end, unwind)
        if blocked:
            reasons[blocked] += 1
            continue
        seen = Counter()
        successes = {}
        for fixture in range(max_cases):
            outcome = run_fixture(pe, begin, end, unwind, targets, fixture)
            seen[outcome["outcome"]] += 1
            cases[outcome["outcome"]] += 1
            profiles[outcome["fixture_memory_profile"] + ":" + outcome["outcome"]] += 1
            if outcome["outcome"] == "original_x64_first_verified_call_reached":
                key = (outcome["callsite_rva"], outcome["native_verified_target_rva"])
                successes.setdefault(key, outcome)
                distinct_sites.add(key)
                if outcome["fixture_memory_profile"] == "stack_only":
                    baseline_sites.add(key)
                covered_parents.add(begin)
        if successes:
            parent_summary.append({
                "parent_rva": hex(begin),
                "distinct_reached_first_calls": len(successes),
                "verified_first_calls": list(successes.values()),
                "fixture_outcomes": dict(sorted(seen.items())),
                "native_parent_function_verified": False,
            })
        else:
            reasons["eligible_prologue_but_no_qualifying_first_call"] += 1
    return {
        "schema": 1,
        "scope": "multi_fixture_original_x64_only_before_first_call",
        "original_sha256": INPUT_SHA,
        "parent_functions_considered": len(parents),
        "fixture_count_per_eligible_parent": max_cases,
        "original_x64_fixtures_executed": sum(cases.values()),
        "exact_empty_unwind_parent_records_accepted": empty_unwind_entries_accepted,
        "original_parent_entries_reaching_verified_first_call": len(covered_parents),
        "distinct_original_verified_first_call_edges_reached": len(distinct_sites),
        "distinct_first_call_edges_reached_without_heap_or_pe_data": len(baseline_sites),
        "distinct_first_call_edges_reached_using_extended_test_memory": len(distinct_sites - baseline_sites),
        "fixture_profile_outcomes": dict(sorted(profiles.items())),
        "candidate_parent_rejections": dict(sorted(reasons.items())),
        "fixture_outcomes": dict(sorted(cases.items())),
        "successful_parent_metadata": parent_summary,
        "native_parent_functions_added": 0,
        "original_game_code_or_guest_register_values_exported": False,
        "engine_boot_verified": False,
    }

def run(executable, mapping_file, evidence_file, report_dir):
    pe = PE(executable)
    if hashlib.sha256(pe.b).hexdigest() != INPUT_SHA:
        raise RuntimeError("Owned original executable changed SHA")
    report = analyze(pe, json.loads(mapping_file.read_text()),
                     json.loads(evidence_file.read_text()))
    report_dir.mkdir(parents=True, exist_ok=True)
    (report_dir / "original-parent-firstcall-batch.json").write_text(
        json.dumps(report, indent=2) + "\n")
    lines = [
        "# MX Bikes multi-fixture parent-to-native-leaf x64 frontier", "",
        "- Original parent candidates: **" + str(report["parent_functions_considered"]) + "**",
        "- Original x64 register/flag fixtures actually executed: **" +
        str(report["original_x64_fixtures_executed"]) + "**",
        "- Distinct original eligible first-CALL edges reached: **" +
        str(report["distinct_original_verified_first_call_edges_reached"]) + "**",
        "- Parent entries reaching at least one verified native leaf as first CALL: **" +
        str(report["original_parent_entries_reaching_verified_first_call"]) + "**",
        "- Exact original empty-frame unwind parents conservatively admitted: **" +
        str(report["exact_empty_unwind_parent_records_accepted"]) + "**",
        "- Entire parent functions translated on ARM64 by this batch: **0**",
        "- Original first-CALL edges reached with stack-only fixtures: **" +
        str(report["distinct_first_call_edges_reached_without_heap_or_pe_data"]) + "**",
        "- Additional edges first reached only with extended test-domain guest-memory models: **" +
        str(report["distinct_first_call_edges_reached_using_extended_test_memory"]) + "**", "",
        "| Candidate classification | Count |", "| --- | ---: |",
    ]
    lines.extend("| " + key + " | " + str(value) + " |"
                 for key, value in report["candidate_parent_rejections"].items())
    lines += ["", "| Original x64 first-CALL fixture outcome | Cases |", "| --- | ---: |"]
    lines.extend("| " + key + " | " + str(value) + " |"
                 for key, value in report["fixture_outcomes"].items())
    lines += ["", "**Original x64 paths with deterministic test input only; NO native parent execution.**",
              "**All unsupported paths fail closed. Not an engine boot, rendered frame or iOS app.**", ""]
    summary = "\n".join(lines)
    (report_dir / "original-parent-firstcall-batch.md").write_text(summary)
    print(summary)
    return report

if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("original_executable", type=Path)
    p.add_argument("same_run_map", type=Path)
    p.add_argument("same_run_verified_native", type=Path)
    p.add_argument("report_dir", type=Path)
    a = p.parse_args()
    run(a.original_executable, a.same_run_map, a.same_run_verified_native, a.report_dir)
