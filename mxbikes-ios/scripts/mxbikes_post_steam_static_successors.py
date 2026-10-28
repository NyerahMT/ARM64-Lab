#!/usr/bin/env python3
"""Map the ORIGINAL game main's possible successors after a Steam CALL return.

Strictly static: SteamAPI_RestartAppIfNecessary is neither executed nor assigned
a return value. The first PC is the six-byte CALL's authentic fallthrough RVA.
Both sides of each conditional branch are explored *as possibilities*, never
as observed game execution. Additional local CALLs are cataloged; scanning
past their return sites also remains hypothetical. No authorization, engine
startup, original bytes, or lifted code is exported.
"""
from __future__ import annotations
from collections import Counter, deque
import hashlib
import json
from pathlib import Path
import struct
import sys

from capstone import Cs, CS_ARCH_X86, CS_MODE_64, CS_GRP_JUMP
from capstone.x86 import X86_OP_IMM, X86_OP_MEM

from mxbikes_first_callee_emu import import_slots
from mxbikes_whole_game_map import INPUT_SHA

STEAM_CALL_RVA = 0x1306ed
STEAM_RETURN_RVA = 0x1306f3
STEAM_IAT_RVA = 0x321a18
STEAM_SYMBOL = ("steam_api64.dll", "SteamAPI_RestartAppIfNecessary")
MAX_FUNCTION_BYTES = 32768
MAX_PDATA_BYTES = 2 * 1024 * 1024
MAX_INSTRUCTIONS = 768
MAX_BRANCHES = 128
MAX_CALLS = 96
MAX_RETURNS_PER_PATH = 12
MAX_IMPORTS = 4096


def containing_unwind(pe, rva):
    """Return the unique original PE .pdata range covering this RVA."""
    begin, size = pe.directory(3)
    if not begin or not size or size % 12 or size > MAX_PDATA_BYTES:
        raise ValueError("Missing or malformed bounded PE unwind directory")
    matches = []
    for start, end, _unwind in struct.iter_unpack("<III", pe.read_rva(begin, size)):
        if start <= rva < end:
            matches.append((start, end))
    if len(matches) != 1:
        raise ValueError("Steam return is not in one original unwind interval")
    start, end = matches[0]
    if not 0 < end-start <= MAX_FUNCTION_BYTES:
        raise ValueError("Steam successor function exceeds static scan budget")
    return start, end


def _one(pe, decoder, rva, end, base):
    if not 0 <= rva < end:
        raise ValueError("Invalid original instruction address")
    raw = bytes(pe.read_rva(rva, min(15, end-rva)))
    rows = list(decoder.disasm(raw, base+rva, count=1))
    if not rows or rows[0].address != base+rva:
        raise ValueError("Cannot decode original instruction at " + hex(rva))
    return rows[0]


def _iat_from_operand(ins, base):
    if len(ins.operands) != 1 or ins.operands[0].type != X86_OP_MEM:
        return None
    mem = ins.operands[0].mem
    if ins.reg_name(mem.base) != "rip" or mem.index:
        return None
    return ins.address + ins.size + mem.disp - base


def _direct_target(ins, base):
    if len(ins.operands) == 1 and ins.operands[0].type == X86_OP_IMM:
        return int(ins.operands[0].imm) - base
    return None


def classify_call(ins, slots, base):
    slot = _iat_from_operand(ins, base)
    target = _direct_target(ins, base)
    info = {"site_rva": hex(ins.address-base),
            "kind": "indirect_unresolved",
            "native_function_verified": False,
            "executed": False}
    if target is not None:
        info.update(kind="direct_original_call", target_rva=hex(target))
    elif slot is not None:
        info["iat_slot_rva"] = hex(slot)
        if slot in slots:
            lib, symbol = slots[slot]
            info.update(kind="named_import", library=lib, symbol=symbol)
        else:
            info["kind"] = "unresolved_indirect_memory_call"
    return info


def map_possible_successors(pe, imports, *, base=0x140000000,
                            call_rva=STEAM_CALL_RVA,
                            return_rva=STEAM_RETURN_RVA,
                            expected_slot=STEAM_IAT_RVA,
                            expected_symbol=STEAM_SYMBOL):
    """Scan bounded static CFG; no emulated registers or guessed API results."""
    if not 0 < base < 1 << 64 or not 0 <= call_rva < return_rva < 1 << 32:
        raise ValueError("Invalid original image base or call addresses")
    if not isinstance(imports, (list, tuple)) or len(imports) > MAX_IMPORTS:
        raise ValueError("Missing or excessive PE import slots")
    slots = {}
    for slot, lib, symbol in imports:
        if (not isinstance(slot, int) or not 0 <= slot < 1 << 32 or
            slot in slots or not isinstance(lib, str) or not lib or
            not isinstance(symbol, str) or not symbol):
            raise ValueError("Invalid or duplicate original PE import")
        slots[slot] = (lib, symbol)
    if expected_slot not in slots or (
        slots[expected_slot][0].lower(), slots[expected_slot][1]
    ) != (expected_symbol[0].lower(), expected_symbol[1]):
        raise ValueError("Real original Steam IAT identity changed")

    start, end = containing_unwind(pe, return_rva)
    if not start <= call_rva < return_rva < end:
        raise ValueError("Original Steam CALL not in the return function")
    dec = Cs(CS_ARCH_X86, CS_MODE_64)
    dec.detail = True
    steam_ins = _one(pe, dec, call_rva, end, base)
    if (steam_ins.mnemonic != "call" or
        steam_ins.address+steam_ins.size != base+return_rva or
        _iat_from_operand(steam_ins, base) != expected_slot):
        raise ValueError("Steam CALL opcode/callsite or return address drift")

    # The initial queue is a HYPOTHETICAL return from external Steam.
    # Subsequent CALL fallthroughs are also hypothetical, tracked by count.
    todo = deque([(return_rva, 0)])
    visited = {}
    branches = []
    calls = []
    terminals = []
    mnemonics = Counter()
    truncation = []
    while todo:
        pc, assumed_calls = todo.popleft()
        if not start <= pc < end:
            terminals.append({"kind": "outside_original_unwind", "rva": hex(pc)})
            continue
        if pc in visited and visited[pc] <= assumed_calls:
            continue
        if len(visited) >= MAX_INSTRUCTIONS:
            truncation.append("instruction_budget")
            break
        visited[pc] = assumed_calls
        try:
            ins = _one(pe, dec, pc, end, base)
        except (ValueError, OverflowError):
            terminals.append({"kind": "undecodable", "rva": hex(pc)})
            continue
        mnemonics[ins.mnemonic] += 1
        following = pc + ins.size
        if ins.mnemonic == "call":
            if len(calls) >= MAX_CALLS:
                truncation.append("call_budget")
                break
            call = classify_call(ins, slots, base)
            call["assumed_prior_local_returns"] = assumed_calls
            calls.append(call)
            if assumed_calls < MAX_RETURNS_PER_PATH:
                todo.append((following, assumed_calls+1))
            else:
                terminals.append({"kind": "call_return_depth_limit",
                                  "rva": hex(pc)})
            continue
        if ins.mnemonic.startswith("ret"):
            terminals.append({"kind": "original_return", "rva": hex(pc)})
            continue
        if ins.mnemonic in ("int", "int3", "ud2", "hlt", "syscall", "sysenter"):
            terminals.append({"kind": "noncontinuable_opcode", "rva": hex(pc)})
            continue
        if ins.group(CS_GRP_JUMP):
            dest = _direct_target(ins, base)
            if dest is None:
                terminals.append({"kind": "indirect_jump_unresolved",
                                  "rva": hex(pc)})
                continue
            if len(branches) >= MAX_BRANCHES:
                truncation.append("branch_budget")
                break
            conditional = ins.mnemonic != "jmp"
            branches.append({"source_rva": hex(pc),
                             "kind": "conditional" if conditional else "unconditional",
                             "taken_rva": hex(dest),
                             "fallthrough_rva": hex(following) if conditional else None,
                             "condition_value_known": False})
            todo.append((dest, assumed_calls))
            if conditional:
                todo.append((following, assumed_calls))
            continue
        if following >= end:
            terminals.append({"kind": "fell_out_of_unwind", "rva": hex(following)})
        else:
            todo.append((following, assumed_calls))
    if not visited:
        raise ValueError("No decodable post-Steam original instruction")
    # Persist only addresses, import names and aggregate forms, never bytes.
    unique_calls = {c["site_rva"]: c for c in calls}
    report = {
        "original_steam_call_rva": hex(call_rva),
        "original_steam_return_rva": hex(return_rva),
        "original_iat_slot_rva": hex(expected_slot),
        "original_caller_unwind_start_rva": hex(start),
        "original_caller_unwind_end_rva": hex(end),
        "static_successor_instructions": len(visited),
        "static_branch_count": len(branches),
        "static_callsite_count": len(unique_calls),
        "static_named_import_count": sum(
            c["kind"] == "named_import" for c in unique_calls.values()),
        "static_direct_original_call_count": sum(
            c["kind"] == "direct_original_call" for c in unique_calls.values()),
        "instruction_family_counts": dict(sorted(mnemonics.items())),
        "possible_branches": branches,
        "possible_calls": sorted(unique_calls.values(), key=lambda x:int(x["site_rva"],16)),
        "scan_terminals": terminals,
        "incomplete": bool(truncation),
        "limits_encountered": sorted(set(truncation)),
        "assumes_steam_call_returned": True,
        "conditional_paths_have_not_executed": True,
        "all_other_call_return_edges_are_hypothetical": True,
        "game_engine_executed": False,
        "native_aarch64_successor_verified": False,
        "steam_authentication_or_client_supplied": False,
    }
    return report


def run(executable, out):
    from tools.pe_probe import PE
    pe = PE(executable)
    if hashlib.sha256(pe.b).hexdigest() != INPUT_SHA:
        raise ValueError("Original owned executable SHA changed")
    out = Path(out)
    # Require the preceding verified original/ARM64 stop, not a standalone
    # fabricated Steam result or an unauthenticated launch assumption.
    prior = json.loads((out/"fused-native-entry-to-steam.json").read_text())
    if (prior.get("original_sha_verified") is not True or
        prior.get("native_steam_api_original_call_rva") != hex(STEAM_CALL_RVA) or
        prior.get("native_steam_api_executed") is not False or
        prior.get("game_engine_booted") is not False):
        raise ValueError("Pre-Steam authentic native proof missing or inconsistent")
    report = map_possible_successors(pe, import_slots(pe))
    if report["incomplete"]:
        # Still export useful metadata, but the job cannot call the
        # successor scan complete under any exceeded budget.
        raise ValueError("Static post-Steam scan truncated: "+str(report["limits_encountered"]))
    report["original_exe_sha_verified"] = True
    report["prior_native_steam_stop_verified"] = True
    out.mkdir(parents=True, exist_ok=True)
    (out/"original-post-steam-static-successors.json").write_text(
        json.dumps(report, indent=2)+"\n")
    lines = ["# MX Bikes — *possible* successors after the Steam call",
             "",
             "- SHA-pinned original x64 decode: **PASS**",
             "- Steam CALL/import/return PC identity: **PASS**",
             "- Static instruction sites analyzed: **"+str(report["static_successor_instructions"])+"**",
             "- Conditional/unconditional branches: **"+str(report["static_branch_count"])+"**",
             "- Later original CALL sites inventoried: **"+str(report["static_callsite_count"])+"**",
             "- Named external imported CALL sites: **"+str(report["static_named_import_count"])+"**",
             "- Native continuation executed after Steam: **NO**",
             "- No Steam result, license or client behavior assumed to be valid.",
             "",
             "## Static CALL candidates (not observed executions)"]
    for call in report["possible_calls"]:
        detail = (
            call.get("library","")+"!"+call.get("symbol","")
            if call["kind"] == "named_import" else
            call.get("target_rva","unresolved target"))
        lines.append("- "+call["site_rva"]+": "+call["kind"]+" "+detail)
    lines += ["","Both outcomes of each condition are analyzed without choosing a",
              "runtime branch. Code after *other* CALL sites is only a possible",
              "return path; no translated engine, Steam handoff or rendered frame.",""]
    (out/"original-post-steam-static-successors.md").write_text("\n".join(lines))
    print("\n".join(lines))
    return report


if __name__ == "__main__":
    if len(sys.argv) != 3:
        raise SystemExit("usage: static_successors.py owned_game.exe metadata_dir")
    run(Path(sys.argv[1]), Path(sys.argv[2]))
