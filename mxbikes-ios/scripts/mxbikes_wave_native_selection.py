#!/usr/bin/env python3
"""Order real closed-leaf x64→ARM64 validation from the startup wave queue.

Scheduling never makes an unwind interval a valid native function. The private
original-binary closed-leaf validator remains the sole source of executable
candidates; waves only change scheduling, not code eligibility.
"""
from __future__ import annotations
from collections import Counter
import re

SHA = "4ae7de3854b4d0a18271679fb57a1f2fdf0b21804417b85dd82055078ea123b6"
MAX_BATCHES = 4096
MAX_WAVE_ENTRIES = 64
HEX = re.compile(r"0x[0-9a-fA-F]{1,8}\Z")


def parse_address(value):
    if not isinstance(value, str) or not HEX.fullmatch(value):
        raise ValueError("Invalid static original wave address")
    return int(value, 16)


def validated_waves(waves):
    """Strictly validate planner metadata before it can influence test order."""
    if waves is None:
        return []
    if (not isinstance(waves, dict) or waves.get("original_sha256") != SHA
        or waves.get("schema") != 1
        or not isinstance(waves.get("code_batches"), list)
        or len(waves["code_batches"]) > MAX_BATCHES):
        raise ValueError("Unverified or oversized MX Bikes wave input")
    batches = []
    all_seen = set()
    ids = set()
    for item in waves["code_batches"]:
        if not isinstance(item, dict):
            raise ValueError("Malformed native validation wave")
        bid = item.get("batch_id")
        nodes = item.get("original_entries")
        if (not isinstance(bid, str) or not re.fullmatch(r"wave-[0-9]{3,4}", bid)
            or bid in ids or not isinstance(nodes, list)
            or not 1 <= len(nodes) <= MAX_WAVE_ENTRIES):
            raise ValueError("Invalid or duplicated wave")
        if item.get("native_dispatch_ready") is not False:
            raise ValueError("Unverified wave falsely marked native ready")
        ids.add(bid)
        converted = [parse_address(x) for x in nodes]
        if len(set(converted)) != len(converted) or all_seen.intersection(converted):
            raise ValueError("Duplicated native entry across waves")
        all_seen.update(converted)
        batches.append((bid, converted))
    return batches


def ordered_call_targets(called, waves=None):
    """Prioritize wave-identified original call targets; preserve global fallback."""
    batches = validated_waves(waves)
    if not isinstance(called, Counter):
        called = Counter(called)
    if any(not isinstance(k, int) or not isinstance(v, int)
           or k < 0 or v <= 0 for k, v in called.items()):
        raise ValueError("Malformed direct-call target counts")
    preferred = {}
    for bid, entries in batches:
        for address in entries:
            if address in called:
                preferred[address] = bid
    order = []
    seen = set()
    for bid, entries in batches:
        for address in sorted((a for a in entries if a in called),
                              key=lambda a: (-called[a], a)):
            order.append((address, called[address], bid))
            seen.add(address)
    order.extend((address, count, None) for address, count in called.most_common()
                 if address not in seen)
    return order


def summarize_native_execution(waves, candidates):
    """Call after the complete original-x64/host/ARM64 differential passes."""
    batches = validated_waves(waves)
    candidates = list(candidates)
    checked = {c["rva"] for c in candidates}
    if len(checked) != len(candidates):
        raise ValueError("Repeated executed native candidate")
    ids = {bid for bid, _ in batches}
    if any(c.get("wave_batch_id") not in ids | {None} for c in candidates):
        raise ValueError("Executed candidate has unknown wave attribution")
    assigned = set()
    report = []
    for bid, addresses in batches:
        executed = [a for a in addresses if a in checked]
        assigned.update(executed)
        report.append({
            "batch_id": bid,
            "original_entries_in_static_wave": len(addresses),
            "complete_closed_leafs_native_executed": len(executed),
            "native_executed_original_rvas": [hex(a) for a in executed],
            "remaining_entries_not_native_verified": len(addresses)-len(executed),
            "wave_completed": len(addresses) == len(executed),
            "note": "Only complete closed leaf semantics tested, not full game boot",
        })
    return {
        "schema": 1, "original_sha256": SHA,
        "private_native_batch_differential_passed": True,
        "native_validated_leaf_total": len(checked),
        "native_validated_in_scheduled_waves": len(assigned),
        "native_validated_global_fallback": len(checked)-len(assigned),
        "total_static_waves": len(batches),
        "waves_fully_native_verified": sum(x["wave_completed"] for x in report),
        "waves": report,
        "full_startup_native_executed": False,
        "ios_game_boot_verified": False,
        "limitation": "A complete x64 leaf differential confirms only that function's bounded semantics."
    }
