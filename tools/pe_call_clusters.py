#!/usr/bin/env python3
"""Bounded PE32+ x64 dependency-cluster mapper.

Analyzes *metadata* about call/jump dependencies from a caller-supplied PE.
No game data is included in this tool. Its output contains RVAs, counts,
dependency types and unresolved boundaries, never original instructions.
This is analysis only: it does not translate or execute functions.
"""
from collections import Counter, deque
import struct

from capstone import Cs, CS_ARCH_X86, CS_MODE_64
from capstone.x86 import X86_OP_IMM, X86_OP_MEM

BRANCHES = {"call", "jmp"}
MAX_DEPTH = 4
MAX_NODES = 96
MAX_BYTES = 4096


def unwind_functions(pe):
    """Return validated exact function bounds from PE x64 exception data."""
    rva, size = pe.directory(3)
    if not rva or not size or size % 12 or size > 16 * 1024 * 1024:
        raise ValueError("Missing or invalid x64 unwind directory")
    rows = sorted((a, b) for a, b, _ in
                  struct.iter_unpack("<III", pe.read_rva(rva, size))
                  if 0 < a < b)
    if any(rows[i - 1][1] > rows[i][0] for i in range(1, len(rows))):
        raise ValueError("Overlapping unwind functions")
    return dict(rows)


def strongly_connected(nodes):
    """Tarjan SCCs, with stable membership and output order."""
    adj = {r: sorted(t for t in data.get("calls", [])
                     if t in nodes)
           for r, data in nodes.items()}
    stack, active, ids, low, groups = [], set(), {}, {}, []

    def visit(node):
        ids[node] = low[node] = len(ids)
        stack.append(node)
        active.add(node)
        for target in adj[node]:
            if target not in ids:
                visit(target)
                low[node] = min(low[node], low[target])
            elif target in active:
                low[node] = min(low[node], ids[target])
        if low[node] == ids[node]:
            group = []
            while True:
                member = stack.pop()
                active.remove(member)
                group.append(member)
                if member == node:
                    break
            groups.append(sorted(group))

    for node in sorted(nodes):
        if node not in ids:
            visit(node)
    return sorted(groups, key=lambda g: (len(g) != 1, g[0]))


def scan(pe, roots, imports=None, max_depth=3, max_nodes=64,
         max_bytes=MAX_BYTES):
    """Discover and group unwind-bounded dependencies; fail closed on limits.

    imports: optional {IAT_RVA: "dll::symbol"}; no DLL bytes are needed.
    A reported external/unknown edge is not a proven translated dependency.
    """
    if not roots or max_depth < 0 or max_depth > MAX_DEPTH:
        raise ValueError("Invalid dependency roots or depth")
    if not 1 <= max_nodes <= MAX_NODES or not 1 <= max_bytes <= MAX_BYTES:
        raise ValueError("Unsafe dependency analysis limits")
    bounds = unwind_functions(pe)
    imports = imports or {}
    decoder = Cs(CS_ARCH_X86, CS_MODE_64)
    decoder.detail = True
    queue = deque((int(root), 0) for root in roots)
    seen, overflow = {}, []

    def verified_import_thunk(target):
        """Recognize only a six-byte JMP [RIP+disp32] into a known IAT slot."""
        try:
            raw = pe.read_rva(target, 6)
            decoded = list(decoder.disasm(raw, target))
        except (ValueError, OSError):
            return None
        if len(decoded) != 1 or decoded[0].size != 6:
            return None
        inst = decoded[0]
        if inst.mnemonic != "jmp" or len(inst.operands) != 1:
            return None
        operand = inst.operands[0]
        if (operand.type != X86_OP_MEM or
                inst.reg_name(operand.mem.base) != "rip" or
                operand.mem.index):
            return None
        slot = inst.address + inst.size + operand.mem.disp
        if slot not in imports:
            return None
        return {"thunk_rva": hex(target), "slot_rva": hex(slot),
                "name": imports[slot]}
    while queue:
        entry, depth = queue.popleft()
        if entry in seen:
            continue
        if len(seen) >= max_nodes:
            overflow.append(hex(entry))
            continue
        info = {"rva": hex(entry), "depth": depth, "calls": [],
                "imports": [], "import_thunks": [], "unresolved": [],
                "local_branches": 0, "features": [], "status": "pending"}
        seen[entry] = info
        end = bounds.get(entry)
        if end is None:
            info["status"] = "missing_exact_unwind_entry"
            continue
        span = end - entry
        info["size_bytes"] = span
        if span > max_bytes:
            info["status"] = "too_large"
            continue
        raw = pe.read_rva(entry, span)
        instructions = list(decoder.disasm(raw, entry))
        if not instructions or sum(ins.size for ins in instructions) != span:
            info["status"] = "partial_decode"
            continue
        info["status"] = "decoded"
        info["instruction_count"] = len(instructions)
        features = set()
        for ins in instructions:
            if ins.mnemonic.startswith("lock "):
                features.add("atomic")
            if ins.mnemonic in ("syscall", "sysenter", "int"):
                features.add("syscall_or_interrupt")
            if ins.mnemonic not in BRANCHES or len(ins.operands) != 1:
                continue
            op = ins.operands[0]
            if op.type == X86_OP_IMM:
                target = op.imm
                if entry <= target < end:
                    info["local_branches"] += 1
                elif target in bounds:
                    info["calls"].append(target)
                    if depth < max_depth:
                        queue.append((target, depth + 1))
                    else:
                        info["unresolved"].append({"kind": "depth_limit",
                                                   "target": hex(target)})
                else:
                    thunk = verified_import_thunk(target) if ins.mnemonic == "call" else None
                    if thunk is not None:
                        info["import_thunks"].append(thunk)
                    else:
                        info["unresolved"].append({"kind": "no_unwind_target",
                                                   "target": hex(target)})
            elif op.type == X86_OP_MEM and ins.reg_name(op.mem.base) == "rip" and not op.mem.index:
                slot = ins.address + ins.size + op.mem.disp
                info["imports"].append({"slot_rva": hex(slot),
                                        "name": imports.get(slot),
                                        "kind": ins.mnemonic})
            else:
                info["unresolved"].append({"kind": "indirect_" + ins.mnemonic,
                                           "site": hex(ins.address)})
        info["calls"] = sorted(set(info["calls"]))
        info["features"] = sorted(features)
    groups = strongly_connected(seen)
    group_of = {r: i for i, group in enumerate(groups) for r in group}
    batches = []
    for i, group in enumerate(groups):
        outward = sorted(set(group_of[t] for r in group for t in seen[r]["calls"]
                             if t in group_of and group_of[t] != i))
        # A node cap can omit a discovered call target altogether. Such a
        # missing dependency must block the batch, not appear executable.
        missing_targets = sorted(set(
            t for r in group for t in seen[r]["calls"] if t not in seen))
        blockers = (sum(len(seen[r]["imports"]) +
                        len(seen[r]["import_thunks"]) +
                        len(seen[r]["unresolved"]) for r in group)
                    + len(missing_targets))
        batches.append({"id": i, "members": [hex(r) for r in group],
                        "depends_on_batches": outward,
                        "external_blockers": blockers,
                        "missing_dependency_targets": [hex(t) for t in missing_targets],
                        "instruction_count": sum(seen[r].get("instruction_count", 0)
                                                 for r in group),
                        "ready_for_translation": blockers == 0 and
                        all(seen[r]["status"] == "decoded" for r in group)})
    # The SCC condensation graph is acyclic. Schedule verified leaf
    # dependencies before callers and propagate blockers through callers.
    order, visiting, visited = [], set(), set()
    def schedule(batch_id):
        if batch_id in visited:
            return
        if batch_id in visiting:
            raise ValueError("Cycle remained after SCC grouping")
        visiting.add(batch_id)
        for dependency in batches[batch_id]["depends_on_batches"]:
            schedule(dependency)
        visiting.remove(batch_id)
        visited.add(batch_id)
        order.append(batch_id)
    for batch_id in range(len(batches)):
        schedule(batch_id)
    for batch_id in order:
        batch = batches[batch_id]
        blocked = [dep for dep in batch["depends_on_batches"]
                   if not batches[dep]["dependency_closure_ready"]]
        batch["blocked_by_batches"] = blocked
        batch["dependency_closure_ready"] = (
            batch["ready_for_translation"] and not blocked)
    all_nodes = [{**data, "calls": [hex(x) for x in data["calls"]]}
                 for _, data in sorted(seen.items())]
    statuses = Counter(x["status"] for x in all_nodes)
    return {"roots": [hex(int(r)) for r in roots], "limits": {
                "depth": max_depth, "nodes": max_nodes,
                "bytes_per_function": max_bytes},
            "function_count": len(all_nodes),
            "status_counts": dict(sorted(statuses.items())),
            "nodes": all_nodes, "translation_batches": batches,
            "translation_order": order,
            "truncated_frontier": sorted(set(overflow)),
            "limitations": [
                "Static direct-call and tail-jump graph, not full control flow.",
                "Indirect dispatch and dynamically loaded code are unresolved.",
                "ready_for_translation checks static local blockers only;",
                "dependency_closure_ready also requires all mapped callees;",
                "Scheduling is static, not evidence that code is executable.",
                "Decoding is not translation, equivalence, startup, or gameplay."
            ]}
