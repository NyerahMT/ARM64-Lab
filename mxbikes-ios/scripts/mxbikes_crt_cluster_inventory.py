#!/usr/bin/env python3
"""Private original-game CRT dependency clusters using the public generic mapper.

The owned game executable stays on the ephemeral private CI runner. The
uploaded report contains only address, callgraph and coverage metadata.
"""
from pathlib import Path
from collections import Counter
import hashlib
import json
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "arm64-lab"))
from tools.pe_probe import PE
from tools.pe_call_clusters import scan, unwind_functions
from tools.x64_semantics_gap import summarize_mnemonics
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
from mxbikes_first_callee_emu import import_slots
from mxbikes_crt_exception_callback_differential import SHA

ROOTS = (0x2ab02c, 0x2ab734, 0x2ab7e4, 0x2ab714, 0x2ab234,
         0x2aafc4, 0x1306e8)  # Main CRT and engine-to-Steam handoff included


def run(exe, output):
    pe = PE(exe)
    if hashlib.sha256(pe.b).hexdigest() != SHA:
        raise RuntimeError("Private original executable does not match pinned revision")
    imports = {rva: dll.lower() + "::" + name
               for rva, dll, name in import_slots(pe)}
    result = scan(pe, ROOTS, imports=imports, max_depth=2,
                  max_nodes=96, max_bytes=4096)
    if result["function_count"] < len(ROOTS):
        raise RuntimeError("Original CRT dependency roots were not all visited")
    if any(x["rva"] not in {v["rva"] for v in result["nodes"]}
           for x in ({"rva": hex(root)} for root in ROOTS)):
        raise RuntimeError("Missing original CRT dependency root")
    # Diagnose the whole original 126-instruction CRT target by opcode
    # family without claiming that operand forms or services are implemented.
    bounds = unwind_functions(pe)
    crt_start = 0x2ab02c
    crt_end = bounds.get(crt_start)
    if crt_end is None or crt_end - crt_start != 518:
        raise RuntimeError("Verified CRT interval changed")
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    crt_ins = list(md.disasm(pe.read_rva(crt_start, 518), crt_start))
    if len(crt_ins) != 126 or sum(i.size for i in crt_ins) != 518:
        raise RuntimeError("Original CRT instruction decoding incomplete")
    # Capstone writes instruction prefixes as spaces (e.g. "lock cmpxchg").
    # Normalize only the aggregate family name; never export original operands.
    profile = summarize_mnemonics(dict(Counter(
        i.mnemonic.replace(" ", "_") for i in crt_ins)))
    output.mkdir(parents=True, exist_ok=True)
    (output / "crt-dependency-clusters.json").write_text(
        json.dumps({"call_graph": result,
                    "crt_opcode_family_profile": profile}, indent=2) + "\n")
    lines = [
        "# MX Bikes original CRT dependency clusters", "",
        "- Distinct functions reached: **" + str(result["function_count"]) + "**",
        "- Connected translation components: **" +
        str(len(result["translation_batches"])) + "**",
        "- Function statuses: " + ", ".join(
            k + "=" + str(v) for k, v in result["status_counts"].items()),
        "- Truncated node frontier: **" +
        str(len(result["truncated_frontier"])) + "**",
        "- Dependency-first batch order: **" +
        ", ".join(str(x) for x in result["translation_order"]) + "**",
        "- Static batches with a fully resolved graph closure: **" +
        str(sum(x["dependency_closure_ready"]
                for x in result["translation_batches"])) + "/" +
        str(len(result["translation_batches"])) + "**", "",
        "## Original 126-instruction CRT opcode-family inventory", "",
        "- Recognized mnemonic-family instances: **" +
        str(profile["mnemonics_currently_recognized"]) + "/126**",
        "- Missing mnemonic-family instances: **" +
        str(profile["mnemonics_needing_extensions"]) + "/126**",
        "- Unsupported mnemonic totals: " +
        (", ".join(k + "=" + str(v) for k, v in
                   profile["unsupported_mnemonics"].items()) or "none"),
        "- This is **mnemonic-only coverage**, not operand support, a complete " +
        "translator, executed ARM64 or real CRT service behavior.", "",
        "## Bounded dependency graph", "",
        "| Original RVA | Depth | Decode | Instructions | Direct dependencies | Imports | Resolved import thunks | Unresolved |",
        "| --- | ---: | --- | ---: | ---: | ---: | ---: | ---: |",
    ]
    for item in result["nodes"]:
        lines.append("| " + item["rva"] + " | " + str(item["depth"]) +
                     " | " + item["status"] + " | " +
                     str(item.get("instruction_count", 0)) + " | " +
                     str(len(item["calls"])) + " | " +
                     str(len(item["imports"])) + " | " +
                     str(len(item["import_thunks"])) + " | " +
                     str(len(item["unresolved"])) + " |")
    lines += ["", "## Translation component ordering", "",
              "| Batch | Original RVAs | Prerequisite batches | Direct blockers | Blocked by | Closure ready |",
              "| ---: | --- | --- | ---: | --- | --- |"]
    for bid in result["translation_order"]:
        batch = result["translation_batches"][bid]
        lines.append("| " + str(bid) + " | " +
                     ", ".join(batch["members"]) + " | " +
                     (", ".join(map(str, batch["depends_on_batches"])) or "-") +
                     " | " + str(batch["external_blockers"]) + " | " +
                     (", ".join(map(str, batch["blocked_by_batches"])) or "-") +
                     " | " + ("yes" if batch["dependency_closure_ready"] else "NO") +
                     " |")
    lines += ["", "**This is only a static dependency inventory. A ready" +
              " batch is not proven translated or executable; CRT callbacks," +
              " real imported services, Steam and game boot remain separate.**", ""]
    report = "\n".join(lines)
    (output / "crt-dependency-clusters.md").write_text(report)
    print(report)
    print("PRIVATE CLUSTER ROOT 0x2ab734 " + json.dumps(
        next(x for x in result["nodes"] if x["rva"] == "0x2ab734"),
        sort_keys=True))
    # Instruction forms are kept in the access-controlled CI log only;
    # exported metadata artifacts never contain proprietary disassembly.
    for entry in (0x2ab734, 0x2ab7fc):
        end = bounds.get(entry)
        if end is None or end - entry > 512:
            print(" PRIVATE CLUSTER FORM UNAVAILABLE " + hex(entry))
            continue
        for ins in md.disasm(pe.read_rva(entry, end - entry), entry):
            print(" PRIVATE CLUSTER FORM " + hex(entry) + " " +
                  hex(ins.address) + " " + ins.mnemonic + " " + ins.op_str)


if __name__ == "__main__":
    if len(sys.argv) != 3:
        raise SystemExit("usage: script.py /private/original.exe output-dir")
    run(Path(sys.argv[1]), Path(sys.argv[2]))
