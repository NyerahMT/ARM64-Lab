#!/usr/bin/env python3
"""Rank real observed x64 startup blockers without claiming a native game boot.

Reads only a bounded, sanitized private Unicorn CRT-frontier JSON report.
Separates imports the original game *called* under test doubles from APIs
independently implemented in the native ARM64 runtime. This cannot establish
native startup, Steam support, a renderer, or an interactive menu.

No executable, recovered machine code, function body, or raw disassembly is
required by the report. The engine and CRT can thus be investigated in parallel.
"""
from __future__ import annotations

import argparse
from collections import Counter, defaultdict
import json
from pathlib import Path

MAX_IMPORTS = 512
MAX_PATH = 256
MAX_INSTRUCTIONS = 10_000_000
NATIVE_PORTABLE_IMPORTS = frozenset({
    ("kernel32.dll", "getcurrentprocessid"),
    ("kernel32.dll", "getcurrentthreadid"),
    ("kernel32.dll", "gettickcount"),
    ("kernel32.dll", "queryperformancecounter"),
    ("kernel32.dll", "queryperformancefrequency"),
    ("kernel32.dll", "getsystemtimeasfiletime"),
    ("kernel32.dll", "sleep"),
    ("winmm.dll", "timegettime"),
})
# Implemented synthetic host services, NOT a native Win64 DLL replacement.
TEST_ONLY_CRT = frozenset({
    "_encode_pointer", "_decode_pointer", "_lock", "_unlock",
    "_onexit", "__dllonexit", "_initterm", "_initterm_e"
})
STEAM_STARTUP = frozenset({
    "steamapi_init", "steamapi_restartappifnecessary",
    "steaminternal_contextinit"
})
WINDOW_CALLS = frozenset({
    "createwindowexa", "registerclassexa", "showwindow",
    "peekmessagea", "dispatchmessagea", "translatemessage",
    "getclientrect", "setwindowtexta"
})
CONTEXT_CALLS = frozenset({
    "wglcreatecontext", "wglmakecurrent", "choosepixelformat",
    "setpixelformat", "swapbuffers"
})
BOOT_PRIORITY = (
    "steam_or_external_runtime",
    "process_crt",
    "filesystem",
    "window_input",
    "graphics_context",
    "opengl_render",
    "other_external"
)

def split_import(text: str) -> tuple[str, str]:
    if not isinstance(text, str) or len(text) > MAX_PATH:
        raise ValueError("Invalid or oversized import name")
    parts = text.split("::")
    if len(parts) != 2 or not all(parts):
        raise ValueError("Expected module::symbol import name")
    lib, symbol = parts
    if len(lib) > 96 or len(symbol) > 160:
        raise ValueError("Import name exceeds bounds")
    if any(c.isspace() or ord(c) < 33 or ord(c) > 126 for c in text):
        raise ValueError("Import contains whitespace or non-ASCII data")
    return lib.lower(), symbol.lower()

def categorize(dll: str, symbol: str) -> str:
    if dll == "steam_api64.dll" or symbol in STEAM_STARTUP:
        return "steam_or_external_runtime"
    if dll == "msvcr90.dll":
        if symbol in ("fopen", "fread", "fclose", "fseek", "ftell", "fgetc", "feof"):
            return "filesystem"
        return "process_crt"
    if dll in {"opengl32.dll"} or symbol.startswith("gl"):
        if symbol.startswith("wgl"):
            return "graphics_context"
        return "opengl_render"
    if symbol in CONTEXT_CALLS or dll in {"gdi32.dll"}:
        return "graphics_context"
    if symbol in WINDOW_CALLS or dll in {"user32.dll", "dinput8.dll"}:
        return "window_input"
    if symbol in {
        "getmodulefilenamea", "setcurrentdirectorya",
        "createfilea", "readfile", "getfileattributesa"
    }:
        return "filesystem"
    if dll in {"kernel32.dll", "advapi32.dll", "ole32.dll", "shell32.dll"}:
        return "process_crt"
    return "other_external"

def runtime_classification(dll: str, symbol: str) -> str:
    if (dll, symbol) in NATIVE_PORTABLE_IMPORTS:
        return "native_portable_service_tested_in_isolation"
    if dll == "msvcr90.dll" and symbol in TEST_ONLY_CRT:
        return "synthetic_crt_contract_only"
    if dll == "steam_api64.dll":
        return "steam_integration_not_implemented"
    return "native_service_unverified"

def analyze_frontier(data: dict) -> dict:
    if not isinstance(data, dict):
        raise ValueError("Expected a dynamic startup trace dictionary")
    required = {"original_instruction_count", "windows_imports_called",
                "stop_reason", "native_arm64_executed"}
    if required - data.keys():
        raise ValueError("Dynamic original x64 execution report incomplete")
    instructions = data["original_instruction_count"]
    imports = data["windows_imports_called"]
    if (not isinstance(instructions, int) or isinstance(instructions, bool)
            or not 0 <= instructions <= MAX_INSTRUCTIONS):
        raise ValueError("Original instruction count exceeds bounded interval")
    if not isinstance(imports, dict) or len(imports) > MAX_IMPORTS:
        raise ValueError("Import inventory exceeds safety bounds")
    if data["native_arm64_executed"] is not False:
        raise ValueError("This analyzer is for original x64 execution, not ARM64")
    if data["stop_reason"] is not None and (
            not isinstance(data["stop_reason"], str)
            or len(data["stop_reason"]) > 96):
        raise ValueError("Invalid stop reason")
    grouped = defaultdict(list)
    observed = set()
    total = 0
    for name, count in imports.items():
        dll, symbol = split_import(name)
        if (not isinstance(count, int) or isinstance(count, bool)
                or not 1 <= count <= MAX_INSTRUCTIONS):
            raise ValueError("Invalid observed import call count")
        total += count
        if total > MAX_INSTRUCTIONS:
            raise ValueError("Unbounded import events")
        observed.add((dll, symbol))
        grouped[categorize(dll, symbol)].append({
            "import": name,
            "observed_x64_calls": count,
            "native_status": runtime_classification(dll, symbol),
        })
    for category in grouped:
        grouped[category].sort(key=lambda x: (-x["observed_x64_calls"], x["import"]))
    stop = data["stop_reason"]
    first = data.get("unimplemented_import")
    if first is not None:
        dll, symbol = split_import(first)
        blocker_group = categorize(dll, symbol)
        blocker_status = runtime_classification(dll, symbol)
        # Fail closed: don't claim the import was called if missing in trace.
        if (dll, symbol) not in observed:
            raise ValueError("Reported unsupported import was not observed")
    elif data.get("memory_fault"):
        first, blocker_group, blocker_status = (
            "guest memory fault", "guest_memory", "original_x64_trace_incomplete")
    elif stop in {"instruction_count_or_timeout", "emulator_exception"}:
        first, blocker_group, blocker_status = (
            "execution bound or emulator fault", "runtime_research",
            "original_x64_trace_incomplete")
    else:
        first, blocker_group, blocker_status = (
            "no recorded unsupported external import",
            "unresolved_runtime_frontier", "not_a_native_startup_proof")
    reached_steam = any(dll == "steam_api64.dll" and name == "steamapi_init"
                        for dll, name in observed)
    reached_window = any(name in WINDOW_CALLS for _, name in observed)
    reached_graphics = any(name in CONTEXT_CALLS or dll == "opengl32.dll"
                           for dll, name in observed)
    groups = [{
        "category": category,
        "distinct_imports": len(grouped[category]),
        "observed_call_events": sum(x["observed_x64_calls"] for x in grouped[category]),
        "imports": grouped[category],
    } for category in BOOT_PRIORITY if grouped[category]]
    # Do not confuse x64 emulated CRT callbacks with native completion.
    return {
        "source": "bounded original x64 instructions, Windows/CRT import test doubles",
        "original_x64_instructions_executed": instructions,
        "original_x64_stop_reason": stop,
        "observed_x64_import_events": total,
        "observed_x64_unique_imports": len(imports),
        "first_blocker": {
            "name": first,
            "category": blocker_group,
            "native_readiness": blocker_status,
        },
        "x64_progress_signals": {
            "original_entry_instructions_executed": instructions > 0,
            "steamapi_init_call_observed": reached_steam,
            "window_api_call_observed": reached_window,
            "graphics_context_or_gl_call_observed": reached_graphics,
        },
        "observed_groups": groups,
        "native_milestones": {
            "complete_original_native_startup": False,
            "original_engine_initialized": False,
            "first_original_rendered_frame": False,
            "interactive_original_menu": False,
        },
        "prioritization_rule": (
            "First validate the observed unresolved import or memory fault. "
            "Static Windows graphics imports are not evidence those paths executed. "
            "Do not assume Steam initialization succeeds or bypass it."
        ),
        "limitations": [
            "The original game ran only in an x64 emulator with injected services.",
            "Original CRT initializer callbacks may have executed under test doubles.",
            "Native portable services are independently tested but not proven on this startup trace.",
            "No original ARM64 engine, Windows API, OpenGL frame or iOS app was executed.",
            "No source code, private binary bytes or original instruction text is exported.",
        ],
    }

def make_summary(report: dict) -> str:
    items = [
        "# MX Bikes — observed engine/CRT startup frontier", "",
        "- Original x64 guest instructions: **" +
        str(report["original_x64_instructions_executed"]) + "**",
        "- Observed import events: **" +
        str(report["observed_x64_import_events"]) + "** across **" +
        str(report["observed_x64_unique_imports"]) + "** API names",
        "- Original x64 stop reason: **" +
        str(report["original_x64_stop_reason"]) + "**",
        "- First unresolved frontier: **" +
        report["first_blocker"]["name"] + "**",
        "- Blocker family: **" +
        report["first_blocker"]["category"] + "**", "",
        "| Dynamically exercised dependency group | Distinct symbols | Import calls |",
        "| --- | ---: | ---: |",
    ]
    for group in report["observed_groups"]:
        items.append("| " + group["category"] + " | " +
                     str(group["distinct_imports"]) + " | " +
                     str(group["observed_call_events"]) + " |")
    items.extend([
        "", "## Parallel engine-entry investigation", "",
        "- Observed original x64 SteamAPI_Init call: **" +
        str(report["x64_progress_signals"]["steamapi_init_call_observed"]) + "**",
        "- Observed original x64 window API: **" +
        str(report["x64_progress_signals"]["window_api_call_observed"]) + "**",
        "- Observed original x64 GL/WGL API: **" +
        str(report["x64_progress_signals"]["graphics_context_or_gl_call_observed"]) + "**",
        "", "**These are original x64 emulation observations with synthetic "
        "import hooks. All four native startup/engine/frame/menu milestones "
        "remain unverified. This report is for prioritization, not proof "
        "of a playable game.**", "",
    ])
    return "\n".join(items)

def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("trace", type=Path)
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()
    if args.trace.stat().st_size > 1024 * 1024:
        raise ValueError("Input report too large")
    report = analyze_frontier(json.loads(args.trace.read_text(encoding="utf-8")))
    args.output_dir.mkdir(parents=True, exist_ok=True)
    (args.output_dir/"boot-frontier.json").write_text(
        json.dumps(report, indent=2)+"\n", encoding="utf-8")
    md = make_summary(report)
    (args.output_dir/"boot-frontier.md").write_text(md, encoding="utf-8")
    print(md)

if __name__ == "__main__":
    main()
