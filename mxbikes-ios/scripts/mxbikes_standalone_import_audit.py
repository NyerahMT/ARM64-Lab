#!/usr/bin/env python3
"""Offline audit of a legally obtained standalone MX Bikes executable.

Metadata only. Never uploads, executes, patches, decrypts, or distributes an
original game executable. Import inspection is NOT proof of license ownership,
a working engine, or Steam-free runtime semantics. An installed, publisher-
supported standalone executable may differ from the pinned Steam build.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from tools.pe_probe import PE

MAX_EXE = 750 * 1024 * 1024
STEAM = {"steam_api.dll", "steam_api64.dll"}
GRAPHICS = {"opengl32.dll", "glu32.dll", "d3d9.dll", "d3d11.dll",
            "d3d12.dll", "dxgi.dll"}
WINDOW = {"user32.dll", "gdi32.dll", "dinput8.dll", "winmm.dll",
          "kernel32.dll", "comctl32.dll"}
PINNED_STEAM_EXE_SHA256 = (
    "4ae7de3854b4d0a18271679fb57a1f2fdf0b21804417b85dd82055078ea123b6"
)


def classify_inventory(metadata: dict) -> dict:
    """Report observed import names only; no invented runtime outcomes."""
    if metadata.get("architecture") != "x86-64 PE32+":
        raise ValueError("unsupported_executable_architecture")
    imports = metadata.get("imports")
    if not isinstance(imports, dict):
        raise ValueError("invalid_import_inventory")
    counted = {}
    for lib, names in imports.items():
        if (not isinstance(lib, str) or not isinstance(names, list) or
                len(names) > 10000 or not all(isinstance(n, str) for n in names)):
            raise ValueError("untrusted_import_inventory")
        counted[lib.lower()] = names
    steam = {k: v for k, v in counted.items() if k in STEAM}
    graphics = {k: v for k, v in counted.items() if k in GRAPHICS}
    windows = {k: v for k, v in counted.items() if k in WINDOW}
    known_sha = metadata.get("sha256")
    return {
        "format": "mxb_standalone_compatibility_audit_v1",
        "candidate_sha256": known_sha,
        "candidate_matches_pinned_steam_executable": known_sha == PINNED_STEAM_EXE_SHA256,
        "architecture": metadata["architecture"],
        "entry_rva": metadata.get("entry_rva"),
        "image_base": metadata.get("image_base"),
        "exe_size_bytes": metadata.get("size_bytes"),
        "unwind_function_records": metadata.get("exception_record_count"),
        "imported_dlls": len(counted),
        "imported_symbols": sum(len(v) for v in counted.values()),
        "steam_dll_imports": {k: v for k, v in steam.items()},
        "steam_symbol_count": sum(len(v) for v in steam.values()),
        "graphics_symbols": {k: v for k, v in graphics.items()},
        "windows_platform_symbols": {k: v for k, v in windows.items()},
        "no_static_steam_imports_observed": not bool(steam),
        "no_steam_import_is_not_proof_of_standalone_license_or_runtime": True,
        "native_ios_engine_executed": False,
        "publisher_permission_verified": False,
    }


def audit(exe: Path, out: Path) -> dict:
    exe = exe.expanduser().resolve()
    out = out.expanduser().resolve()
    if out == ROOT or ROOT in out.parents:
        raise ValueError("output_must_be_outside_public_repository")
    if not exe.is_file() or not 0 < exe.stat().st_size <= MAX_EXE:
        raise ValueError("missing_or_oversized_standalone_candidate")
    if exe == out or out in exe.parents:
        raise ValueError("cannot_write_report_inside_game_input")
    metadata = PE(exe).inventory()
    result = classify_inventory(metadata)
    out.mkdir(parents=True, exist_ok=True)
    (out / "standalone-candidate-imports.json").write_text(
        json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    return result


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--standalone-exe", type=Path, required=True,
                   help="Installed, publisher-licensed standalone runtime executable")
    p.add_argument("--out", type=Path, required=True,
                   help="Metadata-only output directory outside the public checkout")
    args = p.parse_args(argv)
    try:
        result = audit(args.standalone_exe, args.out)
    except (OSError, ValueError) as exc:
        p.exit(2, "Audit rejected: " + str(exc) + "\n")
    print(json.dumps({
        "candidate_sha256": result["candidate_sha256"],
        "steam_symbol_count": result["steam_symbol_count"],
        "graphics_api_dll_count": len(result["graphics_symbols"]),
        "windows_platform_dll_count": len(result["windows_platform_symbols"]),
        "actual_game_engine_executed": False,
    }, indent=2))


if __name__ == "__main__":
    main()
