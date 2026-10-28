#!/usr/bin/env python3
"""Private MX Bikes DLL import audit using existing bounded trace metadata.

Never exports, executes, or decompiles the original commercial DLLs. Only
import names, counts, archive existence and compatibility categories are saved.
"""
import argparse
import json
from pathlib import Path
import sys

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"arm64-lab"))
from tools.pe_probe import PE
from tools.win64_import_audit import archive_index, audit_inventory, markdown_summary

EXPECTED_SHA = "4ae7de3854b4d0a18271679fb57a1f2fdf0b21804417b85dd82055078ea123b6"


def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--exe",type=Path,required=True)
    ap.add_argument("--trace",type=Path,required=True)
    ap.add_argument("--game-zip",type=Path,required=True)
    ap.add_argument("--steam-zip",type=Path,required=True)
    ap.add_argument("--output-dir",type=Path,required=True)
    args=ap.parse_args()
    inventory=PE(args.exe).inventory()
    if inventory["sha256"] != EXPECTED_SHA:
        raise RuntimeError("Original MX Bikes executable SHA-256 does not match verified revision")
    trace=json.loads(args.trace.read_text())
    archives=archive_index([args.game_zip,args.steam_zip])
    report=audit_inventory(inventory,trace,archives)
    if report["total_imports"] != inventory["import_function_count"] or report["dll_count"] != inventory["import_library_count"]:
        raise RuntimeError("Import counts diverged from PE parser")
    if report["trace_calls_unmatched"]:
        # Fail visibly when trace observes a function not present in the PE
        # import table. Could be a dynamically loaded dependency.
        print("Warning: trace references nonstatic imports:",report["trace_calls_unmatched"])
    args.output_dir.mkdir(parents=True,exist_ok=True)
    (args.output_dir/"dll-import-audit.json").write_text(json.dumps(report,indent=2)+"\n")
    md=markdown_summary(report)
    (args.output_dir/"dll-import-audit.md").write_text(md)
    print(md)


if __name__=="__main__":
    main()
