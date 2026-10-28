#!/usr/bin/env python3
"""Strictly group original-game import dependencies by *actual* adapter maturity.

Input data comes from the SHA-verified original executable's existing static
import-thunk scan. No executable bytes, generated code, string contents, game
assets, or compiled ARM64 objects are retained.

Catalog statuses describe reviewed CODE CAPABILITIES, NOT dynamically executed
imports or production Windows compatibility. An adapter file existing cannot
by itself establish operational fidelity, process integration, or iOS boot.
"""
from __future__ import annotations
from collections import Counter, defaultdict
import argparse
import json
from pathlib import Path
import re

SHA = "4ae7de3854b4d0a18271679fb57a1f2fdf0b21804417b85dd82055078ea123b6"
STATES = {
    "host_dispatch_bounded", "test_guest_model",
    "terminal_boundary_only", "missing",
}
IMPLEMENTED_IN_TEST_DOMAIN = STATES - {"missing"}
MODULE_NAME = re.compile(r"^[a-z0-9_-]+\.dll$")
SYMBOL_NAME = re.compile(r"^[A-Za-z_][A-Za-z0-9_@?]*$")
PATH_NAME = re.compile(r"^runtime/[a-zA-Z0-9_./-]+\.(?:c|h)$")


def imported_key(dll, symbol):
    if (not isinstance(dll, str) or not isinstance(symbol, str)
        or not MODULE_NAME.fullmatch(dll.lower())
        or not SYMBOL_NAME.fullmatch(symbol)):
        raise ValueError("Invalid original named import identity")
    return dll.lower(), symbol.lower()


def validate_catalog(catalog, runtime_root=None):
    if (not isinstance(catalog, dict)
        or catalog.get("original_executable_sha256") != SHA
        or catalog.get("schema") != 1
        or not isinstance(catalog.get("families"), list)
        or not isinstance(catalog.get("services"), list)
        or len(catalog["services"]) > 512):
        raise ValueError("Unpinned or malformed service catalog")
    families = {}
    for fam in catalog["families"]:
        if (not isinstance(fam, dict)
            or not isinstance(fam.get("family"), str)
            or not re.fullmatch(r"[a-z][a-z0-9_]{2,63}", fam["family"])
            or fam["family"] in families
            or not isinstance(fam.get("batch_name"), str)
            or not isinstance(fam.get("next_work"), str)
            or not fam["batch_name"].strip() or not fam["next_work"].strip()):
            raise ValueError("Malformed or duplicate service family")
        families[fam["family"]] = fam
    services = {}
    for service in catalog["services"]:
        if not isinstance(service, dict):
            raise ValueError("Malformed original service")
        key = imported_key(service.get("dll"), service.get("symbol"))
        status = service.get("status")
        code = service.get("implementation")
        if (key in services or service.get("family") not in families
            or status not in STATES
            or service.get("production_win64_service") is not False
            or not isinstance(service.get("scope"), str)
            or len(service["scope"]) < 20
            or (status == "missing") != (code is None)
            or (code is not None and (
                not isinstance(code, str)
                or not PATH_NAME.fullmatch(code)
                or ".." in Path(code).parts))):
            raise ValueError("Invalid/duplicate catalog service capability")
        if code and runtime_root is not None:
            root = Path(runtime_root)
            if not (root / code).is_file():
                raise ValueError("Referenced runtime implementation is unavailable: " + code)
        services[key] = service
    return families, services


def analyze(scan, catalog, *, runtime_root=None, strict=True):
    if (not isinstance(scan, dict)
        or scan.get("original_sha256") != SHA
        or scan.get("input_kind") !=
            "SHA-pinned PE import table plus static original x64 instructions"
        or not isinstance(scan.get("import_dependencies"), list)):
        raise ValueError("Import-thunk inventory does not match pinned executable")
    families, services = validate_catalog(catalog, runtime_root=runtime_root)
    observed = {}
    for entry in scan["import_dependencies"]:
        if not isinstance(entry, dict):
            raise ValueError("Malformed observed imported service")
        key = imported_key(entry.get("dll"), entry.get("symbol"))
        refs = entry.get("statically_referenced")
        if key in observed or not isinstance(refs, int) or isinstance(refs, bool) or refs < 1:
            raise ValueError("Duplicate or invalid scanned imported service")
        observed[key] = {"dll": entry["dll"].lower(),
                         "symbol": entry["symbol"],
                         "static_references": refs}
    unmatched = sorted(observed.keys() - services.keys())
    unused = sorted(services.keys() - observed.keys())
    if unmatched and strict:
        raise ValueError("Original imports have no audited runtime disposition: " +
                         ", ".join(f"{a}::{b}" for a,b in unmatched))
    work = {}
    for key, entry in sorted(observed.items()):
        cat = services.get(key)
        if cat is None:
            work[key] = {
                **entry, "family": "unclassified",
                "status": "unclassified", "code_reference": None,
                "scope": "No verified adapter or explicit missing capability assigned",
                "production_win64_service": False,
            }
            continue
        work[key] = {
            **entry, "family": cat["family"], "status": cat["status"],
            "code_reference": cat["implementation"], "scope": cat["scope"],
            "production_win64_service": False,
        }
    grouped = defaultdict(list)
    for row in work.values():
        grouped[row["family"]].append(row)
    family_rows = []
    for family, entries in sorted(grouped.items()):
        count = Counter(row["status"] for row in entries)
        cfg = families.get(family, {})
        missing = [row["symbol"] for row in entries if row["status"] == "missing"]
        family_rows.append({
            "family": family,
            "batch_name": cfg.get("batch_name", "review_unknown_original_services"),
            "next_work": cfg.get("next_work", "Investigate and classify original service"),
            "distinct_imports": len(entries),
            "source_references": sum(row["static_references"] for row in entries),
            "status_counts": dict(sorted(count.items())),
            "missing_symbols": missing,
            "complete_portable_implementation": False,
        })
    family_rows.sort(key=lambda x: (
        -len(x["missing_symbols"]), -x["source_references"], x["family"]
    ))
    summary = Counter(row["status"] for row in work.values())
    return {
        "schema": 1,
        "original_sha256": SHA,
        "source_kind": "bounded original import-thunk inventory and reviewed runtime service contracts",
        "total_named_services_observed": len(work),
        "source_import_references": sum(e["static_references"] for e in work.values()),
        "status_counts": dict(sorted(summary.items())),
        "bounded_host_dispatch_count": summary["host_dispatch_bounded"],
        "test_only_guest_model_count": summary["test_guest_model"],
        "terminal_boundary_count": summary["terminal_boundary_only"],
        "missing_service_count": summary["missing"],
        "unclassified_original_imports": [
            f"{a}::{b}" for a,b in unmatched],
        "reviewed_but_not_observed_here": [
            f"{a}::{b}" for a,b in unused],
        "families": family_rows,
        "services": list(work.values()),
        "next_missing_work_groups": [
            x for x in family_rows if x["missing_symbols"]],
        "fully_implemented_win64_services": 0,
        "real_windows_dlls_executed": False,
        "original_game_engine_booted_on_arm64": False,
        "limitations": [
            "Only statically referenced imports inside bounded root call graph are included.",
            "Status host_dispatch_bounded means a host-input-dependent adapter exists, not a production Win32 service.",
            "Status test_guest_model means bounded fixture behavior, not general Microsoft runtime compatibility.",
            "A recognized terminal boundary is not implementation of an OS process exit.",
            "Implementation provenance is manually reviewed; file existence alone does not prove end-to-end fidelity.",
            "This metadata does not establish original dynamic call frequency, Steam integration, engine boot or first frame.",
        ],
    }


def render(report):
    c = report["status_counts"]
    lines = [
        "# MX Bikes — original startup import service-family readiness", "",
        f"- Named imported services in original bounded scan: **{report['total_named_services_observed']}**",
        f"- Portable callback-driven dispatchers available: **{c.get('host_dispatch_bounded', 0)}** (host input required)",
        f"- Bounded test-domain guest models available: **{c.get('test_guest_model', 0)}**",
        f"- Recognized terminal-only boundaries: **{c.get('terminal_boundary_only', 0)}**",
        f"- Missing/unsupported runtime services: **{c.get('missing', 0)}**",
        f"- Unclassified original services: **{len(report['unclassified_original_imports'])}**",
        "",
        "## Runtime development batches", "",
        "| Family | Imports | Missing | Bounded host dispatch | Test model | Terminal |",
        "| --- | ---: | ---: | ---: | ---: | ---: |",
    ]
    for row in report["families"]:
        s = row["status_counts"]
        lines.append(
            f"| {row['family']} | {row['distinct_imports']} | "
            f"{s.get('missing', 0)} | {s.get('host_dispatch_bounded', 0)} | "
            f"{s.get('test_guest_model', 0)} | {s.get('terminal_boundary_only', 0)} |"
        )
    lines.extend(["", "## Missing-capability batches", ""])
    for row in report["next_missing_work_groups"]:
        lines.append(
            f"- **{row['batch_name']}**: {', '.join(row['missing_symbols'])}. "
            f"{row['next_work']}"
        )
    lines += ["",
        "**No source adapter in this matrix is automatically a production-ready "
        "Win64 service. All identified API calls require actual guest ABI, "
        "host context, and original-x64/ARM64 integration verification before "
        "the port can use them for gameplay.**", ""]
    return "\n".join(lines)


def run(scan_path, catalog_path, output, *, runtime_root=None):
    scan = json.loads(scan_path.read_text())
    catalog = json.loads(catalog_path.read_text())
    report = analyze(scan, catalog, runtime_root=runtime_root)
    output.mkdir(parents=True, exist_ok=True)
    (output / "startup-runtime-service-matrix.json").write_text(
        json.dumps(report, indent=2) + "\n")
    md = render(report)
    (output / "startup-runtime-service-matrix.md").write_text(md)
    print(md)
    return report


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("original_import_thunk_report", type=Path)
    parser.add_argument("reviewed_service_catalog", type=Path)
    parser.add_argument("metadata_output", type=Path)
    parser.add_argument("--runtime-root", type=Path)
    args = parser.parse_args()
    run(args.original_import_thunk_report, args.reviewed_service_catalog,
        args.metadata_output, runtime_root=args.runtime_root)
