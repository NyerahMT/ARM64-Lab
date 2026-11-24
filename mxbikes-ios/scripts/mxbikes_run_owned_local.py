#!/usr/bin/env python3
"""Run *actual* owned MX Bikes x64 startup locally without private GitHub CI.

Input is a personally owned Game.zip (contains mxbikes.exe and steam_api64.dll)
or exact paths to the two installed files. No game bytes are committed, uploaded
or recorded in reports. Only the SHA-pinned original x64 code can be executed.
Steamworks and unsupported Windows APIs still stop fail-closed. Never asserts
that a game frame was rendered without original-game provenance.
"""
from __future__ import annotations

import argparse
import calendar
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import shutil
import sys
import tempfile
import zipfile

ROOT = Path(__file__).resolve().parents[1]
PUBLIC_REPO_ROOT = ROOT.parent
SCRIPTS = ROOT / "scripts"
PINNED_EXE_SHA256 = "4ae7de3854b4d0a18271679fb57a1f2fdf0b21804417b85dd82055078ea123b6"
MAX_EXE = 750 * 1024 * 1024
MAX_DLL = 64 * 1024 * 1024
MAX_CORE_INI = 64 * 1024
COPY_BLOCK = 1024 * 1024


class InputRejected(ValueError):
    pass


def file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while True:
            block = stream.read(COPY_BLOCK)
            if not block:
                break
            digest.update(block)
    return digest.hexdigest()


def validate_owned_pair(exe: Path, dll: Path) -> dict:
    if not exe.is_file() or not dll.is_file():
        raise InputRejected("both_original_files_required")
    size, dll_size = exe.stat().st_size, dll.stat().st_size
    if not (0 < size <= MAX_EXE and 0 < dll_size <= MAX_DLL):
        raise InputRejected("game_or_dll_outside_safe_size_budget")
    if exe.resolve() == dll.resolve():
        raise InputRejected("game_executable_and_steam_dll_cannot_match")
    if file_sha256(exe) != PINNED_EXE_SHA256:
        raise InputRejected("original_executable_sha256_mismatch")
    return {
        "steam_api64_dll_present": True,
        "matching_owned_dll_count": 1,
        "owned_dll_size_bytes": dll_size,
        "original_sha256_verified": True,
        "source": "local user-owned original files; no source payload retained in output",
    }


def archive_member(zf: zipfile.ZipFile, name: str, limit: int) -> zipfile.ZipInfo:
    hits = []
    for info in zf.infolist():
        if info.is_dir():
            continue
        parts = PurePosixPath(info.filename.replace("\\", "/"))
        if parts.name.lower() != name.lower():
            continue
        if (parts.is_absolute() or ".." in parts.parts or
                info.flag_bits & 0x1 or info.file_size <= 0 or info.file_size > limit):
            raise InputRejected("unsafe_or_oversized_original_archive_member")
        # This path is never joined to the output path: archive names are
        # identifiers ONLY, and the extracted destination is a fixed basename.
        hits.append(info)
    if len(hits) != 1:
        raise InputRejected("expected_exactly_one_original_" + name.lower())
    return hits[0]


def optional_owned_core_ini(zf: zipfile.ZipFile) -> zipfile.ZipInfo | None:
    """Only the exact root core.ini, never an arbitrary user/host path.

    A missing file is allowed (original Windows fopen would return NULL).
    A duplicate, encrypted, symlink or oversized file is not. The contents
    remain private and are only extracted to the temporary owned-game dir.
    """
    matches=[x for x in zf.infolist() if not x.is_dir()
             and x.filename.replace(chr(92),"/").lower()=="core.ini"]
    if len(matches)>1:
        raise InputRejected("duplicate_original_core_ini")
    if not matches:
        return None
    member=matches[0]
    mode=(member.external_attr>>16)&0o170000
    if (member.flag_bits&1 or mode==0o120000 or
        member.file_size<=0 or member.file_size>MAX_CORE_INI):
        raise InputRejected("unsafe_or_oversized_original_core_ini")
    return member


def bounded_extract(zf: zipfile.ZipFile, member: zipfile.ZipInfo, destination: Path) -> None:
    total = 0
    with zf.open(member, "r") as src, destination.open("xb") as output:
        while total < member.file_size:
            chunk = src.read(min(COPY_BLOCK, member.file_size - total))
            if not chunk:
                raise InputRejected("truncated_owned_zip_member")
            total += len(chunk)
            output.write(chunk)
        if src.read(1):
            raise InputRejected("archive_member_exceeded_declared_size")
    if total != member.file_size:
        raise InputRejected("archive_member_size_changed")


def extract_owned_archive(archive: Path, destination: Path) -> tuple[Path, Path]:
    if not archive.is_file():
        raise InputRejected("owned_game_archive_not_found")
    if archive.stat().st_size > 4 * 1024 * 1024 * 1024:
        raise InputRejected("owned_game_archive_too_large")
    with zipfile.ZipFile(archive, "r") as zf:
        exe_info = archive_member(zf, "mxbikes.exe", MAX_EXE)
        dll_info = archive_member(zf, "steam_api64.dll", MAX_DLL)
        exe = destination / "mxbikes.exe"
        dll = destination / "steam_api64.dll"
        bounded_extract(zf, exe_info, exe)
        bounded_extract(zf, dll_info, dll)
        core_info=optional_owned_core_ini(zf)
        if core_info is not None:
            core_path=destination/"core.ini"
            bounded_extract(zf,core_info,core_path)
            # ZIP stores naive local-wall-clock timestamps, not UTC offsets.
            # For deterministic research, preserve the archived wall-clock
            # fields as a UTC-assumed mtime on this PRIVATE temporary copy.
            # This must not be represented as the true Windows NTFS time.
            try:
                zip_time=calendar.timegm((*core_info.date_time,0,0,0))
                if zip_time<0:
                    raise ValueError("ZIP time predates Unix epoch")
                os.utime(core_path,ns=(zip_time*1_000_000_000,
                                        zip_time*1_000_000_000))
            except (OverflowError,ValueError,OSError) as exc:
                raise InputRejected("invalid_original_core_ini_archive_time") from exc
    validate_owned_pair(exe, dll)
    return exe, dll


def public_safe_output(path: Path) -> Path:
    output = path.expanduser().resolve()
    root = PUBLIC_REPO_ROOT.resolve()
    if output == root or root in output.parents:
        raise InputRejected("report_output_must_be_outside_public_repository")
    return output


def make_report(exe: Path, dll: Path, output: Path, mode: str, *,
                steam_failure_probe: bool = False,
                steam_init_success_probe: bool = False,
                steam_subscription_research_probe: bool = False) -> dict:
    manifest = validate_owned_pair(exe, dll)
    core_ini=exe.parent/"core.ini"
    if core_ini.is_symlink():
        raise InputRejected("owned_core_ini_symlink_rejected")
    core_present=core_ini.is_file()
    if core_present and not 0<core_ini.stat().st_size<=MAX_CORE_INI:
        raise InputRejected("owned_core_ini_size_budget")
    manifest["owned_core_ini_present"]=core_present
    manifest["owned_core_ini_size_bytes"]=core_ini.stat().st_size if core_present else 0
    # This is provenance metadata only. The 100ns value is based on a ZIP
    # local datetime *treated as UTC* or on an installed file's native mtime.
    # It is NOT a claim of exact original Windows creation/access timestamps.
    win_filetime_offset=116444736000000000
    filetime=(core_ini.stat().st_mtime_ns//100+win_filetime_offset
              if core_present else None)
    if filetime is not None and not 0<=filetime<2**64:
        raise InputRejected("owned_core_ini_filetime_outside_win64_range")
    manifest["owned_core_ini_last_write_filetime_100ns"]=filetime
    manifest["owned_core_ini_zip_wall_clock_assumed_utc"]=mode=="owned_zip"
    output.mkdir(parents=True, exist_ok=True)
    (output / "owned-steam-file-manifest.json").write_text(
        json.dumps(manifest, indent=2) + "\n", encoding="utf-8"
    )

    # Critical after migration: the public ARM64-Lab tools package is at
    # ROOT.parent/tools, NOT the old ROOT/arm64-lab/tools checkout.
    sys.path.insert(0, str(PUBLIC_REPO_ROOT))
    sys.path.insert(0, str(SCRIPTS))
    if steam_failure_probe or steam_init_success_probe or steam_subscription_research_probe:
        from mxbikes_startup_fast_blocks import execute
        # Probe the genuine guest game failure path; never synthesize Steam
        # authentication or pass through unsupported interface creation.
        guest = execute(exe, dll, output,
            steam_failure_probe=steam_failure_probe,
            steam_init_success_probe=steam_init_success_probe,
            steam_subscription_research_probe=steam_subscription_research_probe)
        result = {
            "mode": mode,
            "steam_failure_probe": steam_failure_probe,
            "steam_init_success_probe": steam_init_success_probe,
            "steam_subscription_research_probe": steam_subscription_research_probe,
            "real_original_x64_executed": guest["original_guest_basic_block_executions"]>0,
            "explicit_failed_steam_returns": guest["steam_failure_probe"]["original_guest_steam_failure_return_count"],
            "modeled_steam_returns": guest["steam_failure_probe"]["original_guest_steam_modeled_return_count"],
            "modeled_init_success_is_not_real_authentication": steam_init_success_probe or steam_subscription_research_probe,
            "synthetic_ownership_method_reached": bool(guest.get("synthetic_steam_subscription_research") and guest["synthetic_steam_subscription_research"]["original_subscription_vtable_call_reached"]),
            "real_original_blocks_after_first_failed_return": len(guest["original_post_failure_block_rvas"]),
            "stop": guest["stop"]["status"],
            "blocked_import": guest["stop"].get("import"),
            "actual_original_opengl_calls": guest["actual_original_gl_import_events"],
            "steam_client_initialized": False,
            "license_or_entitlement_granted": False,
            "native_ios_game_running": False,
        }
        report_name = ("local-steam-init-success-probe.json" if steam_init_success_probe else
                       "local-steam-subscription-research.json" if steam_subscription_research_probe else
                       "local-steam-failure-probe.json")
        (output / report_name).write_text(
            json.dumps(result, indent=2) + "\n", encoding="utf-8"
        )
        return result
    from mxbikes_original_game_graphics_handoff import run
    trace = run(exe, dll, output)
    result = {
        "mode": mode,
        "verified_original_executable": trace["original_game_code_executed"],
        "original_guest_blocks": trace["original_guest_blocks"],
        "original_guest_import_calls": trace["original_guest_import_calls"],
        "original_opengl_import_events": trace["original_opengl_import_events"],
        "original_game_vertices": trace["actual_original_game_vertex_count"],
        "stop": trace["runtime_stop"]["status"],
        "blocked_import": trace["runtime_stop"].get("import"),
        "original_game_frame_rendered": False,
        "original_steam_client_initialized": False,
        "test_was_run_against_real_game": True,
    }
    (output / "local-original-game-gate.json").write_text(
        json.dumps(result, indent=2) + "\n", encoding="utf-8"
    )
    return result


def run_cli(argv=None) -> int:
    parser = argparse.ArgumentParser(
        description="Execute owned, SHA-verified original MX Bikes startup on Linux/WSL "
                    "without private Actions, Steam emulation or game-asset publication"
    )
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--game-zip", type=Path, help="Owned Game.zip containing original EXE and DLL")
    source.add_argument("--game-exe", type=Path, help="Path to the exact owned mxbikes.exe")
    parser.add_argument("--steam-dll", type=Path, help="Original steam_api64.dll (with --game-exe)")
    parser.add_argument("--out", type=Path, required=True,
                        help="Metadata-only directory outside the public repository")
    parser.add_argument("--map-graphics-paths", action="store_true",
                        help="Also statically index original direct-call paths toward Steam/graphics; no guessed execution")
    parser.add_argument("--static-graphics-only", action="store_true",
                        help="Run genuine original-PE static graph without executing the game")
    scenarios = parser.add_mutually_exclusive_group()
    scenarios.add_argument("--steam-failure-probe", action="store_true",
                        help="Opt-in diagnostic: execute original game with documented Steam false/failure returns")
    scenarios.add_argument("--steam-init-success-probe", action="store_true",
                        help="Opt-in counterfactual x64 branch probe: model Steam Init true WITHOUT real authentication or interfaces")
    scenarios.add_argument("--steam-subscription-research-probe", action="store_true",
                        help="Research-only: model one SteamApps virtual method true to map original post-subscription code; NOT entitlement")
    parser.add_argument("--validate-only", action="store_true",
                        help="Verify owned inputs without running any original instructions")
    args = parser.parse_args(argv)
    if (args.steam_failure_probe or args.steam_init_success_probe or args.steam_subscription_research_probe) and (args.validate_only or args.static_graphics_only):
        parser.error("Steam branch probes require execution, not --validate-only/--static-graphics-only")

    if bool(args.game_exe) != bool(args.steam_dll):
        parser.error("--game-exe and --steam-dll must be provided together")
    try:
        out = public_safe_output(args.out)
        with tempfile.TemporaryDirectory(prefix="mxb-owned-private-") as folder:
            private_temp = Path(folder)
            if os.name != "nt":
                private_temp.chmod(0o700)
            if args.game_zip:
                exe, dll = extract_owned_archive(args.game_zip.expanduser(), private_temp)
                mode = "owned_zip"
            else:
                exe, dll = args.game_exe.expanduser(), args.steam_dll.expanduser()
                mode = "owned_installed_files"
            manifest = validate_owned_pair(exe, dll)
            if args.validate_only:
                print(json.dumps({"validated": True, "original_sha256_verified": True,
                                  "dll_bytes": manifest["owned_dll_size_bytes"],
                                  "original_code_executed": False}, indent=2))
                return 0
            if args.static_graphics_only or args.map_graphics_paths:
                from mxbikes_real_frame_frontier import audit_owned_exe
                # Local metadata derived from the owned original PE only. Static
                # paths are not execution of Steamworks or the game engine.
                graph = audit_owned_exe(exe, out)
                graph_overview = {
                    "static_graph_function_nodes": graph["static_main_direct_call_graph_nodes"],
                    "candidate_static_graphics_imports": graph[
                        "candidate_imports_on_direct_call_graph"]["graphics"][
                            "candidate_import_calls_from_main_graph"],
                    "static_code_executed": False,
                }
                if args.static_graphics_only:
                    print(json.dumps(graph_overview, indent=2))
                    return 0
            report = make_report(exe, dll, out, mode,
                                 steam_failure_probe=args.steam_failure_probe,
                                 steam_init_success_probe=args.steam_init_success_probe,
                                 steam_subscription_research_probe=args.steam_subscription_research_probe)
            if args.map_graphics_paths:
                report["static_graph"] = graph_overview
            print(json.dumps(report, indent=2))
            return 0
    except (InputRejected, zipfile.BadZipFile, zipfile.LargeZipFile) as exc:
        parser.exit(2, "Input rejected: " + str(exc) + "\n")


if __name__ == "__main__":
    raise SystemExit(run_cli())
