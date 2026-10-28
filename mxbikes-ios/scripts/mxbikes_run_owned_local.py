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
    validate_owned_pair(exe, dll)
    return exe, dll


def public_safe_output(path: Path) -> Path:
    output = path.expanduser().resolve()
    root = PUBLIC_REPO_ROOT.resolve()
    if output == root or root in output.parents:
        raise InputRejected("report_output_must_be_outside_public_repository")
    return output


def make_report(exe: Path, dll: Path, output: Path, mode: str) -> dict:
    manifest = validate_owned_pair(exe, dll)
    output.mkdir(parents=True, exist_ok=True)
    (output / "owned-steam-file-manifest.json").write_text(
        json.dumps(manifest, indent=2) + "\n", encoding="utf-8"
    )

    # Critical after migration: the public ARM64-Lab tools package is at
    # ROOT.parent/tools, NOT the old ROOT/arm64-lab/tools checkout.
    sys.path.insert(0, str(PUBLIC_REPO_ROOT))
    sys.path.insert(0, str(SCRIPTS))
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
    parser.add_argument("--validate-only", action="store_true",
                        help="Verify owned inputs without running any original instructions")
    args = parser.parse_args(argv)

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
            report = make_report(exe, dll, out, mode)
            print(json.dumps(report, indent=2))
            return 0
    except (InputRejected, zipfile.BadZipFile, zipfile.LargeZipFile) as exc:
        parser.exit(2, "Input rejected: " + str(exc) + "\n")


if __name__ == "__main__":
    raise SystemExit(run_cli())
