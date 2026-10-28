#!/usr/bin/env python3
"""Metadata-only MX Bikes inventory: no original game content in reports."""
import collections
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import shutil
import stat
import sys
import zipfile

import pefile

download_dir = Path(sys.argv[1]).resolve()
report_dir = Path(sys.argv[2]).resolve()
report_dir.mkdir(parents=True, exist_ok=True)
extract_root = Path(os.environ.get("RUNNER_TEMP", "/tmp")) / "mxbikes-pe-temp"
extract_root.mkdir(parents=True, exist_ok=True)
release = json.loads((download_dir / "release.json").read_text())
asset_by_name = {a["name"]: a for a in release.get("assets", [])}
pe_candidates = []
archive_reports = []
all_ext = collections.Counter()

def sha256_file(path):
    h = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(4 * 1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()

for filename in ("Game.zip", "Steam.zip", "tracks.pkz"):
    path = download_dir / filename
    remote = asset_by_name.get(filename, {})
    row = {"name": filename, "uploaded_size": remote.get("size"),
           "release_sha256": remote.get("digest"), "downloaded": path.is_file()}
    if not path.is_file():
        archive_reports.append(row)
        continue
    actual = sha256_file(path)
    row["actual_sha256"] = actual
    expected = (remote.get("digest") or "").removeprefix("sha256:")
    if expected and actual != expected:
        raise RuntimeError(f"Hash mismatch for {filename}; refusing to inspect")
    if not zipfile.is_zipfile(path):
        row["format"] = "not ZIP-compatible"
        archive_reports.append(row)
        continue
    archive_total = 0
    archive_files = 0
    biggest = []
    with zipfile.ZipFile(path) as zf:
        for member in zf.infolist():
            if member.is_dir():
                continue
            archive_files += 1
            archive_total += member.file_size
            if archive_files > 200000 or archive_total > 30 * 1024**3:
                raise RuntimeError(f"Unsafe expanded archive size or file count: {filename}")
            rel = PurePosixPath(member.filename.replace("\\", "/"))
            if rel.is_absolute() or not rel.parts or ".." in rel.parts or stat.S_ISLNK(member.external_attr >> 16):
                continue
            ext = rel.suffix.lower() or "(none)"
            all_ext[ext] += 1
            biggest.append((member.file_size, str(rel)))
            if filename == "tracks.pkz" or ext not in (".exe", ".dll", ".pyd"):
                continue
            if member.file_size > 750 * 1024**2:
                continue
            local = extract_root / filename / Path(*rel.parts)
            local.parent.mkdir(parents=True, exist_ok=True)
            with zf.open(member) as source, local.open("wb") as target:
                shutil.copyfileobj(source, target, length=1024 * 1024)
            pe_candidates.append((filename, str(rel), local))
    row.update(format="ZIP", file_count=archive_files, expanded_bytes=archive_total,
               largest_files=[{"name": n, "bytes": s} for s, n in sorted(biggest, reverse=True)[:15]])
    archive_reports.append(row)

pe_details = []
imports_all = collections.Counter()
machine_counts = collections.Counter()
graphics_clues = set()
graphics_words = ("opengl", "d3d", "directx", "vulkan", "glfw", "sdl", "fmod", "openal", "physx", "xaudio", "xinput")
for archive, rel, path in pe_candidates:
    record = {"archive": archive, "path": rel, "bytes": path.stat().st_size}
    try:
        pe = pefile.PE(str(path), fast_load=True)
        pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"]])
        machine = pe.FILE_HEADER.Machine
        record["machine"] = hex(machine)
        record["architecture"] = {
            0x14c: "x86 (32-bit)", 0x8664: "x86-64 (64-bit)", 0xaa64: "ARM64",
        }.get(machine, f"other ({hex(machine)})")
        record["subsystem"] = int(pe.OPTIONAL_HEADER.Subsystem)
        record["image_base"] = hex(pe.OPTIONAL_HEADER.ImageBase)
        record["entry_rva"] = hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint)
        record["sections"] = len(pe.sections)
        imports = sorted({entry.dll.decode("utf-8", "replace") for entry in getattr(pe, "DIRECTORY_ENTRY_IMPORT", [])})
        record["imported_libraries"] = imports
        imports_all.update(i.lower() for i in imports)
        machine_counts[record["architecture"]] += 1
        for item in imports + [Path(rel).name]:
            if any(word in item.lower() for word in graphics_words):
                graphics_clues.add(item)
        pe.close()
    except Exception as exc:
        record["error"] = f"{type(exc).__name__}: {str(exc)[:200]}"
    pe_details.append(record)

report = {
    "release": release.get("tag_name"),
    "repository": os.environ.get("GITHUB_REPOSITORY"),
    "assets": archive_reports,
    "extension_counts": all_ext.most_common(45),
    "pe_architectures": dict(machine_counts),
    "pe_binaries": pe_details,
    "imported_libraries_by_frequency": imports_all.most_common(),
    "render_audio_input_clues": sorted(graphics_clues),
    "potential_startup_binaries": [p for p in pe_details if p["path"].lower().endswith(".exe")],
    "limits": [
        "The tracks.pkz archive is indexed only if requested; never extracted.",
        "Only EXE/DLL/PYD binaries are temporarily extracted; other files are indexed without extraction.",
        "PE imports are static indicators, not proof that the executable can run on ARM64 or iOS.",
        "No game binaries, assets, or translated code are uploaded as report artifacts.",
    ],
}
(report_dir / "inventory.json").write_text(json.dumps(report, indent=2))
lines = ["# MX Bikes — initial executable and asset inventory", "",
         f"Release: {release.get('tag_name')} · Repository: {os.environ.get('GITHUB_REPOSITORY', 'unknown')}", "",
         "## Archives", "",
         "| Asset | Downloaded | Entries | Expanded size (GiB) | Hash |",
         "|---|---|---:|---:|---|"]
for item in archive_reports:
    size = item.get("expanded_bytes")
    hash_state = "verified" if item.get("actual_sha256") else "not downloaded"
    if size is not None:
        lines.append(f"| {item['name']} | yes | {item.get('file_count', '—')} | {size / 1024**3:.2f} | {hash_state} |")
    else:
        lines.append(f"| {item['name']} | {'yes' if item['downloaded'] else 'no'} | — | — | {hash_state} |")
lines += ["", "## PE architectures", ""]
lines += [f"- {k}: {v}" for k, v in machine_counts.items()] or ["- No readable PE binaries detected."]
lines += ["", "## Executables", ""]
for binary in report["potential_startup_binaries"][:60]:
    lines.append(f"- {binary['archive']}:{binary['path']} — {binary.get('architecture', binary.get('error', 'unknown'))}; entry RVA {binary.get('entry_rva', 'unknown')}")
lines += ["", "## Likely rendering, audio and input libraries", ""]
lines += [f"- {x}" for x in sorted(graphics_clues)] or ["- None identifiable from static import names."]
lines += ["", "## Most common imported DLLs", ""]
lines += [f"- {name}: {count} binaries" for name, count in imports_all.most_common(30)] or ["- None identified."]
lines += ["", "## Top file extensions", ""]
lines += [f"- {extension}: {count}" for extension, count in all_ext.most_common(20)]
lines += ["", "## Interpretation", "",
          "This report identifies actual executable architecture and dependency clues. It does not demonstrate recompilation, startup, menus, or gameplay.",
          "Original archives remain in the private release. Only metadata reports are uploaded as Actions artifacts.", ""]
(report_dir / "inventory.md").write_text("\n".join(lines))
print("\n".join(lines))
