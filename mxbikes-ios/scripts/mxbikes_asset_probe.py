#!/usr/bin/env python3
"""Check privately uploaded original game ZIPs for one requested startup DLL.

Emits only existence, archive path, and compressed/uncompressed sizes.
Does not extract original game contents or publish executable bytes.
"""
import json
from pathlib import Path, PurePosixPath
import sys
import zipfile

TARGET = "steam_api64.dll"


def find_asset(archives):
    hits = []
    for path in archives:
        if not path.is_file():
            raise FileNotFoundError(str(path))
        with zipfile.ZipFile(path) as zf:
            for info in zf.infolist():
                if info.is_dir():
                    continue
                candidate = PurePosixPath(info.filename.replace("\\", "/"))
                if candidate.name.lower() == TARGET:
                    hits.append({
                        "archive": path.name,
                        "member_path": str(candidate),
                        "uncompressed_size_bytes": info.file_size,
                        "compressed_size_bytes": info.compress_size,
                    })
    return hits


def main():
    if len(sys.argv) < 4:
        raise SystemExit("usage: asset_probe.py REPORT_DIR Game.zip Steam.zip")
    out = Path(sys.argv[1])
    out.mkdir(parents=True, exist_ok=True)
    hits = find_asset([Path(x) for x in sys.argv[2:]])
    report = {
        "requested_startup_filename": TARGET,
        "exact_basename_matches": len(hits),
        "matches": hits,
        "original_file_extracted": False,
        "filesystem_adapter_implemented": False,
    }
    (out/"startup-file-availability.json").write_text(json.dumps(report,indent=2)+"\n")
    lines = ["# MX Bikes startup file availability", "",
             "- Original CRT fopen target: steam_api64.dll",
             f"- Exact basename matches in private ZIPs: {len(hits)}", ""]
    for hit in hits:
        lines.append(f"- {hit['archive']}:{hit['member_path']} ({hit['uncompressed_size_bytes']} bytes)")
    lines += ["", "This is private ZIP indexing only, not a successful original-game file open.", ""]
    summary = "\n".join(lines)
    (out/"startup-file-availability.md").write_text(summary)
    print(summary)


if __name__ == "__main__":
    main()
