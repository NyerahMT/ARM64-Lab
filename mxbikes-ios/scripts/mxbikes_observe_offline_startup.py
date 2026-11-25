#!/usr/bin/env python3
"""Observe normal startup of an owned MX Bikes installation on Windows.

No modification of executable, Steam DLL, launch arguments, authentication,
network or process state. Close Steam yourself before running this test.
The game may legitimately restart Steam; this script only observes it.
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import time
from datetime import datetime, timezone

CLIENT_NAMES = {"steam.exe", "steamwebhelper.exe"}
ROOT = Path(__file__).resolve().parents[2]


def digest(path):
    h = hashlib.sha256()
    with path.open("rb") as f:
        for block in iter(lambda: f.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def parse_tasks(raw):
    result = {}
    for row in csv.reader(io.StringIO(raw)):
        if len(row) < 2:
            continue
        try:
            pid = int(row[1])
        except ValueError:
            continue
        if pid > 0:
            result[pid] = row[0].casefold()
    if not result:
        raise RuntimeError("tasklist did not return a valid process snapshot")
    return result


def snapshot():
    p = subprocess.run(
        ["tasklist.exe", "/FO", "CSV", "/NH"],
        check=True, capture_output=True, text=True, errors="replace", timeout=15
    )
    return parse_tasks(p.stdout)


def observe(tasks, game_name, launcher_pid, elapsed, exit_code):
    return {
        "elapsed_seconds": round(elapsed, 3),
        "steam_client_present": any(n in CLIENT_NAMES for n in tasks.values()),
        "steam_client_pids": sorted(p for p, n in tasks.items() if n in CLIENT_NAMES),
        "game_pids": sorted(p for p, n in tasks.items() if n == game_name),
        "initial_process_pid": launcher_pid,
        "initial_process_exit_code": exit_code,
    }


def summarize(samples):
    if not samples:
        raise ValueError("no observations")
    steam_seen = any(s["steam_client_present"] for s in samples)
    game_seen = any(s["game_pids"] for s in samples)
    last = samples[-1]
    if steam_seen:
        result = "steam_client_observed_during_launch"
    elif last["game_pids"]:
        result = "game_process_alive_without_observed_steam_client"
    elif last["initial_process_exit_code"] is not None:
        result = "initial_process_exited_without_observed_steam_client"
    else:
        result = "inconclusive"
    return {
        "classification": result,
        "steam_seen": steam_seen,
        "game_process_seen": game_seen,
        "initial_exit_code": last["initial_process_exit_code"],
        "actual_engine_initialized": None,
        "actual_menu_rendered": None,
        "steam_api_result_observed": False,
        "note": "Process observations only; transient processes between samples may be missed. "
                "Alive does not establish successful startup or licensing.",
    }


def run(exe, out, duration, interval):
    if os.name != "nt":
        raise RuntimeError("this experiment requires Windows")
    exe = exe.resolve(strict=True)
    out = out.resolve()
    if not exe.is_file() or exe.suffix.casefold() != ".exe":
        raise ValueError("provide the original installed executable")
    if out.suffix.casefold() != ".json" or out.exists():
        raise ValueError("output must be a new JSON file")
    if out == ROOT or ROOT in out.parents or exe.parent in out.parents:
        raise ValueError("save report outside repository and installation")
    if not out.parent.is_dir():
        raise ValueError("output parent must exist")
    game_name = exe.name.casefold()
    baseline = snapshot()
    if any(n in CLIENT_NAMES for n in baseline.values()):
        raise RuntimeError("Steam client already present; close it normally, then retry")
    if game_name in baseline.values():
        raise RuntimeError("game already running; exit it normally, then retry")
    dll = exe.parent / "steam_api64.dll"
    metadata = {
        "exe_sha256": digest(exe),
        "exe_bytes": exe.stat().st_size,
        "steam_dll_sha256": digest(dll) if dll.is_file() else None,
        "utc_started": datetime.now(timezone.utc).isoformat(),
        "requested_observation_seconds": duration,
        "sample_interval_seconds": interval,
        "steam_initially_observed": False,
        "game_modified": False,
        "normal_executable_launch": True,
    }
    # Recheck immediately before starting; hashing can take time.
    baseline = snapshot()
    if any(n in CLIENT_NAMES or n == game_name for n in baseline.values()):
        raise RuntimeError("baseline changed while hashing; retry")
    p = subprocess.Popen([str(exe)], cwd=str(exe.parent))
    started = time.monotonic()
    samples = []
    error = None
    try:
        while True:
            tasks = snapshot()
            elapsed = time.monotonic() - started
            samples.append(observe(tasks, game_name, p.pid, elapsed, p.poll()))
            if elapsed >= duration:
                break
            time.sleep(min(interval, duration - elapsed))
    except (OSError, subprocess.SubprocessError, RuntimeError, KeyboardInterrupt) as exc:
        error = type(exc).__name__
    summary = summarize(samples) if samples else {"classification": "inconclusive"}
    if error:
        summary["partial_classification"] = summary["classification"]
        summary["classification"] = "observation_incomplete"
    report = {"metadata": metadata, "samples": samples, "summary": summary,
              "observation_error": error, "processes_terminated_by_test": False}
    with out.open("x", encoding="utf-8") as stream:
        json.dump(report, stream, indent=2)
        stream.write("\n")
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--exe", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--seconds", type=int, default=45, choices=range(5, 121),
                        metavar="5..120")
    parser.add_argument("--interval", type=float, default=0.5)
    args = parser.parse_args()
    if not 0.25 <= args.interval <= 5:
        parser.error("--interval must be between 0.25 and 5 seconds")
    try:
        report = run(args.exe, args.out, args.seconds, args.interval)
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as exc:
        parser.exit(2, str(exc) + "\n")
    print(json.dumps(report["summary"], indent=2))
    return 1 if report["observation_error"] else 0


if __name__ == "__main__":
    sys.exit(main())
