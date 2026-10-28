#!/usr/bin/env python3
"""Batch real-game CRT translation diagnostics to surface sibling failures.

Each original-game differential remains independently fail-closed. The batch
runs all cases and reports EVERY failing gate before CI fails, avoiding a
one-symptom-per-Actions-run feedback loop. Upload metadata only.
"""
from pathlib import Path
import json
import os
import subprocess
import sys
import time

# All paths are fixed, local repository code: no shell or user supplied args.
CHECKS=[
    ("first-crt-full-39","scripts/mxbikes_crt_cfg_differential.py",
      "crt-cfg-arm64-differential.md","original initializer"),
    ("second-crt-five-prefix","scripts/mxbikes_next_crt_prefix_differential.py",
      "next-crt-prefix-arm64.md","stack and first import boundary"),
    ("second-crt-six-gs-lock","scripts/mxbikes_next_crt_gs_lock_differential.py",
      "next-crt-gs-lock-arm64.md","GS, TEB, bounded compare-exchange"),
    ("second-crt-twelve-joined","scripts/mxbikes_next_crt_joined_differential.py",
      "next-crt-joined-arm64.md","first joined Win64 import"),
    ("second-crt-ten-retry","scripts/mxbikes_crt_retry_differential.py",
      "next-crt-retry-arm64.md","all three lock/retry paths"),
    ("second-crt-twenty-continuous","scripts/mxbikes_crt_joined_retry_differential.py",
      "next-crt-joined-retry-arm64.md","both imported calls and retry control flow"),
    ("second-crt-init-state-triad","scripts/mxbikes_crt_init_state_differential.py",
      "next-crt-init-state-arm64.md","three-way CRT state globals and direct-call boundaries"),
    ("second-crt-thirtyeight-continuous","scripts/mxbikes_crt_joined_state_differential.py",
      "next-crt-joined-state-arm64.md","20-instruction CRT prefix joined into all three initialization states"),
    ("second-crt-release-triad","scripts/mxbikes_crt_common_release_differential.py",
      "next-crt-common-release-arm64.md","CRT direct-call stop, recursive ownership and exclusive XCHG unlock"),
    ("second-crt-fortynine-continuous","scripts/mxbikes_crt_joined_release_differential.py",
      "next-crt-joined-release-arm64.md","joined initial CRT, state choices, and exclusive guest lock release"),
    ("crt-msvcr90-original-call-thunks","scripts/mxbikes_crt_import_thunk_differential.py",
      "crt-msvcr90-import-thunk-arm64.md","two original CRT imported calls, native callback and return ABI"),
    ("crt-msvcr90-after-call-branches","scripts/mxbikes_crt_post_import_differential.py",
      "crt-post-msvcr90-arm64.md","original call+RET followed by status/error, state transition, lock release"),
    ("second-crt-joined-msvcr90","scripts/mxbikes_crt_joined_msvcr90_differential.py",
      "next-crt-joined-release-arm64.md","entire prior CRT startup prefix through synthetic initializer call returns"),
    ("crt-original-exception-callback","scripts/mxbikes_crt_exception_callback_differential.py",
      "crt-exception-callback-arm64.md","six original exception-filter callback instructions and shared helper inventory"),
    ("crt-original-shared-helper","scripts/mxbikes_crt_shared_helper_differential.py",
      "crt-shared-helper-arm64.md","eight original shared-helper instructions and synthetic child-call ABI"),
    ("crt-original-dependency-clusters","scripts/mxbikes_crt_cluster_inventory.py",
      "crt-dependency-clusters.md","bound whole CRT child/callback dependency families and report blockers"),
    ("game-original-strrchr-import-arm64","scripts/mxbikes_crt_strrchr_differential.py",
      "crt-original-strrchr-guest-native.md","actual game filename helper strrchr CALL/IAT thunk with bounded CRT guest model"),
    ("crt-original-amsg-exit-terminal","scripts/mxbikes_crt_amsg_exit_boundary.py",
      "crt-original-amsg-exit-boundary.md","original fatal CRT handoff to imported _amsg_exit never resumes"),
    ("crt-original-child-x64-reference","scripts/mxbikes_crt_child_path_reference.py",
      "crt-child-x64-path-reference.md","complete x64 child reference with deterministic CRT service boundaries"),
    ("crt-original-child-aot-arm64","scripts/mxbikes_crt_child_aot_differential.py",
      "crt-child-aot-arm64.md","complete 39-instruction child via generic AOT x64→C→AArch64 using 16 real original x64 fixtures"),
    ("crt-joined-wrapper-child-aot","scripts/mxbikes_crt_joined_wrapper_child_aot.py",
      "crt-joined-wrapper-child-arm64.md","original 8-instruction wrapper CALL to real translated 39-instruction child with full nested Win64 effects"),
    ("crt-joined-initterm-tail-callback","scripts/mxbikes_crt_tail_callback_joined_aot.py",
      "crt-joined-tail-callback-arm64.md","authentic _initterm table slot 3 callback LEA/JMP through 8-instruction wrapper and generated 39-instruction child"),
    ("crt-real-initializer-tables","scripts/mxbikes_crt_initializer_table_walk.py",
      "crt-real-tables-dispatch.md","both authentic original _initterm tables fail closed on missing callbacks; verified slot-3 callback runs through native wrapper/child"),
    ("crt-original-argument-body-aot","scripts/mxbikes_crt_argsetup_body_differential.py",
      "crt-original-argsetup-body-arm64.md","authentic 19-instruction _initterm argument callback x64 vs host C vs ARM64 with injected Win64 callees"),
    ("crt-original-appsetup-body-aot","scripts/mxbikes_crt_appsetup_body_differential.py",
      "crt-original-appsetup-body-arm64.md","authentic 52-instruction _initterm_e app/PE startup x64 vs host C vs executed ARM64 with injected CRT dependencies"),
    ("crt-original-second-tail-body-aot","scripts/mxbikes_crt_second_tail_body_differential.py",
      "crt-original-second-tail-body-arm64.md","authentic six-instruction _initterm slot-2 CALL/tail JMP original x64 vs executed ARM64"),
    ("crt-joined-e-init-table","scripts/mxbikes_crt_joined_e_initializer.py",
      "crt-joined-einit-native.md","both authentic _initterm_e callbacks executed in original pointer-table order in same guest context with x64 boundary references"),
    ("crt-joined-init-table","scripts/mxbikes_crt_joined_init_table.py",
      "crt-joined-init-native.md","all three _initterm callback bodies in original native table order with shared guest globals and original-x64 boundary references"),
]

def run(exe,report):
    if not exe.is_file():
        raise RuntimeError("Original executable is absent: no tests run")
    report.mkdir(parents=True,exist_ok=True)
    output=[]
    for name,script,summary,root_cause in CHECKS:
        if not Path(script).is_file():
            raise RuntimeError("Required test script missing: "+script)
        started=time.monotonic()
        proc=subprocess.run([sys.executable,script,str(exe),str(report)],
                            capture_output=True,text=True)
        seconds=round(time.monotonic()-started,2)
        ok=proc.returncode==0 and (report/summary).is_file()
        output.append({"test":name,"group":root_cause,"pass":ok,
                       "exit":proc.returncode,"elapsed_seconds":seconds})
        print(f"\n## {name}: {'PASS' if ok else 'FAIL'} ({seconds}s)",flush=True)
        if ok:
            text=(report/summary).read_text()
            print(text[-1800:],flush=True)
            if name=="crt-original-exception-callback":
                for line in proc.stdout.splitlines():
                    if line.startswith(" PRIVATE HELPER FORM "):
                        print(line,flush=True)  # private CI logs only
            if name=="crt-original-dependency-clusters":
                for line in proc.stdout.splitlines():
                    if line.startswith(("PRIVATE CLUSTER ROOT ", " PRIVATE CLUSTER FORM ")):
                        print(line,flush=True)  # private CI logs only
        else:
            # Tracebacks are private-runner logs; no original binary or
            # game-derived source/artifacts are uploaded by this script.
            print((proc.stderr or proc.stdout)[-5500:],flush=True)
    failures=[x for x in output if not x["pass"]]
    markdown=[
        "# MX Bikes CRT grouped regression",
        "",
        f"- Passed: **{len(output)-len(failures)}/{len(output)}**",
        "- Batch purpose: show all failing original-code stages in one CI run",
        "- This is diagnostic coverage, not game boot",
        "",
        "| Independent gate | Root-cause group | Result |",
        "| --- | --- | --- |",
    ]
    for entry in output:
        markdown.append(f"| {entry['test']} | {entry['group']} | "+
                        ("PASS" if entry["pass"] else "FAIL")+" |")
    markdown.extend(["","**Private executable stays on the runner; only these grouped metadata results are uploaded.**",""])
    (report/"crt-batch-results.json").write_text(json.dumps(output,indent=2)+"\n")
    (report/"crt-batch-results.md").write_text("\n".join(markdown))
    if os.environ.get("GITHUB_STEP_SUMMARY"):
        with open(os.environ["GITHUB_STEP_SUMMARY"],"a") as handle:
            handle.write("\n".join(markdown))
    print("\n".join(markdown),flush=True)
    if failures:
        raise SystemExit("Grouped CRT regression failed: "+", ".join(x["test"] for x in failures))

if __name__=="__main__":
    if len(sys.argv)!=3:
        raise SystemExit("usage: script.py /private/original.exe /private/report_dir")
    run(Path(sys.argv[1]),Path(sys.argv[2]))
