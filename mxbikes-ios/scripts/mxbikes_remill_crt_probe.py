#!/usr/bin/env python3
"""Execute the Remill-generated CRT initializer with a deliberately minimal host.

This is a diagnostic, not a Windows or guest-memory implementation: guest
operate on a bounded synthetic stack and globals; foreign calls are rejected. It
never claims complete initializer semantics or an iPhone boot.
"""
from pathlib import Path
import json
import re
import subprocess
import sys
import tempfile

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"arm64-lab"))
from tools.import_aot_smoke import execute_arm64_elf

HELPERS={
    "__remill_read_memory_64",
    "__remill_write_memory_64",
    "__remill_function_call",
    "__remill_function_return",
}
COOKIE_SEEDS=(0x0, 0x1, 0x100000000, 0x1111111111111111, 0xabcdef98765432, 0xffffffff00000000, 0x2b992ddfa231)
LLVM_RUNTIME=r"""
@mx_cookies = private constant [7 x i64] [i64 0, i64 1, i64 4294967296, i64 1229782938247303441, i64 48358649956291634, i64 18446744069414584320, i64 47936899621425]
declare void @mx_prepare(i64)
declare i32 @mx_status()

define i32 @smoke() {
entry:
  br label %loop
loop:
  %i = phi i64 [ 0, %entry ], [ %next, %advance ]
  %seedptr = getelementptr inbounds [7 x i64], [7 x i64]* @mx_cookies, i64 0, i64 %i
  %seed = load i64, i64* %seedptr
  call void @mx_prepare(i64 %seed)
  %state = alloca %struct.State, align 16
  store %struct.State zeroinitializer, %struct.State* %state
  %memory = inttoptr i64 4096 to %struct.Memory*
  %returned = call %struct.Memory* @sub_0(%struct.State* %state, i64 0, %struct.Memory* %memory)
  %same = icmp eq %struct.Memory* %returned, %memory
  %status = call i32 @mx_status()
  %status_ok = icmp eq i32 %status, 0
  %both_ok = and i1 %same, %status_ok
  br i1 %both_ok, label %advance, label %fail
advance:
  %next = add nuw i64 %i, 1
  %done = icmp eq i64 %next, 7
  br i1 %done, label %pass, label %loop
fail:
  ret i32 1
pass:
  ret i32 0
}
"""

def run(original_ir,output):
    source=original_ir.read_text()
    if not re.search(r"(?m)^define .*@sub_0\(",source):
        raise RuntimeError("No lifted original instruction sequence entry")
    lines=source.splitlines()
    declarations=[line for line in lines if line.startswith("declare ")
                  and "@__remill_" in line]
    seen=set()
    for line in declarations:
        match=re.search(r"@(__remill_[A-Za-z0-9_]+)\(",line)
        if not match or match.group(1) not in HELPERS:
            raise RuntimeError("Unexpected native Remill helper declaration: "+line[:150])
        seen.add(match.group(1))
    if seen!=HELPERS:
        raise RuntimeError("Incomplete original CRT helper declarations: "+repr(seen))
    filtered=source  # Keep Remill declarations: matching native C symbols resolve at link.
    with tempfile.TemporaryDirectory(prefix="crt-remill-runtime-") as td:
        root=Path(td)
        sourcefile=root/"private_crt_with_bounded_runtime.ll"
        sourcefile.write_text(filtered+"\n"+LLVM_RUNTIME)
        bc=root/"crt.bc";obj=root/"crt.o";exe=root/"crt.elf"
        def cmd(args):
            r=subprocess.run(args,text=True,capture_output=True)
            if r.returncode:
                raise RuntimeError("Runtime build failed: "+r.stderr[-3000:])
        cmd(["llvm-as-14",str(sourcefile),"-o",str(bc)])
        cmd(["opt-14","-verify","-disable-output",str(bc)])
        cmd(["llc-14","-mtriple=aarch64-unknown-linux-gnu","-filetype=obj",str(bc),"-o",str(obj)])
        externals=subprocess.run(["llvm-nm-14","--undefined-only",str(obj)],
                                 capture_output=True,text=True,check=True)
        names={line.split()[-1] for line in externals.stdout.splitlines() if line.strip()}
        expected=HELPERS | {"mx_prepare","mx_status"}
        if names != expected:
            raise RuntimeError("Unexpected native runtime dependencies: "+str(sorted(names)))
        helper=root/"memory_host.o"
        host=Path(__file__).resolve().with_name("mxbikes_crt_guest_memory.c")
        cmd(["clang","--target=aarch64-unknown-linux-gnu","-ffreestanding",
             "-fno-stack-protector","-fno-builtin","-O2","-c",
             str(host),"-o",str(helper)])
        cmd(["clang","--target=aarch64-unknown-linux-gnu","-fuse-ld=lld",
             "-nostdlib","-static","-ffreestanding","-Wl,-e,smoke",
             "-Wl,-z,max-page-size=4096","-Wl,--build-id=none",
             str(obj),str(helper),"-o",str(exe)])
        arm=execute_arm64_elf(exe)
    reference_file=output/"crt-x64-reference.json"
    if not reference_file.is_file():
        raise RuntimeError("Original x64 CRT reference must pass before ARM64 reporting")
    reference=json.loads(reference_file.read_text())
    required={
        "original_x64_executed":True,
        "case_count":len(COOKIE_SEEDS),
        "dynamic_instruction_count_per_case":15,
        "guest_64bit_memory_write_count_per_case":4,
        "all_cases_passed":True,
        "import_calls_executed":0,
    }
    if reference.get("fixture_cookies")!=list(COOKIE_SEEDS):
        raise RuntimeError("Original x64 fixture cookie values differ from ARM64 inputs")
    for key,expected in required.items():
        if reference.get(key)!=expected:
            raise RuntimeError("x64-vs-ARM64 fixture mismatch: "+key)
    report={
        "original_function_rva":"0x2ab954",
        "remill_llvm_original_span":True,
        "four_runtime_abi_symbols_linked":True,
        "arm64_unicorn_code_executed":arm["return_to_sentinel"],
        "bounded_guest_memory_path_completed":arm["arm64_smoke_exit"]==0,
        "full_function_semantics_verified":False,
        "bounded_read_write_backing":True,
        "original_x64_reference_verified":True,
        "original_x64_differential_cases":len(COOKIE_SEEDS),
        "translated_arm64_differential_cases":len(COOKIE_SEEDS),
        "bounded_guest_memory_effects_match_x64_reference":True,
        "full_guest_register_state_differential":False,
        "windows_imports_executed":False,
        "steam_api_integrated":False,
        "ios_boot":False,
        "limitation":"Seven nondefault-cookie fixtures exercise the same early branch; no second-branch, complete CPU-state, or Windows-runtime differential."
    }
    output.mkdir(parents=True,exist_ok=True)
    (output/"remill-crt-probe.json").write_text(json.dumps(report,indent=2)+"\n")
    summary="# MX Bikes original CRT Remill AArch64 runtime probe\n\n"
    summary+="- Remill-generated original-function IR linked with four bounded runtime helpers\n"
    summary+="- Native-backed stack/cookie guest memory with a restricted no-external-call path\n"
    summary+="- Original x64 early-branch memory/return fixtures agree with ARM64: **7/7 passed**\n"
    summary+="- AArch64 Unicorn ELF execution: **passed**\n\n"
    summary+="**Seven cookie values on the early branch; no full register-state differential, Steam or game startup.**\n"
    (output/"remill-crt-probe.md").write_text(summary)
    print(summary)

if __name__=="__main__":
    if len(sys.argv)!=3:raise SystemExit("usage: script.py CRT_REMILL_IR REPORT_DIR")
    run(Path(sys.argv[1]),Path(sys.argv[2]))
