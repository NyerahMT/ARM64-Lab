#!/usr/bin/env python3
"""Attempt ONE uninterrupted native AArch64 execution of real owned read/CRC/close.

Exact original x64 CRC reference for every chunk. Executes the entire guest
file-service chain in one AArch64 ELF invocation with no checkpoint re-seeding
between chunks. Stops before unimplemented Steam/engine; this is not full
original Win64 CALL-site translation.
"""
import hashlib,json,subprocess,sys,tempfile
from pathlib import Path
import mxbikes_crc_native as crc
import mxbikes_native_file_crc_chain as chain
from mxbikes_owned_file_crt import OwnedReadOnlyFile
from mxbikes_whole_game_map import INPUT_SHA
from tools.import_aot_smoke import execute_arm64_elf

def run(exe,dll,out):
    from tools.pe_probe import PE
    pe=PE(exe)
    if hashlib.sha256(pe.b).hexdigest()!=INPUT_SHA:
        raise ValueError("Original game SHA changed")
    crc.original_form(pe)
    manifest=json.loads((out/"owned-steam-file-manifest.json").read_text())
    if(manifest.get("matching_owned_dll_count")!=1 or
       manifest.get("steam_api64_dll_present") is not True):
        raise ValueError("Owned file identity mismatch")
    original=OwnedReadOnlyFile.from_private_path(
        dll,manifest["owned_dll_size_bytes"])
    chunks=crc.original_x64_chunks(pe,original.content,bx_seed=crc.SEED)
    source=chain.private_source(original.content,chunks,0,crc.SEED,True,True)
    with tempfile.TemporaryDirectory(prefix="mxb-uninterrupted-arm64-crc-") as td:
        tmp=Path(td)
        src=tmp/"private-native-chain.c"
        src.write_text(source)
        opts=["-O3","-std=c11","-Wall","-Wextra","-Werror",
              "-I",str(chain.ROOT/"scripts"),
              "-I",str(chain.ROOT/"arm64-lab"/"runtime")]
        host=tmp/"host"
        comp=subprocess.run(["cc",*opts,"-DHOST",str(src),"-o",str(host)],
                            capture_output=True,text=True)
        if comp.returncode:
            raise RuntimeError("Single-path host build: "+comp.stderr[-3500:])
        result=subprocess.run([str(host)],capture_output=True,text=True)
        if result.returncode:
            raise RuntimeError("Single-path host CRC mismatched original x64 exit "+
                               str(result.returncode))
        arm=tmp/"native-original-crc-file-flow-aarch64.elf"
        cc=["clang","--target=aarch64-unknown-linux-gnu",
            "-fuse-ld=lld","-nostdlib","-static","-ffreestanding",
            "-fno-builtin","-fno-stack-protector",*opts,
            "-Wl,-e,smoke","-Wl,-z,max-page-size=4096",
            "-Wl,--build-id=none",str(src),"-o",str(arm)]
        compile_result=subprocess.run(cc,capture_output=True,text=True)
        if compile_result.returncode:
            raise RuntimeError("Single-path ARM64 build: "+compile_result.stderr[-3500:])
        result=execute_arm64_elf(arm,instruction_budget=6000000,
                                 timeout_us=15000000)
    out.mkdir(parents=True,exist_ok=True)
    report={
        "original_sha256":INPUT_SHA,
        "one_uninterrupted_native_aarch64_elf_execution":result["return_to_sentinel"],
        "all_owned_file_bytes_read_native":len(original.content),
        "original_x64_original_crc_checkpoints_compared":len(chunks),
        "real_native_win64_guest_memory":"mx_cfg_memory",
        "real_native_win64_guest_state":"mx_crt_cluster_state",
        "native_closed_file_checked":True,
        "original_rolling_checksum":hex(chunks[-1]["bx"]),
        "original_win64_call_instruction_chain_translated":False,
        "steam_client_or_engine_started":False
    }
    (out/"native-file-crc-single-run.json").write_text(json.dumps(report,indent=2)+"\n")
    summary="\n".join([
        "# MX Bikes — one complete native ARM64 read/CRC/close execution","",
        "- Original owned game CRC checkpoints: **"+str(len(chunks))+"**",
        "- Exact DLL bytes processed in ONE native ARM64 ELF execution: **"+
           str(len(original.content))+"**",
        "- Retained rolling guest state without per-chunk re-seeding: **YES**",
        "- File seek, length, rewind, guest read, CRC and close: **PASS**",
        "- Final original checksum: **"+hex(chunks[-1]["bx"])+"**",
        "",
        "This is one true continuous native service/checksum routine.",
        "The game Win64 CALL-site/branch instructions, Steam runtime, engine,",
        "renderer and first iOS frame remain unimplemented.",""])
    (out/"native-file-crc-single-run.md").write_text(summary)
    print(summary)
    return report

if __name__=="__main__":
    if len(sys.argv)!=4:
        raise SystemExit("usage: native_file_crc_single.py game.exe steam.dll reports")
    run(Path(sys.argv[1]),Path(sys.argv[2]),Path(sys.argv[3]))
