#!/usr/bin/env python3
"""Native post-DLL game original CRC gate + exact SteamAPI CALL frontier.

The original Win64 CPU executes to the imported SteamAPI call but NEVER
invokes it; the AArch64 guest runtime executes authentic register restores,
CRC equality/inequality conditional and app-id setup, then also STOPS at
the same unimplemented Steam boundary. No result is fabricated.
"""
import hashlib,json,subprocess,sys,tempfile
from pathlib import Path
import mxbikes_original_postseek_full_native as full
import mxbikes_crc_native as crc
from mxbikes_owned_file_crt import OwnedReadOnlyFile
from mxbikes_whole_game_map import INPUT_SHA
from tools.import_aot_smoke import execute_arm64_elf

ROOT=full.ROOT
END=0x1306ed

def make_code(blob,before,at_close,expected):
    src=full.c_source(blob,before,at_close)
    needle=" if(mxb_postseek_native_finish_reads(&s,&mem,&f,&e))return 8;"
    if src.count(needle)!=1:
        raise ValueError("Original full-loop fixture layout changed")
    extension=[
        needle,
        " {mx_crt_cluster_state bad=s;",
        "  mxb_postseek_extra extra_bad=e;",
        "  bad.rbx^=UINT64_C(1);",
        "  if(mxb_postseek_native_until_steam(&bad,&mem,&extra_bad)!=2",
        "     ||bad.rip!=MXB_POSTSEEK_SIZE_FAIL||bad.rax!=1U",
        "     ||bad.zf)return 9;}",
        " if(mxb_postseek_native_until_steam(&s,&mem,&e)!=1)return 10;",
        " if(s.rip!=MXB_POSTSEEK_STEAM_BOUNDARY||f.is_open)return 11;",
    ]
    for reg in ("rip","rsp","rax","rbx","rcx","rdx","r8",
                "r9","rsi","rdi","r11","zf","sf","cf"):
        extension.append(" if(s."+reg+"!=UINT64_C("+str(expected[reg])+"))return 12;")
    for reg in ("rbp","r12","r13","r14"):
        extension.append(" if(e."+reg+"!=UINT64_C("+str(expected[reg])+"))return 13;")
    extension.extend([
        " if(e.original_crt_calls!=255U)return 14;",
        " if(s.rcx!=UINT64_C(0xa008c))return 15;",
    ])
    return src.replace(needle,"\n".join(extension))

def run(exe,dll,out):
    from tools.pe_probe import PE
    pe=PE(exe)
    if hashlib.sha256(pe.b).hexdigest()!=INPUT_SHA:
        raise ValueError("Original owned exe identity changed")
    crc.original_form(pe)
    original=json.loads((out/"original-postclose-steam-boundary.json").read_text())
    if (original["original_first_unsupported_external_call"]["import"]!=
        "steam_api64.dll!SteamAPI_RestartAppIfNecessary"):
        raise ValueError("Original Steam boundary changed")
    rows=original["original_postclose_instruction_forms"]
    got={(r["rva"],r["mnemonic"],r["operands"]) for r in rows}
    mandatory={
      ("0x1306b8","mov","r14, qword ptr [rsp + 0x420]"),
      ("0x1306c0","mov","r13, qword ptr [rsp + 0x428]"),
      ("0x1306c8","mov","rdi, qword ptr [rsp + 0x458]"),
      ("0x1306d0","mov","rbp, qword ptr [rsp + 0x448]"),
      ("0x1306d8","mov","r11d, 0xbc72"),
      ("0x1306de","cmp","bx, r11w"),
      ("0x1306e2","jne","0x130606"),
      ("0x1306e8","mov","ecx, 0xa008c"),
      ("0x1306ed","call","qword ptr [rip + 0x1f1325]")
    }
    if not mandatory.issubset(got):
        raise ValueError("Original postclose Steam CRC gate has changed")
    expected=original["authentic_original_before_steam_call_guest_registers"]
    if expected["rip"]!=full.BASE+END or expected["rcx"]!=0xa008c:
        raise ValueError("Original x64 Steam-call argument/PC unexpected")
    manifest=json.loads((out/"owned-steam-file-manifest.json").read_text())
    blob=OwnedReadOnlyFile.from_private_path(
        dll,manifest.get("owned_dll_size_bytes")).content
    before,at_close,calls=full.x64_reference(pe,blob)
    generated=make_code(blob,before,at_close,expected)
    with tempfile.TemporaryDirectory(prefix="mxb-native-postclose-steam-gate-") as td:
        tmp=Path(td);src=tmp/"private-steam-call-gate.c"
        src.write_text(generated)
        opts=["-O3","-std=c11","-Wall","-Wextra","-Werror",
              "-I",str(ROOT/"scripts"),"-I",str(ROOT/"arm64-lab"/"runtime")]
        host=tmp/"host"
        comp=subprocess.run(["cc",*opts,"-DHOST",str(src),"-o",str(host)],
                            capture_output=True,text=True)
        if comp.returncode:
            raise RuntimeError("Original postclose guest host compile: "+comp.stderr[-3000:])
        test=subprocess.run([str(host)],capture_output=True,text=True)
        if test.returncode:
            raise RuntimeError("Original x64 guest Steam-call frontier mismatch "+
                               str(test.returncode))
        arm=tmp/"game-original-crc-to-steam-arm64.elf"
        cmd=["clang","--target=aarch64-unknown-linux-gnu",
             "-fuse-ld=lld","-nostdlib","-static","-ffreestanding",
             "-fno-builtin","-fno-stack-protector",*opts,
             "-Wl,-e,smoke","-Wl,-z,max-page-size=4096",
             "-Wl,--build-id=none",str(src),"-o",str(arm)]
        b=subprocess.run(cmd,capture_output=True,text=True)
        if b.returncode:
            raise RuntimeError("Original postclose AArch64 compile: "+b.stderr[-3000:])
        native=execute_arm64_elf(arm,instruction_budget=6000000,timeout_us=15000000)
    report={
        "original_game_sha_verified":True,
        "translated_original_win64_postseek_through_steam_call":True,
        "native_entry_rva":hex(full.first.START),
        "native_end_rva":hex(END),
        "full_file_bytes_handled_before_steam":len(blob),
        "postclose_original_instruction_forms_verified":len(mandatory),
        "postclose_original_guest_registers_differential":18,
        "original_crc_match_path":True,
        "native_crc_mismatch_error_path":True,
        "native_original_steam_app_id_argument":hex(expected["rcx"]),
        "native_aarch64_executed_to_real_steam_call":native["return_to_sentinel"],
        "steam_restart_api_actually_executed":False,
        "engine_or_renderer_started":False
    }
    out.mkdir(parents=True,exist_ok=True)
    (out/"native-original-steam-call-frontier.json").write_text(json.dumps(report,indent=2)+"\n")
    summary="\n".join([
        "# MX Bikes native original CRC gate to real Steam call","",
        "- Original game file-reading and CRC loop through fclose: **PASS**",
        "- SHA-pinned authentic original postclose instructions verified: **"+
           str(len(mandatory))+"**",
        "- Original expected CRC 0xBC72 success: **PASS**",
        "- Wrong checksum to original error path: **PASS**",
        "- Original 0x1306ED SteamAPI_RestartAppIfNecessary CALL entry: **REACHED**",
        "- Original Win64 app ID argument: **"+hex(expected["rcx"])+"**",
        "- CPU register and flags match original x64: **PASS**",
        "- Executed one native AArch64 program: **"+str(native["return_to_sentinel"])+"**",
        "",
        "Stop BEFORE Steam import execution: no Steam result, authorization or",
        "original game engine work fabricated. No visible game screen yet.",""])
    (out/"native-original-steam-call-frontier.md").write_text(summary)
    print(summary)
    return report
if __name__=="__main__":
    if len(sys.argv)!=4:raise SystemExit("usage: steam_frontier.py exe steam_dll report_dir")
    run(Path(sys.argv[1]),Path(sys.argv[2]),Path(sys.argv[3]))
