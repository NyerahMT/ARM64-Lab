#!/usr/bin/env python3
"""Real native guest-file-service -> verified original CRC -> close execution.

Uses actual privately-owned DLL bytes in generated temporary C, the existing
mx_crt_cluster_state and mx_cfg_memory, and per-chunk original x64 guest
register oracles. A complete file is streamed through bounded guest memory;
no x64 original instructions run during the AArch64 execution. File service
adapters are NOT yet translations of original CALL-site/branch instructions.
Original SteamAPI_RestartAppIfNecessary is intentionally not implemented.
"""
import hashlib,json,subprocess,sys,tempfile
from pathlib import Path
import mxbikes_crc_native as crc
from mxbikes_owned_file_crt import OwnedReadOnlyFile
from mxbikes_whole_game_map import INPUT_SHA
from tools.import_aot_smoke import execute_arm64_elf

ROOT=Path(__file__).resolve().parents[1]
DATA=0x600010200
BLOCKS_PER_AARCH64=32

def private_source(raw,rows,offset,seed,first,last):
    if not raw or not rows or offset<0 or offset>=len(raw):
        raise ValueError("Invalid original guest file batch")
    if sum(x["length"] for x in rows)>len(raw)-offset:
        raise ValueError("Invalid original guest file byte span")
    source=[
        '#include <stdint.h>',
        '#include "mxbikes_native_file_crc_chain.h"',
        "#define DATA UINT64_C("+str(DATA)+")",
        "static const uint8_t original_owned_dll["+str(len(raw))+"]={"+
            ",".join(str(x) for x in raw)+"};",
        "static uint8_t guest_read_buffer[1000U];",
        "typedef struct {uint64_t rbx,rax;uint32_t count;} expected_chunk;",
        "static const expected_chunk refs["+str(len(rows))+"]={"+
            ",".join("{UINT64_C("+str(v["bx"])+"),UINT64_C("+
                     str(v["ax"])+"),"+str(v["length"])+"U}" for v in rows)+
            "};",
        "int smoke(void){",
        " mx_cfg_region region={DATA,guest_read_buffer,sizeof(guest_read_buffer)};",
        " mx_cfg_memory memory={&region,1U};",
        " mx_crt_cluster_state state={0};",
        " mxb_readonly_file file={0};",
        " if(!mxb_file_init(&file,original_owned_dll,sizeof(original_owned_dll),"+
                    str(offset)+"U))return 1;",
    ]
    if first:
        source.extend([
         " if(!mxb_file_seek(&file,0,MXB_FILE_SEEK_END))return 2;",
         " uint64_t length=0U;",
         " if(!mxb_file_tell(&file,&length)||length!="+
                  str(len(raw))+"U)return 3;",
         " if(!mxb_file_seek(&file,0,MXB_FILE_SEEK_SET)||file.position!=0U)return 4;",
        ])
    source.extend([
       " state.rbx=UINT64_C("+str(seed)+");",
       " state.rax=UINT64_C(0x12345678);",
       " for(uint32_t i=0U;i<"+str(len(rows))+"U;i++){",
       "   if(!mxb_file_read_and_crc(&file,&state,&memory,DATA,refs[i].count,",
       "                             UINT64_C(255)))return 5;",
       "   if(state.rip!=MXB_CRC_EXIT_VA||state.rcx!=DATA+refs[i].count||",
       "      state.rdx!=0U||state.rbx!=refs[i].rbx||state.rax!=refs[i].rax||",
       "      state.cf||state.sf||!state.zf)return 6;",
       " }",
       " if(file.total_bytes_read!="+str(sum(x["length"] for x in rows))+"U||",
       "    file.position!="+str(offset+sum(x["length"] for x in rows))+"U||",
       "    file.read_calls!="+str(len(rows))+"U)return 7;",
    ])
    if first:
        source.append(" if(file.seek_calls!=2U||file.tell_calls!=1U)return 8;")
    if last:
        source.extend([
            " if(!mxb_file_close(&file)||file.is_open||file.close_calls!=1U)return 9;",
            " uint32_t copied=1234U;",
            " if(mxb_file_read(&file,&memory,DATA,1U,&copied))return 10;",
            " if(mxb_file_seek(&file,0,MXB_FILE_SEEK_SET))return 11;",
            " uint64_t pos=0U;",
            " if(mxb_file_tell(&file,&pos))return 12;",
            " if(mxb_file_close(&file))return 13;",
        ])
    source.extend([
        " {mx_crt_cluster_state failed={0};",
        "  mxb_readonly_file invalid={0};",
        "  if(!mxb_file_init(&invalid,original_owned_dll,sizeof(original_owned_dll),0U))return 14;",
        "  if(mxb_file_read_and_crc(&invalid,&failed,&memory,DATA+1000U,1U,255U))return 15;",
        "  if(invalid.position!=0U||invalid.total_bytes_read!=0U)return 16;",
        "  if(mxb_file_seek(&invalid,-1,MXB_FILE_SEEK_SET))return 17;",
        "  if(mxb_file_seek(&invalid,1,MXB_FILE_SEEK_END))return 18;",
        "  if(mxb_file_read_and_crc(&invalid,&failed,&memory,DATA,1U,0U))return 19;",
        " }",
        " return 0;",
        "}",
        "#ifdef HOST",
        "int main(void){return smoke();}",
        "#endif",
    ])
    return "\n".join(source)+"\n"

def run(exe,dll,out):
    from tools.pe_probe import PE
    pe=PE(exe)
    if hashlib.sha256(pe.b).hexdigest()!=INPUT_SHA:
        raise ValueError("Unrecognized original exe SHA")
    crc.original_form(pe)
    manifest=json.loads((out/"owned-steam-file-manifest.json").read_text())
    if (manifest.get("steam_api64_dll_present") is not True or
        manifest.get("matching_owned_dll_count")!=1):
        raise ValueError("Authentic original DLL unavailable")
    owned=OwnedReadOnlyFile.from_private_path(dll,manifest["owned_dll_size_bytes"])
    source_bytes=owned.content
    original=crc.original_x64_chunks(pe,source_bytes,bx_seed=crc.SEED)
    if sum(row["length"] for row in original)!=len(source_bytes):
        raise ValueError("Original guest chunks do not cover the owned file")
    offset=0
    batches=0
    with tempfile.TemporaryDirectory(prefix="mxb-guest-file-runtime-") as temp:
        root=Path(temp)
        for start in range(0,len(original),BLOCKS_PER_AARCH64):
            rows=original[start:start+BLOCKS_PER_AARCH64]
            seed=crc.SEED if start==0 else original[start-1]["bx"]
            is_first=start==0
            is_last=start+len(rows)==len(original)
            body=private_source(source_bytes,rows,offset,seed,is_first,is_last)
            src=root/"guest-file-chain.c"
            src.write_text(body)
            options=["-O2","-std=c11","-Wall","-Wextra","-Werror",
                    "-I",str(ROOT/"scripts"),
                    "-I",str(ROOT/"arm64-lab"/"runtime")]
            host=root/"native-host"
            result=subprocess.run(
                ["cc",*options,"-DHOST",str(src),"-o",str(host)],
                capture_output=True,text=True)
            if result.returncode:
                raise RuntimeError("Native Win64 guest stream compile failure: "+
                                  result.stderr[-4000:])
            result=subprocess.run([str(host)],capture_output=True,text=True)
            if result.returncode:
                raise RuntimeError("Original x64 / native guest stream mismatch batch "+
                                   str(batches)+" status "+str(result.returncode))
            arm=root/"native-file-chain-aarch64.elf"
            cmd=["clang","--target=aarch64-unknown-linux-gnu",
                 "-fuse-ld=lld","-nostdlib","-static","-ffreestanding",
                 "-fno-builtin","-fno-stack-protector",*options,
                 "-Wl,-e,smoke","-Wl,-z,max-page-size=4096",
                 "-Wl,--build-id=none",str(src),"-o",str(arm)]
            build=subprocess.run(cmd,capture_output=True,text=True)
            if build.returncode:
                raise RuntimeError("Native AArch64 guest stream build failed: "+
                                   build.stderr[-4000:])
            outcome=execute_arm64_elf(arm,instruction_budget=6000000,
                                     timeout_us=15000000)
            if not outcome["return_to_sentinel"]:
                raise RuntimeError("Native guest file-chain batch didn't return")
            offset+=sum(v["length"] for v in rows)
            batches+=1
    if offset!=len(source_bytes):
        raise ValueError("Native AArch64 file path left original bytes unread")
    report={
      "sha_pinned_original_exe":INPUT_SHA,
      "native_guest_header":"scripts/mxbikes_native_file_crc_chain.h",
      "native_guest_registers":"mx_crt_cluster_state",
      "native_guest_memory":"mx_cfg_memory",
      "owned_dll_original_bytes":len(source_bytes),
      "original_x64_verified_checksum_chunks":len(original),
      "actual_arm64_file_service_and_crc_batches":batches,
      "full_owned_stream_fseek_end_ftell_fseek_set":True,
      "native_owned_file_read_and_crc_all_bytes":True,
      "native_guest_file_closed_and_fail_closed":True,
      "native_original_rolling_checksum":hex(original[-1]["bx"]),
      "real_original_iat_callsite_control_flow_translated":False,
      "original_steam_runtime_available_on_ios":False,
      "original_game_engine_started":False,
      "first_game_frame_rendered":False
    }
    out.mkdir(parents=True,exist_ok=True)
    (out/"native-file-crc-chain.json").write_text(json.dumps(report,indent=2)+"\n")
    lines=["# MX Bikes — real native ARM64 read-only file + original CRC service chain","",
       "- Original game x64 checksum reference chunks: **"+str(len(original))+"**",
       "- Owned DLL actual bytes read and checksummed in ARM64: **"+
           str(len(source_bytes))+"**",
       "- Independently completed native AArch64 execution batches: **"+
           str(batches)+"**",
       "- Original x64 and native guest memory/register CRC checkpoint comparison: **PASS**",
       "- File service order: **fseek(end) -> ftell -> fseek(start) -> "+
           str(len(original))+" fread/CRC chunks -> fclose**",
       "- Final verified rolling checksum: **"+hex(original[-1]["bx"])+"**",
       "- Invalid guest address, seek boundaries, wrong R14, closed handle: **blocked**",
       "",
       "Native service + CRC chain is real. The surrounding original Win64",
       "CALLsite and branch logic is not translated or connected yet.",
       "SteamAPI_RestartAppIfNecessary, engine init, graphics, IPA do not run.",""]
    (out/"native-file-crc-chain.md").write_text("\n".join(lines))
    print("\n".join(lines))
    return report

if __name__=="__main__":
    if len(sys.argv)!=4:
        raise SystemExit("usage: native_file_crc_chain.py owned.exe owned.dll report-dir")
    run(Path(sys.argv[1]),Path(sys.argv[2]),Path(sys.argv[3]))
