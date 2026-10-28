#!/usr/bin/env python3
"""Differential-test a persistent CRC-to-native-guest-memory bridge on ARM64.

Runs the verified byte routine through the SAME mx_crt_cluster_state and
mx_cfg_memory structures as the startup translator. Original x64 is the
independent oracle. The owned file is private input only, never an artifact.
"""
import hashlib,json,subprocess,sys,tempfile
from pathlib import Path
import mxbikes_crc_native as crc
import mxbikes_main_joined_callee_native as joined
from mxbikes_owned_file_crt import OwnedReadOnlyFile
from mxbikes_whole_game_map import INPUT_SHA
from tools.import_aot_smoke import execute_arm64_elf

ROOT=Path(__file__).resolve().parents[1]
DATA=0x600010200

def make_source(cases,owned,original,*,seed=crc.SEED):
    data_declarations=[
      "#include <stdint.h>",
      '#include "mxbikes_crc_cluster_bridge.h"',
      "#define DATA UINT64_C("+str(DATA)+")",
      "static uint8_t owned_file["+str(len(owned))+"]={"+
            ",".join(str(x) for x in owned)+"};",
      """typedef struct {uint64_t bx,ax; uint32_t size;} crc_expected;""",
      "static const crc_expected expected["+str(len(original))+"]={"+
      ",".join("{UINT64_C("+str(q["bx"])+"),UINT64_C("+
               str(q["ax"])+"),"+str(q["length"])+"U}" for q in original)+
      "};"
    ]
    for n,(seed,blob,refs) in enumerate(cases):
        if len(refs)!=1:raise ValueError("Native guest input must be one chunk")
        data_declarations.extend([
          "static uint8_t synthetic_"+str(n)+"["+str(len(blob))+"]={"+
                ",".join(str(x) for x in blob)+"};",
        ])
    commands=[
      "int smoke(void){",
      "  mx_cfg_region region={DATA,owned_file,sizeof(owned_file)};",
      "  mx_cfg_memory memory={&region,1U};",
      "  mx_crt_cluster_state state={0};",
      "  uint64_t rolling=UINT64_C("+str(seed)+");",
      "  uint64_t cursor=0U;",
      "  for(uint32_t i=0U;i<"+str(len(original))+"U;i++){",
      "    state.rip=MXB_CRC_LOOP_VA;state.rax=UINT64_C(0x12345678);",
      "    state.rbx=rolling;state.rcx=DATA+cursor;",
      "    state.rdx=expected[i].size;state.instructions=0U;",
      "    state.zf=0U;state.sf=1U;state.cf=1U;",
      "    if(!mxb_crc_cluster_run(&state,&memory,UINT64_C(255)))return 1;",
      "    if(state.rip!=MXB_CRC_EXIT_VA || state.rcx!=DATA+cursor+expected[i].size ||",
      "       state.rdx!=0U || state.rbx!=expected[i].bx ||",
      "       state.rax!=expected[i].ax || !state.zf || state.sf || state.cf ||",
      "       state.instructions!=expected[i].size*17U)return 2;",
      "    rolling=state.rbx;cursor+=expected[i].size;",
      "  }",
      "  if(cursor!=sizeof(owned_file))return 3;",
    ]
    for n,(seed,blob,refs) in enumerate(cases):
        expected=refs[0]
        commands.extend([
          "  {mx_cfg_region test={DATA,synthetic_"+str(n)+",sizeof(synthetic_"+
             str(n)+")};",
          "   mx_cfg_memory m={&test,1U};",
          "   mx_crt_cluster_state s={0};",
          "   s.rip=MXB_CRC_LOOP_VA;s.rcx=DATA;s.rdx="+str(len(blob))+"U;",
          "   s.rbx=UINT64_C("+str(seed)+");s.rax=UINT64_C(0x12345678);",
          "   if(!mxb_crc_cluster_run(&s,&m,UINT64_C(255)))return "+str(10+n*4)+";",
          "   if(s.rax!=UINT64_C("+str(expected["ax"])+") ||",
          "      s.rbx!=UINT64_C("+str(expected["bx"])+") ||",
          "      s.rcx!=DATA+"+str(len(blob))+"U || s.rdx ||",
          "      s.rip!=MXB_CRC_EXIT_VA || s.instructions!="+
                     str(len(blob)*17)+"U)return "+str(11+n*4)+";",
          "  }",
        ])
    commands.extend([
        "  {mx_crt_cluster_state s={0};s.rip=MXB_CRC_LOOP_VA;",
        "   s.rcx=DATA;s.rdx=1U;s.rbx=UINT64_C(0x12345678);",
        "   const uint64_t before=s.rbx;",
        "   if(mxb_crc_cluster_run(&s,&memory,0U) || s.rbx!=before ||",
        "      s.rcx!=DATA || s.rip!=MXB_CRC_LOOP_VA)return 60;",
        "   s.rdx=0U;",
        "   if(mxb_crc_cluster_run(&s,&memory,255U))return 61;",
        "   s.rdx=1U;s.rcx=DATA+sizeof(owned_file);",
        "   if(mxb_crc_cluster_run(&s,&memory,255U))return 62;",
        "   s.rcx=DATA;s.rip=MXB_CRC_EXIT_VA;",
        "   if(mxb_crc_cluster_run(&s,&memory,255U))return 63;",
        "   s.rip=MXB_CRC_LOOP_VA;s.rdx=1001U;",
        "   if(mxb_crc_cluster_run(&s,&memory,255U))return 64;",
        "  }",
        "  return 0;",
        "}",
        "#ifdef HOST",
        "int main(void){return smoke();}",
        "#endif",
    ])
    return "\n".join(data_declarations+commands)+"\n"

def run(executable,dll,report_dir):
    from tools.pe_probe import PE
    pe=PE(executable)
    if hashlib.sha256(pe.b).hexdigest()!=INPUT_SHA:
        raise ValueError("Original owned game SHA mismatch")
    crc.original_form(pe)
    manifest=json.loads((report_dir/"owned-steam-file-manifest.json").read_text())
    if manifest.get("steam_api64_dll_present") is not True:
        raise ValueError("No privately owned DLL present")
    file=OwnedReadOnlyFile.from_private_path(dll,manifest.get("owned_dll_size_bytes"))
    cases=[]
    for seed,length,salt in crc.REGRESSIONS:
        blob=crc.pseudo_bytes(length,salt)
        cases.append((seed,blob,crc.original_x64_chunks(pe,blob,bx_seed=seed)))
    owned=crc.original_x64_chunks(pe,file.content,bx_seed=crc.SEED)
    chunk_group=32
    processed=0
    batches=0
    with tempfile.TemporaryDirectory(prefix="mxb-crc-cluster-") as td:
        root=Path(td)
        for start in range(0,len(owned),chunk_group):
            selected=owned[start:start+chunk_group]
            batch_bytes=sum(q["length"] for q in selected)
            group_data=file.content[processed:processed+batch_bytes]
            if len(group_data)!=batch_bytes:
                raise ValueError("Original owned bytes missing during batched guest bridge")
            rolling=crc.SEED if start==0 else owned[start-1]["bx"]
            src=make_source(cases if start==0 else [],
                            group_data,selected,seed=rolling)
            source=root/("private-guest-regression-"+str(batches)+".c")
            source.write_text(src)
            args=["-O2","-std=c11","-Wall","-Wextra","-Werror",
                  "-I",str(ROOT/"scripts"),
                  "-I",str(ROOT/"arm64-lab"/"runtime")]
            host=root/("host-"+str(batches))
            build=subprocess.run(["cc",*args,"-DHOST",str(source),"-o",str(host)],
                                 capture_output=True,text=True)
            if build.returncode:
                raise RuntimeError("Native guest CRC host build failed: "+build.stderr[-3500:])
            check=subprocess.run([str(host)],capture_output=True,text=True)
            if check.returncode:
                raise RuntimeError("Original x64 / native C guest-state mismatch in batch "+
                                   str(batches)+" exit "+str(check.returncode))
            arm=root/("native-guest-crc-"+str(batches)+".elf")
            cmd=["clang","--target=aarch64-unknown-linux-gnu",
                 "-fuse-ld=lld","-nostdlib","-static","-ffreestanding",
                 "-fno-builtin","-fno-stack-protector",*args,
                 "-Wl,-e,smoke","-Wl,-z,max-page-size=4096",
                 "-Wl,--build-id=none",str(source),"-o",str(arm)]
            result=subprocess.run(cmd,capture_output=True,text=True)
            if result.returncode:
                raise RuntimeError("Native AArch64 guest bridge compile failed: "+
                                   result.stderr[-3500:])
            executed=execute_arm64_elf(arm,instruction_budget=6000000,
                                       timeout_us=15000000)
            if not executed["return_to_sentinel"]:
                raise RuntimeError("Native guest CRC batch did not return")
            processed+=batch_bytes
            batches+=1
            source.unlink()
            host.unlink()
            arm.unlink()
    if processed!=len(file.content):
        raise ValueError("Native guest CRC batching left owned file unread")
    report={
        "original_sha256":INPUT_SHA,
        "native_bridge_header":"scripts/mxbikes_crc_cluster_bridge.h",
        "guest_state_struct":"mx_crt_cluster_state",
        "guest_memory_struct":"mx_cfg_memory",
        "original_x64_verified_chunk_count":len(owned),
        "independent_original_x64_variants":len(cases),
        "actual_owned_file_bytes_native_compared":len(file.content),
        "final_crc":hex(owned[-1]["bx"]),
        "native_c_guest_frame_checks_passed":True,
        "native_aarch64_independent_test_batches":batches,
        "actual_arm64_guest_frame_checks_passed":executed["return_to_sentinel"],
        "negative_guest_memory_and_state_cases":5,
        "full_game_native_dispatch_integrated":False,
        "original_game_engine_running":False,
        "ios_screen_rendered":False
    }
    report_dir.mkdir(parents=True,exist_ok=True)
    (report_dir/"original-crc-guest-bridge.json").write_text(json.dumps(report,indent=2)+"\n")
    lines=["# MX Bikes — native game guest-register CRC integration","",
      "- Reusable CRC dispatch through production guest ABI: **mx_crt_cluster_state**",
      "- Bounded guest memory: **mx_cfg_memory**",
      "- Original x64 vs native ARM64 owned file chunks: **"+
          str(len(owned))+"**",
      "- Original owned bytes compared: **"+str(len(file.content))+"**",
      "- Independent x64 test inputs: **"+str(len(cases))+"**",
      "- Executed ARM64 guest runtime batches: **"+str(batches)+"**",
      "- Invalid-state / memory rejection paths: **5**",
      "- Executed ARM64 ELF returned normally: **"+
          str(executed["return_to_sentinel"])+"**",
      "- Last original checksum: **"+hex(owned[-1]["bx"])+"**",
      "",
      "This is a callable guest ABI bridge, not yet continuous game startup.",
      "Native graphics, Steam runtime and first-screen boot remain unimplemented.",""]
    (report_dir/"original-crc-guest-bridge.md").write_text("\n".join(lines))
    print("\n".join(lines))
    return report

if __name__=="__main__":
    if len(sys.argv)!=4:
        raise SystemExit("usage: mxbikes_crc_cluster_native.py owned.exe owned.dll report-dir")
    run(Path(sys.argv[1]),Path(sys.argv[2]),Path(sys.argv[3]))
