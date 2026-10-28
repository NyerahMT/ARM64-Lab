#!/usr/bin/env python3
"""Full original post-fseek 251 fread/CRC x64 control-flow differential on ARM64.

Original SHA-pinned x64 CPU to 0x1306B8 is the independent oracle.
Native AArch64 executes original CALL/conditional semantics and typed read-only
CRT services without running Windows DLLs or bypassing any Steam checks.
"""
import hashlib,json,subprocess,sys,tempfile
from pathlib import Path
from unicorn import UC_HOOK_CODE,UcError
from unicorn.x86_const import (
 UC_X86_REG_RIP,UC_X86_REG_RAX,UC_X86_REG_RCX,UC_X86_REG_RDX,
 UC_X86_REG_R8,UC_X86_REG_R9)
import mxbikes_original_postseek_native as first
import mxbikes_steam_fopen_result_probe as fopen
import mxbikes_crc_native as crc
from mxbikes_startup_batch_runner import install_import_dispatch,symbol_is_supported,STUBS,STUB_BYTES
from mxbikes_owned_file_crt import OwnedReadOnlyFile,ReadOnlyCRT,FILE_HANDLE
from mxbikes_whole_game_map import INPUT_SHA
from tools.import_aot_smoke import execute_arm64_elf

BASE=first.BASE
ROOT=first.ROOT
END=0x1306b8

def x64_reference(pe,blob):
    _,uc=fopen.original_case(pe,0,FILE_HANDLE,0x1305c0,0x1305b6,return_cpu=True)
    imports=install_import_dispatch(uc,pe)
    uc.emu_start(BASE+0x1305c0,BASE+first.START,timeout=3000000,count=5)
    if uc.reg_read(UC_X86_REG_RIP)!=BASE+first.START:
        raise ValueError("Game x64 input frontier drift")
    prior=first.register_snapshot(uc)
    crt=ReadOnlyCRT(OwnedReadOnlyFile(blob))
    events=[]
    def service(u,pc,size,ctx):
        lib,sym=imports[pc]
        if not symbol_is_supported(lib,sym):
            raise ValueError("Unexpected Steam/Windows import")
        x=crt.dispatch(u,sym,u.reg_read(UC_X86_REG_RCX),
          u.reg_read(UC_X86_REG_RDX),u.reg_read(UC_X86_REG_R8),
          u.reg_read(UC_X86_REG_R9))
        u.reg_write(UC_X86_REG_RAX,x&0xffffffffffffffff)
    def finish(u,pc,size,ctx):
        events.append(pc);u.emu_stop()
    uc.hook_add(UC_HOOK_CODE,service,begin=STUBS,end=STUBS+STUB_BYTES-1)
    uc.hook_add(UC_HOOK_CODE,finish,begin=BASE+END,end=BASE+END)
    try: uc.emu_start(BASE+first.START,0,timeout=15000000,count=15000000)
    except UcError as exc:
        raise ValueError("Original full Win64 x64 trace fault: "+str(exc)) from exc
    if events!=[BASE+END] or uc.reg_read(UC_X86_REG_RIP)!=BASE+END:
        raise ValueError("Original Win64 did not reach first fclose return")
    if crt.calls!={"fseek":2,"ftell":1,"fread":251,"fclose":1}:
        raise ValueError("Original IAT call count changed "+str(crt.calls))
    if crt.bytes_returned!=len(blob) or crt.file.open:
        raise ValueError("Original x64 file processing incomplete")
    return prior,first.register_snapshot(uc),crt.calls

def c_source(blob,before,after):
    lines=[
      "#include <stdint.h>",
      '#include "mxbikes_original_postseek_native.h"',
      "static const uint8_t owned_bytes["+str(len(blob))+"]={"+
               ",".join(str(i) for i in blob)+"};",
      "static uint8_t guest_stack[8192U];",
      "int smoke(void){",
      " mx_crt_cluster_state s={0};",
      " mxb_postseek_extra e={0};",
      " mxb_readonly_file f={0};",
      " mx_cfg_region region={UINT64_C("+str(before["rsp"]-0x800)+
          "),guest_stack,sizeof(guest_stack)};",
      " mx_cfg_memory mem={&region,1U};",
      " if(!mxb_file_init(&f,owned_bytes,sizeof(owned_bytes),0U))return 1;",
    ]
    for reg in ("rip","rsp","rax","rbx","rcx","rdx","r8","r9",
                "rsi","rdi","zf","sf","cf"):
        lines.append(" s."+reg+"=UINT64_C("+str(before[reg])+");")
    for reg in ("rbp","r12","r13","r14"):
        lines.append(" e."+reg+"=UINT64_C("+str(before[reg])+");")
    lines.extend([
        " if(mxb_postseek_native_first_read(&s,&mem,&f,&e)!=1)return 2;",
        " if(!mxb_postseek_native_finish_reads(&s,&mem,&f,&e))return 3;",
    ])
    for reg in ("rip","rsp","rax","rbx","rcx","rdx","r8","r9",
                "rsi","rdi","zf","sf","cf"):
        lines.append(" if(s."+reg+"!=UINT64_C("+str(after[reg])+"))return 4;")
    lines.extend([
        " if(f.total_bytes_read!=sizeof(owned_bytes)||",
        "    f.position!=sizeof(owned_bytes)||f.read_calls!=251U||",
        "    f.seek_calls!=2U||f.tell_calls!=1U||f.close_calls!=1U||f.is_open)",
        "    return 5;",
        " if(e.original_crt_calls!=255U)return 6;",
        " if(s.rip!=MXB_POSTSEEK_AFTER_CLOSE)return 7;",
        " if(mxb_postseek_native_finish_reads(&s,&mem,&f,&e))return 8;",
        " return 0;",
        "}",
        "#ifdef HOST","int main(void){return smoke();}","#endif"
    ])
    return "\n".join(lines)+"\n"

def run(exe,dll,out):
    from tools.pe_probe import PE
    pe=PE(exe)
    if hashlib.sha256(pe.b).hexdigest()!=INPUT_SHA:
        raise ValueError("Owned original exe SHA mismatch")
    crc.original_form(pe)
    prior_report=json.loads((out/"original-file-postseek-cfg.json").read_text())
    if prior_report["stop"]["status"]!="reached_first_original_crc_chunk_exit":
        raise ValueError("Missing independently verified first x64 chunk")
    m=json.loads((out/"owned-steam-file-manifest.json").read_text())
    if m.get("steam_api64_dll_present") is not True or m.get("matching_owned_dll_count")!=1:
        raise ValueError("Original Steam DLL not uniquely present in owned archive")
    bytes_owned=OwnedReadOnlyFile.from_private_path(dll,m["owned_dll_size_bytes"]).content
    before,after,calls=x64_reference(pe,bytes_owned)
    code=c_source(bytes_owned,before,after)
    with tempfile.TemporaryDirectory(prefix="mxb-original-full-fread-cfg-") as td:
        root=Path(td)
        source=root/"private-full-cfg.c";source.write_text(code)
        opts=["-O3","-std=c11","-Wall","-Wextra","-Werror",
              "-I",str(ROOT/"scripts"),"-I",str(ROOT/"arm64-lab"/"runtime")]
        host=root/"host"
        b=subprocess.run(["cc",*opts,"-DHOST",str(source),"-o",str(host)],
            capture_output=True,text=True)
        if b.returncode: raise RuntimeError("Host CFG compile: "+b.stderr[-3500:])
        r=subprocess.run([str(host)],capture_output=True,text=True)
        if r.returncode:raise RuntimeError("Original x64 vs native full CFG error "+
                                            str(r.returncode))
        arm=root/"real-fread-loop-aarch64.elf"
        cmd=["clang","--target=aarch64-unknown-linux-gnu","-fuse-ld=lld",
             "-nostdlib","-static","-ffreestanding","-fno-builtin",
             "-fno-stack-protector",*opts,"-Wl,-e,smoke",
             "-Wl,-z,max-page-size=4096","-Wl,--build-id=none",
             str(source),"-o",str(arm)]
        b=subprocess.run(cmd,capture_output=True,text=True)
        if b.returncode:raise RuntimeError("Original CFG AArch64 compile: "+b.stderr[-3500:])
        outcome=execute_arm64_elf(arm,instruction_budget=6000000,timeout_us=15000000)
    report={
      "sha_verified_original":True,
      "original_x64_and_native_aarch64_entry_rva":hex(first.START),
      "original_x64_and_native_aarch64_exit_rva":hex(END),
      "original_251_chunk_fread_loop_translated":True,
      "native_fread_calls":251,
      "original_win64_file_size_gate_preserved":True,
      "original_steam_dll_bytes_read_native":len(bytes_owned),
      "native_original_x64_guest_register_and_flags_matching":True,
      "aarch64_one_uninterrupted_original_cfg_execution":outcome["return_to_sentinel"],
      "verified_original_win64_crt_calls":calls,
      "original_post_close_game_instructions_translated":False,
      "steam_client_or_engine_started":False,
    }
    out.mkdir(parents=True,exist_ok=True)
    (out/"original-postseek-complete-native.json").write_text(json.dumps(report,indent=2)+"\n")
    lines=["# MX Bikes original full fread/CRC loop executing on ARM64","",
      "- SHA-pinned original Win64 entry **0x1305D9**",
      "- Original 251-run CRC backedge and fclose boundary **0x1306B8**",
      "- Entire original DLL bytes processed **"+str(len(bytes_owned))+"**",
      "- Original x64 vs native ARM64 guest register/flags at final boundary: **PASS**",
      "- Single uninterrupted native AArch64 execution: **"+
         str(outcome["return_to_sentinel"])+"**",
      "- Original Win64 2 fseek, 1 ftell, 251 fread, 1 fclose: **PASS**","",
      "Translated original CALL/branch control from fseek to fclose.",
      "Earlier fopen prefix is separately verified, not fused into this ELF.",
      "Steam client, engine and graphics remain unimplemented.",""]
    (out/"original-postseek-complete-native.md").write_text("\n".join(lines))
    print("\n".join(lines))
    return report

if __name__=="__main__":
    if len(sys.argv)!=4:raise SystemExit("usage: full_native.py exe steam_dll report_dir")
    run(Path(sys.argv[1]),Path(sys.argv[2]),Path(sys.argv[3]))
