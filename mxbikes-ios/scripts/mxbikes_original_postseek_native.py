#!/usr/bin/env python3
"""Native AArch64 original post-fseek Win64 CALL/branch CFG to first CRC exit.

SHA-pinned original x64 CPU is an independent oracle for two outcomes:
 genuine complete owned Steam DLL -> 1000-byte original checksum exit;
 truncated read-only fixture -> original fclose / size-mismatch branch.
Portable native code uses the existing Win64 guest ABI, bounded guest
memory, typed FILE* adapter and verified original CRC implementation.
It does not execute any Windows/Steam DLL or skip game license checks.
"""
import hashlib,json,subprocess,sys,tempfile
from pathlib import Path
from unicorn import UC_HOOK_CODE,UcError
from unicorn.x86_const import (
 UC_X86_REG_RIP,UC_X86_REG_RSP,UC_X86_REG_RAX,UC_X86_REG_RBX,
 UC_X86_REG_RCX,UC_X86_REG_RDX,UC_X86_REG_R8,UC_X86_REG_R9,
 UC_X86_REG_RSI,UC_X86_REG_RDI,UC_X86_REG_R11,UC_X86_REG_R12,UC_X86_REG_RBP,
 UC_X86_REG_R13,UC_X86_REG_R14,UC_X86_REG_EFLAGS,
)
import mxbikes_main_joined_callee_native as joined
import mxbikes_steam_fopen_result_probe as fopen
import mxbikes_crc_native as crc
from mxbikes_startup_batch_runner import install_import_dispatch,symbol_is_supported
from mxbikes_owned_file_crt import OwnedReadOnlyFile,ReadOnlyCRT,FILE_HANDLE,GuestServiceBlocked
from mxbikes_whole_game_map import INPUT_SHA
from tools.import_aot_smoke import execute_arm64_elf

ROOT=Path(__file__).resolve().parents[1]
BASE=joined.BASE
START=0x1305d9
CRC_EXIT=0x1306a9
SIZE_FAIL=0x13072e
REGS=[
 ("rax",UC_X86_REG_RAX),("rbx",UC_X86_REG_RBX),
 ("rcx",UC_X86_REG_RCX),("rdx",UC_X86_REG_RDX),
 ("r8",UC_X86_REG_R8),("r9",UC_X86_REG_R9),
 ("rsi",UC_X86_REG_RSI),("rdi",UC_X86_REG_RDI),
 ("rsp",UC_X86_REG_RSP),("r11",UC_X86_REG_R11),("rbp",UC_X86_REG_RBP),
 ("r12",UC_X86_REG_R12),("r13",UC_X86_REG_R13),
 ("r14",UC_X86_REG_R14)
]

def register_snapshot(uc):
    result={key:uc.reg_read(reg) for key,reg in REGS}
    result["rip"]=uc.reg_read(UC_X86_REG_RIP)
    flags=uc.reg_read(UC_X86_REG_EFLAGS)
    for field,mask in (("zf",64),("sf",128),("cf",1)):
        result[field]=int(bool(flags&mask))
    return result

def original_x64(pe,content,valid):
    _,uc=fopen.original_case(
        pe,0,FILE_HANDLE,0x1305c0,0x1305b6,return_cpu=True)
    imports=install_import_dispatch(uc,pe)
    stream=OwnedReadOnlyFile(content)
    crt=ReadOnlyCRT(stream)
    uc.emu_start(BASE+0x1305c0,BASE+START,timeout=3000000,count=5)
    if uc.reg_read(UC_X86_REG_RIP)!=BASE+START:
        raise ValueError("Original x64 did not reach authentic first fseek CALL")
    incoming=register_snapshot(uc)
    stop=CRC_EXIT if valid else SIZE_FAIL
    caught=[]
    def hook(u,pc,size,ctx):
        if pc==BASE+stop:
            caught.append("reached_target")
            u.emu_stop()
            return
        service=imports.get(pc)
        if service is not None:
            lib,name=service
            if not symbol_is_supported(lib,name):
                raise ValueError("Unsupported original guest service "+lib+"!"+name)
            value=crt.dispatch(u,name,
                u.reg_read(UC_X86_REG_RCX),u.reg_read(UC_X86_REG_RDX),
                u.reg_read(UC_X86_REG_R8),u.reg_read(UC_X86_REG_R9))
            u.reg_write(UC_X86_REG_RAX,value&0xffffffffffffffff)
    uc.hook_add(UC_HOOK_CODE,hook)
    try:uc.emu_start(BASE+START,0,timeout=10000000,count=90000)
    except UcError as exc:
        raise ValueError("Original x64 reference execution fault "+str(exc)) from exc
    if not caught or uc.reg_read(UC_X86_REG_RIP)!=BASE+stop:
        raise ValueError("Original x64 failed postseek outcome "+
                         hex(uc.reg_read(UC_X86_REG_RIP)-BASE))
    observed=register_snapshot(uc)
    if valid:
        expected={"fseek":2,"ftell":1,"fread":1}
        if crt.calls!=expected or crt.bytes_returned!=1000 or not stream.open:
            raise ValueError("Original x64 CRC input service count changed")
        saved={}
        for label,disp in (("saved_rbp",0x448),("saved_rdi",0x458),
                           ("saved_r13",0x428),("saved_r14",0x420)):
            saved[label]=int.from_bytes(uc.mem_read(incoming["rsp"]+disp,8),"little")
        if (saved["saved_rbp"]!=incoming["rbp"] or
            saved["saved_rdi"]!=incoming["rdi"] or
            saved["saved_r13"]!=incoming["r13"] or
            saved["saved_r14"]!=incoming["r14"]):
            raise ValueError("Original saved callee registers changed")
    else:
        expected={"fseek":2,"ftell":1,"fclose":1}
        if crt.calls!=expected or stream.open:
            raise ValueError("Original x64 wrong-size CRT failure path changed")
    return {"incoming":incoming,"expected":observed,
            "file_calls":dict(crt.calls),"original_bytes_read":crt.bytes_returned,
            "original_file_closed":not stream.open}

def byte_list(buffer):
    return ",".join(str(b) for b in buffer)

def c_fixture(rows,original,wrong):
    # Verify all original game 64-bit and flags at the actual transfer PC.
    def guest_seed(row,tag):
        before=row["incoming"];after=row["expected"]
        text=[
          " { mx_crt_cluster_state state={0};",
          "   mxb_postseek_extra extra={0};",
          "   mxb_readonly_file f={0};",
          "   static uint8_t guest_stack[8192U];",
          "   mx_cfg_region region={UINT64_C("+str(before["rsp"]-0x800)+
                   "),guest_stack,sizeof(guest_stack)};",
          "   mx_cfg_memory mem={&region,1U};",
          "   if(!mxb_file_init(&f,"+tag+",sizeof("+tag+"),0U))return 1;",
        ]
        for reg in ("rip","rsp","rax","rbx","rcx","rdx",
                    "r8","r9","rsi","rdi","zf","sf","cf"):
            text.append("   state."+reg+"=UINT64_C("+str(before[reg])+");")
        for reg in ("rbp","r12","r13","r14"):
            text.append("   extra."+reg+"=UINT64_C("+str(before[reg])+");")
        text.append("   int status=mxb_postseek_native_first_read(&state,&mem,&f,&extra);")
        text.append("   if(status!="+("1" if tag=="valid_dll" else "2")+")return 2;")
        for reg in ("rip","rsp","rax","rbx","rcx","rdx","r8","r9",
                    "rsi","rdi","zf","sf","cf"):
            text.append("   if(state."+reg+"!=UINT64_C("+
                        str(after[reg])+"))return 3;")
        if tag=="valid_dll":
            text.extend([
                "   if(extra.original_crt_calls!=4U||",
                "      f.seek_calls!=2U||f.tell_calls!=1U||",
                "      f.read_calls!=1U||f.total_bytes_read!=1000U||",
                "      f.position!=1000U||!f.is_open)return 4;",
            ])
            for label,disp,from_reg in (
                 ("saved_rbp",0x448,"rbp"),
                 ("saved_rdi",0x458,"rdi"),
                 ("saved_r13",0x428,"r13"),
                 ("saved_r14",0x420,"r14")):
                text.extend([
                "   { uint64_t value=0U;",
                "     if(!mx_cfg_transfer(&mem,state.rsp+"+str(disp)+"U,",
                "         &value,8U,0)||value!=UINT64_C("+
                           str(before[from_reg])+"))return 5;}",
                ])
            text.append(
                "   for(uint32_t i=0U;i<1000U;i++)"
                " if(guest_stack[0x820U+i]!=valid_dll[i])return 6;")
        else:
            text.extend([
                "   if(extra.original_crt_calls!=4U||f.close_calls!=1U||",
                "      f.read_calls!=0U||f.position!=0U||f.is_open)return 7;",
            ])
        text.append(" }")
        return text
    source=[
      "#include <stdint.h>",
      '#include "mxbikes_original_postseek_native.h"',
      "static const uint8_t valid_dll["+str(len(original))+"]={"+
          byte_list(original)+"};",
      "static const uint8_t short_dll["+str(len(wrong))+"]={"+
          byte_list(wrong)+"};",
      "int smoke(void){",
    ]
    source.extend(guest_seed(rows[0],"valid_dll"))
    source.extend(guest_seed(rows[1],"short_dll"))
    source.extend([" return 0;","}",
                   "#ifdef HOST","int main(void){return smoke();}","#endif"])
    return "\n".join(source)+"\n"

def run(exe,dll,out):
    from tools.pe_probe import PE
    pe=PE(exe)
    if hashlib.sha256(pe.b).hexdigest()!=INPUT_SHA:
        raise ValueError("Original private game exe changed")
    crc.original_form(pe)
    doc=json.loads((out/"original-file-postseek-cfg.json").read_text())
    rows=doc["x64_original_static_instructions"]
    forms=[(a["rva"],a["mnemonic"],a["operands"]) for a in rows]
    required={
        ("0x1305d9","call","0x2aaf28"),
        ("0x1305e1","call","0x2aaef8"),
        ("0x1305f0","call","0x2aaf28"),
        ("0x1305fc","je","0x130610"),
        ("0x130601","call","0x2aaec8"),
        ("0x13065a","call","0x2aaee6"),
        ("0x130664","je","0x1306a9")
    }
    if not required.issubset(set(forms)):
        raise ValueError("Real guest binary CALL/Jcc schedule no longer matches")
    manifest=json.loads((out/"owned-steam-file-manifest.json").read_text())
    if (manifest.get("steam_api64_dll_present") is not True or
        manifest.get("matching_owned_dll_count")!=1):
        raise ValueError("No authentic owned Steam DLL")
    source=OwnedReadOnlyFile.from_private_path(
        dll,manifest.get("owned_dll_size_bytes")).content
    short=source[:2000]
    refs=[original_x64(pe,source,True),original_x64(pe,short,False)]
    text=c_fixture(refs,source,short)
    with tempfile.TemporaryDirectory(prefix="mxb-native-actual-x64-postseek-") as td:
        work=Path(td)
        src=work/"private-original-postseek.c"
        src.write_text(text)
        opts=["-O2","-std=c11","-Wall","-Wextra","-Werror",
              "-I",str(ROOT/"scripts"),
              "-I",str(ROOT/"arm64-lab"/"runtime")]
        host=work/"native-host"
        cmd=["cc",*opts,"-DHOST",str(src),"-o",str(host)]
        comp=subprocess.run(cmd,capture_output=True,text=True)
        if comp.returncode:
            raise RuntimeError("Original postseek native compile: "+comp.stderr[-4000:])
        check=subprocess.run([str(host)],capture_output=True,text=True)
        if check.returncode:
            raise RuntimeError("Original x64 and native host postseek mismatch exit "+
                               str(check.returncode))
        arm=work/"original-postseek-aarch64.elf"
        cmd=["clang","--target=aarch64-unknown-linux-gnu",
          "-fuse-ld=lld","-nostdlib","-static","-ffreestanding",
          "-fno-builtin","-fno-stack-protector",*opts,
          "-Wl,-e,smoke","-Wl,-z,max-page-size=4096",
          "-Wl,--build-id=none",str(src),"-o",str(arm)]
        result=subprocess.run(cmd,capture_output=True,text=True)
        if result.returncode:
            raise RuntimeError("Original postseek ARM64 build: "+result.stderr[-4000:])
        outcome=execute_arm64_elf(arm,instruction_budget=6000000,
                                  timeout_us=15000000)
    result={
        "sha_verified_original":True,
        "native_executed_from_original_rva":hex(START),
        "good_owned_file_native_exit_rva":hex(CRC_EXIT),
        "wrong_size_native_error_rva":hex(SIZE_FAIL),
        "original_guest_controls_and_imports_verified":len(required),
        "original_x64_differential_outcomes":2,
        "successful_native_guest_crc_bytes":1000,
        "successful_file_length_gate_bytes":len(source),
        "native_host_outcomes_passed":2,
        "native_aarch64_outcomes_passed":2,
        "native_aarch64_elf_returned_to_sentinel":outcome["return_to_sentinel"],
        "native_wiring_from_prior_original_fopen_prefix":False,
        "full_original_file_loop_continuous_from_entry":False,
        "steam_client_or_engine_started":False,
    }
    out.mkdir(parents=True,exist_ok=True)
    (out/"original-postseek-native-cfg.json").write_text(json.dumps(result,indent=2)+"\n")
    lines=["# MX Bikes — original file-startup CALL/branch paths running on AArch64","",
        "- Original SHA-pinned CALL/Jcc targets checked: **"+str(len(required))+"**",
        "- Native execute from genuine original 0x1305D9 entry: **PASS**",
        "- Real file-size gate (250,656 bytes) -> first 1000-byte native CRC: **PASS**",
        "- Wrong-size original failure -> actual close and 0x13072E: **PASS**",
        "- Original x64 guest register and flags differential outcomes: **2/2**",
        "- Original guest saved Win64 callee registers and read-buffer bytes: **PASS**",
        "- Actual AArch64 ELF returned normally: **"+str(outcome["return_to_sentinel"])+"**",
        "",
        "Original x64 game glue is translated through first fread/CRC.",
        "Later CRC chunk CFG and connection from earlier native startup prefix",
        "remain separate. No original Steam client, engine, graphics or iOS menu.",""]
    (out/"original-postseek-native-cfg.md").write_text("\n".join(lines))
    print("\n".join(lines))
    return result

if __name__=="__main__":
    if len(sys.argv)!=4:
        raise SystemExit("usage: postseek_native.py original.exe steam.dll reports")
    run(Path(sys.argv[1]),Path(sys.argv[2]),Path(sys.argv[3]))
