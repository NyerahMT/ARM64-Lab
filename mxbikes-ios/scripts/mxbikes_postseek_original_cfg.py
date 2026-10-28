#!/usr/bin/env python3
"""Map ORIGINAL SHA-verified Win64 CRT CALL/return/branch sequence through CRC.

Uses only owned steam_api64.dll read-only data and allows original x64 CPU
to run until first true checksum loop exit at 0x1306A9. Snapshots original
guest states at real CRT callsites, returns and branch transfers. Does not
execute Windows DLLs, Steam initialization or fabricate Steam results.
No DLL bytes, guest stack contents or original executable code archived.
"""
from pathlib import Path
import hashlib,json,sys
from capstone import Cs,CS_ARCH_X86,CS_MODE_64
from unicorn import UC_HOOK_CODE,UcError
from unicorn.x86_const import (UC_X86_REG_RIP,UC_X86_REG_RAX,
 UC_X86_REG_RBX,UC_X86_REG_RCX,UC_X86_REG_RDX,UC_X86_REG_R8,
 UC_X86_REG_R9,UC_X86_REG_RSI,UC_X86_REG_RDI,
 UC_X86_REG_RSP,UC_X86_REG_EFLAGS,UC_X86_REG_R12)
import mxbikes_main_joined_callee_native as joined
import mxbikes_steam_fopen_result_probe as bootstrap
from mxbikes_owned_file_crt import OwnedReadOnlyFile,ReadOnlyCRT,FILE_HANDLE,GuestServiceBlocked
from mxbikes_startup_batch_runner import install_import_dispatch,symbol_is_supported
from mxbikes_whole_game_map import INPUT_SHA
BASE=joined.BASE
START=0x1305d9
STATIC_END=0x1306b8
OBSERVE=frozenset((0x1305d9,0x1305de,0x1305e6,0x1305f5,
                   0x130610,0x130630,0x130641,0x13065f,
                   0x130666,0x130670,0x1306a9,0x1306ab))
MAX_EVENTS=100
MAX_INSTRUCTIONS=90000

def snapshot(uc,rva):
    flags=uc.reg_read(UC_X86_REG_EFLAGS)
    return {"rva":hex(rva),
        **{x:hex(uc.reg_read(reg)) for x,reg in (
          ("rax",UC_X86_REG_RAX),("rbx",UC_X86_REG_RBX),
          ("rcx",UC_X86_REG_RCX),("rdx",UC_X86_REG_RDX),
          ("r8",UC_X86_REG_R8),("r9",UC_X86_REG_R9),
          ("rsi",UC_X86_REG_RSI),("rdi",UC_X86_REG_RDI),
          ("rsp",UC_X86_REG_RSP),("r12",UC_X86_REG_R12))},
        "zf":int(bool(flags&64)),"sf":int(bool(flags&128)),
        "cf":int(bool(flags&1))}

def run(exe,dll,out):
    from tools.pe_probe import PE
    pe=PE(exe)
    if hashlib.sha256(pe.b).hexdigest()!=INPUT_SHA:
        raise ValueError("Original owned Win64 SHA mismatch")
    file=OwnedReadOnlyFile.from_private_path(
        dll,json.loads((out/"owned-steam-file-manifest.json").read_text())["owned_dll_size_bytes"])
    _,uc=bootstrap.original_case(
        pe,0,FILE_HANDLE,0x1305c0,0x1305b6,return_cpu=True)
    imported=install_import_dispatch(uc,pe)
    decoder=Cs(CS_ARCH_X86,CS_MODE_64)
    code=list(decoder.disasm(pe.read_rva(START,STATIC_END-START),START))
    if not code or code[0].address!=START or code[-1].address+code[-1].size>STATIC_END:
        raise ValueError("Original CRT start disassembly did not align")
    instruction_forms=[{"rva":hex(i.address),
                        "mnemonic":i.mnemonic,"operands":i.op_str}
                       for i in code]
    stream=ReadOnlyCRT(file)
    events=[]
    calls=[]
    stop={"status":None,"reason":None}
    counts={"guest_instructions":0}
    def on_code(u,pc,size,ctx):
        counts["guest_instructions"]+=1
        if counts["guest_instructions"]>MAX_INSTRUCTIONS:
            stop.update(status="budget",reason="original guest step limit")
            u.emu_stop();return
        if pc in imported:
            lib,symbol=imported[pc]
            if not symbol_is_supported(lib,symbol):
                stop.update(status="unsupported_import",
                            reason=lib+"!"+symbol)
                u.emu_stop();return
            try:
                rc=stream.dispatch(u,symbol,
                    u.reg_read(UC_X86_REG_RCX),
                    u.reg_read(UC_X86_REG_RDX),
                    u.reg_read(UC_X86_REG_R8),
                    u.reg_read(UC_X86_REG_R9))
            except GuestServiceBlocked as exc:
                stop.update(status="blocked_service",reason=str(exc))
                u.emu_stop();return
            u.reg_write(UC_X86_REG_RAX,rc&0xffffffffffffffff)
            if len(calls)<MAX_EVENTS:
                calls.append({"import":lib+"!"+symbol,
                              "return_value":hex(rc&0xffffffffffffffff),
                              "file_cursor":file.cursor})
            return
        rva=pc-BASE
        if rva==0x1306a9:
            events.append(snapshot(u,rva))
            stop.update(status="reached_first_original_crc_chunk_exit",
                        reason=None)
            u.emu_stop();return
        if rva in OBSERVE and len(events)<MAX_EVENTS:
            # Record first time per checkpoint, don't log repeated CRC bytes.
            if not any(x["rva"]==hex(rva) for x in events):
                events.append(snapshot(u,rva))
    uc.hook_add(UC_HOOK_CODE,on_code)
    if uc.reg_read(UC_X86_REG_RIP)!=BASE+0x1305c0:
        raise ValueError("Native seed does not start at original fopen success")
    try:
        uc.emu_start(BASE+0x1305c0,0,timeout=10_000_000,count=MAX_INSTRUCTIONS)
    except UcError as exc:
        stop.update(status="original_guest_fault",reason=type(exc).__name__)
    if stop["status"]!="reached_first_original_crc_chunk_exit":
        raise ValueError("Original x64 failed to reach first authentic CRC boundary: "+str(stop))
    if sum("fread" in x["import"] for x in calls)!=1 or file.cursor!=1000:
        raise ValueError("Original first fread import count or file cursor diverged")
    out.mkdir(parents=True,exist_ok=True)
    report={
      "sha_verified_original":True,
      "x64_original_static_instructions":instruction_forms,
      "original_x64_first_chunk_checkpoints":events,
      "original_x64_first_chunk_imports":calls,
      "original_x64_executed_steps_through_first_crc_exit":counts["guest_instructions"],
      "original_first_read_bytes":stream.bytes_returned,
      "stop":stop,
      "native_aarch64_execution":False,
      "engine_booted":False,
    }
    (out/"original-file-postseek-cfg.json").write_text(json.dumps(report,indent=2)+"\n")
    lines=["# MX Bikes original x64 post-fseek startup control-flow","",
      "- Original x64 first 1000-byte CRC chunk reached: **YES**",
      "- Executed guest instructions before boundary: **"+
         str(counts["guest_instructions"])+"**",
      "- Read-only file service calls: **"+
         str([x["import"] for x in calls])+"**",
      "- First original checksum loop exit: **0x1306A9**","",
      "## Original x64 CALL/branch and setup instructions"]
    lines.extend("- "+x["rva"]+": "+x["mnemonic"]+" "+x["operands"]
                 for x in instruction_forms)
    lines.extend(["","## Dynamic original guest execution checkpoint PCs"])
    lines.extend("- "+x["rva"]+" RAX="+x["rax"]+" RCX="+x["rcx"]+
                 " RDX="+x["rdx"]+" R8="+x["r8"]+" RBX="+x["rbx"]
                 for x in events)
    lines.extend(["","No ARM64 execution in this map; no Steam auth/engine/rendering.",""])
    (out/"original-file-postseek-cfg.md").write_text("\n".join(lines))
    print("\n".join(lines))
    return report
if __name__=="__main__":
    if len(sys.argv)!=4:
        raise SystemExit("usage: mxbikes_postseek_original_cfg.py original.exe dll report")
    run(Path(sys.argv[1]),Path(sys.argv[2]),Path(sys.argv[3]))
