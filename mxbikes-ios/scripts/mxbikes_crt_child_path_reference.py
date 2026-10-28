#!/usr/bin/env python3
"""Real x64 CRT child control-path reference, without recovered source export.

Executes authentic, SHA-pinned original x86-64 instructions privately using
bounded Unicorn memory with six explicitly injected MSVCR90 test doubles.
Captures basic-block coverage, externally observable effects and call order.
No native translation, real Windows CRT execution or iOS boot is claimed.
"""
from collections import Counter
from pathlib import Path
import hashlib
import json
import struct
import sys

from capstone import Cs, CS_ARCH_X86, CS_MODE_64
from unicorn import Uc, UC_ARCH_X86, UC_MODE_64, UC_HOOK_CODE
from unicorn.x86_const import (
    UC_X86_REG_RAX, UC_X86_REG_RBX, UC_X86_REG_RCX,
    UC_X86_REG_RDX, UC_X86_REG_R8, UC_X86_REG_RSP,
    UC_X86_REG_RIP, UC_X86_REG_RDI, UC_X86_REG_RSI,
    UC_X86_REG_R11, UC_X86_REG_EFLAGS,
)

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/"arm64-lab"))
from tools.pe_probe import PE
from mxbikes_first_callee_emu import import_slots
from mxbikes_crt_exception_callback_differential import SHA,BASE,SP,STACK,STOP

ENTRY=0x2ab734
END=0x2ab7e4
GLOBALS=(0xe4adb8,0xe4adb0)
SLOTS={
    0x321550:"_decode_pointer",
    0x321548:"_onexit",
    0x321508:"_encode_pointer",
    0x321540:"_lock",
    0x321538:"__dllonexit",
    0x321530:"_unlock",
}
THUNKS=(0x2aba1a,0x2aba20,0x2aba26)
STUB=0x600000000

def prepare(pe):
    if hashlib.sha256(pe.b).hexdigest()!=SHA:
        raise RuntimeError("Private original executable checksum mismatch")
    pdata,size=pe.directory(3)
    if not pdata or size%12:
        raise RuntimeError("Missing original Windows unwind records")
    records=struct.iter_unpack("<III",pe.read_rva(pdata,size))
    if not any(a==ENTRY and b==END for a,b,_ in records):
        raise RuntimeError("CRT child no longer exact original unwind entry")
    dis=Cs(CS_ARCH_X86,CS_MODE_64)
    decoded=list(dis.disasm(pe.read_rva(ENTRY,END-ENTRY),ENTRY))
    if len(decoded)!=39 or sum(x.size for x in decoded)!=END-ENTRY:
        raise RuntimeError("Original child no longer exactly 39 instructions")
    imports={rva:(dll.lower(),name) for rva,dll,name in import_slots(pe)}
    if any(imports.get(slot)!=("msvcr90.dll",name)
           for slot,name in SLOTS.items()):
        raise RuntimeError("MSVCR90 IAT identity changed")
    if any(pe.read_rva(thunk,2)!=b"\xff\x25" for thunk in THUNKS):
        raise RuntimeError("Expected bounded original x64 import JMP thunks")
    return {BASE+x.address for x in decoded}

def cases():
    for i in range(16):
        short=i<8
        yield {
            "short":short,
            "rcx":BASE+0x140000+i*0x20,
            "global0":0x55110000+i*17,
            "global1":0x22660000+i*19,
            "decode":(
                0xffffffffffffffff if short else 0x70003000+i*16,
                0x70004000+i*16,0x70005000+i*16),
            "encode":(
                0x11220000+i,0x55660000+i,0x99aa0000+i),
            "onexit":0 if i%3==0 else BASE+0x140000+i*0x20,
            "dll":0 if i%4==0 else BASE+0x140000+i*0x20,
            "update":(i%2==0),
            "start":0x70006000+i*16,
            "end":0x70007000+i*16,
        }

def original(pe,allowed,c):
    cpu=Uc(UC_ARCH_X86,UC_MODE_64)
    for page in ((BASE+ENTRY)&~4095,
                 (BASE+0x321000)&~4095,
                 (BASE+GLOBALS[0])&~4095):
        cpu.mem_map(page,0x1000)
    cpu.mem_map(STUB,0x1000)
    cpu.mem_map(STACK,0x10000)
    cpu.mem_write(BASE+ENTRY,pe.read_rva(ENTRY,END-ENTRY))
    for rva in THUNKS:
        cpu.mem_write(BASE+rva,pe.read_rva(rva,6))
    handlers={}
    for idx,(slot,name) in enumerate(SLOTS.items()):
        addr=STUB+16*idx
        handlers[addr]=name
        cpu.mem_write(addr,b"\xc3")
        cpu.mem_write(BASE+slot,struct.pack("<Q",addr))
    for index,rva in enumerate(GLOBALS):
        cpu.mem_write(BASE+rva,struct.pack("<Q",c["global"+str(index)]))
    cpu.mem_write(SP,struct.pack("<Q",STOP))
    cpu.reg_write(UC_X86_REG_RSP,SP)
    cpu.reg_write(UC_X86_REG_RIP,BASE+ENTRY)
    cpu.reg_write(UC_X86_REG_RCX,c["rcx"])
    cpu.reg_write(UC_X86_REG_RBX,0xaaaa0000)
    cpu.reg_write(UC_X86_REG_RAX,0xbbbb0000)
    visited=set()
    trace=[]
    calls=Counter()
    valid_thunks={BASE+rva for rva in THUNKS}

    def hook(emu,pc,size,context):
        if pc in allowed:
            visited.add(pc-BASE)
            return
        if pc in valid_thunks:
            return
        if pc not in handlers:
            raise RuntimeError("Original child escaped bounded code and stubs")
        name=handlers[pc]
        index=calls[name]
        calls[name]+=1
        rcx=emu.reg_read(UC_X86_REG_RCX)
        if emu.reg_read(UC_X86_REG_RSP)!=SP-0x30:
            raise RuntimeError("Original imported Win64 CALL stack ABI mismatch")
        trace.append(name)
        if name in ("_lock","_unlock"):
            if rcx!=8:
                raise RuntimeError("Unexpected original CRT lock number")
            return
        if name=="_decode_pointer":
            if index>=3:raise RuntimeError("Too many decoder calls")
            value=c["decode"][index]
        elif name=="_encode_pointer":
            if index>=3:raise RuntimeError("Too many encoder calls")
            value=c["encode"][index]
        elif name=="_onexit":
            value=c["onexit"]
        elif name=="__dllonexit":
            value=c["dll"]
            if c["update"]:
                addr=emu.reg_read(UC_X86_REG_RDX)
                addr2=emu.reg_read(UC_X86_REG_R8)
                if (addr,addr2)!=(SP+0x10,SP+0x18):
                    raise RuntimeError("Original DLL onexit pointer argument ABI moved")
                emu.mem_write(addr,struct.pack("<Q",c["start"]))
                emu.mem_write(addr2,struct.pack("<Q",c["end"]))
        else:
            raise RuntimeError("Unrecognized CRT boundary")
        emu.reg_write(UC_X86_REG_RAX,value)

    cpu.hook_add(UC_HOOK_CODE,hook)
    cpu.emu_start(BASE+ENTRY,STOP,timeout=3000000,count=128)
    expected=(
        ["_decode_pointer","_onexit"] if c["short"]
        else ["_decode_pointer","_lock","_decode_pointer","_decode_pointer",
              "_encode_pointer","__dllonexit","_encode_pointer",
              "_encode_pointer","_unlock"]
    )
    if trace!=expected or cpu.reg_read(UC_X86_REG_RIP)!=STOP or (
            cpu.reg_read(UC_X86_REG_RSP)!=SP+8):
        raise RuntimeError("Original CRT branch/call trace diverged")
    global_out=[
        struct.unpack("<Q",bytes(cpu.mem_read(BASE+rva,8)))[0]
        for rva in GLOBALS]
    expect_globals=(
        [c["global0"],c["global1"]] if c["short"]
        else [c["encode"][1],c["encode"][2]]
    )
    if global_out!=expect_globals:
        raise RuntimeError("Original CRT global-state side effects moved")
    expected_return=c["onexit"] if c["short"] else c["dll"]
    if cpu.reg_read(UC_X86_REG_RAX)!=expected_return:
        raise RuntimeError("Original CRT child return value changed")
    return {
        "path":"onexit-early" if c["short"] else "onexit-register",
        "instructions_visited":visited,
        "calls":trace,
        "return_nonzero":bool(expected_return),
        # Internal data for the private native differential. This exact x64
        # guest machine state is never included in public CI artifacts.
        "rax":cpu.reg_read(UC_X86_REG_RAX),
        "rbx":cpu.reg_read(UC_X86_REG_RBX),
        "rcx":cpu.reg_read(UC_X86_REG_RCX),
        "rdx":cpu.reg_read(UC_X86_REG_RDX),
        "r8":cpu.reg_read(UC_X86_REG_R8),
        "rdi":cpu.reg_read(UC_X86_REG_RDI),
        "rsi":cpu.reg_read(UC_X86_REG_RSI),
        "r11":cpu.reg_read(UC_X86_REG_R11),
        "rsp":cpu.reg_read(UC_X86_REG_RSP),
        "rip":cpu.reg_read(UC_X86_REG_RIP),
        "zf":int(bool(cpu.reg_read(UC_X86_REG_EFLAGS)&64)),
        "g0":global_out[0],
        "g1":global_out[1],
        "stack":bytes(cpu.mem_read(SP-128,256)),
    }

def run(exe,out):
    pe=PE(exe)
    allowed=prepare(pe)
    rows=[original(pe,allowed,c) for c in cases()]
    seen=set().union(*(r["instructions_visited"] for r in rows))
    if len(rows)!=16 or len(seen)!=39:
        raise RuntimeError("Original child fixture suite did not cover all 39 instructions")
    totals=Counter(x["path"] for x in rows)
    if totals!={"onexit-early":8,"onexit-register":8}:
        raise RuntimeError("Incorrect original branch coverage")
    report={
        "original_function_rva":hex(ENTRY),
        "original_instruction_count":39,
        "original_instruction_coverage":len(seen),
        "total_x64_path_fixtures":len(rows),
        "early_path_fixtures":totals["onexit-early"],
        "registration_path_fixtures":totals["onexit-register"],
        "branch_classes":sorted(totals),
        "unique_import_traces":[
            ["_decode_pointer","_onexit"],
            ["_decode_pointer","_lock","_decode_pointer","_decode_pointer",
             "_encode_pointer","__dllonexit","_encode_pointer",
             "_encode_pointer","_unlock"]],
        "real_original_x64_instructions_executed":True,
        "all_imported_services_synthetic":True,
        "native_host_or_ARM64_game_child_executed":False,
        "full_initializer_callbacks_executed":False,
        "no_proprietary_code_exported":True,
    }
    out.mkdir(parents=True,exist_ok=True)
    (out/"crt-child-x64-path-reference.json").write_text(
        json.dumps(report,indent=2)+"\n")
    summary="\n".join([
        "# MX Bikes original 39-instruction CRT child dynamic x64 reference","",
        "- Original child original x64 instruction coverage: **"+
        str(len(seen))+"/39**",
        "- Private original x64 fixtures passed: **"+str(len(rows))+"/16**",
        "- Short onexit path: **8**; long registration path: **8**",
        "- Deterministic import trace, final guest return/stack and two",
        "  CRT global outputs were checked on both paths","",
        "**Original machine instructions only; imported MSVCR90 APIs are",
        "test doubles. No translated ARM64 child, DLL execution, engine",
        "startup or iOS gameplay is claimed.**",""])
    (out/"crt-child-x64-path-reference.md").write_text(summary)
    print(summary)

if __name__=="__main__":
    if len(sys.argv)!=3:raise SystemExit("usage: script.py original-private-exe private-report-dir")
    run(Path(sys.argv[1]),Path(sys.argv[2]))
