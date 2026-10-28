#!/usr/bin/env python3
"""Execute the first authentic MX Bikes game-entry x64 basic block privately.

This is a deterministic *diagnostic* bridge from CRT main-call handoff to the
game entry, not an ARM64 port. Stops before the first original branch/CALL/RET;
unrecognized instructions, memory faults and jumps away fail closed. Reports
only addresses/register metadata, never game code or original file contents.
"""
from pathlib import Path
import hashlib
import json
import struct
import sys

from capstone import Cs,CS_ARCH_X86,CS_MODE_64,CS_GRP_CALL,CS_GRP_JUMP,CS_GRP_RET
from capstone.x86 import X86_OP_IMM
from unicorn import (
    Uc, UcError, UC_ARCH_X86, UC_MODE_64,
    UC_HOOK_CODE, UC_HOOK_MEM_INVALID, UC_HOOK_MEM_WRITE
)
from unicorn.x86_const import (
    UC_X86_REG_GS_BASE,UC_X86_REG_RIP,UC_X86_REG_RSP,
    UC_X86_REG_RAX,UC_X86_REG_RBX,UC_X86_REG_RCX,UC_X86_REG_RDX,
    UC_X86_REG_R8,UC_X86_REG_R9,UC_X86_REG_RDI,UC_X86_REG_RSI,
    UC_X86_REG_EFLAGS
)
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/"arm64-lab"))
from tools.pe_probe import PE

EXE_SHA="4ae7de3854b4d0a18271679fb57a1f2fdf0b21804417b85dd82055078ea123b6"
BASE=0x140000000
MAIN=0x136710
STACK=0x700000000
TEB=0x720000000
MAX_BLOCK_BYTES=256
MAX_BLOCK_INSNS=40
MAX_MAPPED_IMAGE=128*1024*1024

def align4k(x):
    return (x+4095)&~4095

def probe(executable,include_private_reference=False):
    pe=PE(executable)
    if hashlib.sha256(pe.b).hexdigest()!=EXE_SHA:
        raise RuntimeError("Original executable SHA mismatch")
    pdata,size=pe.directory(3)
    if not pdata or not size or size%12:
        raise RuntimeError("Original x64 unwind directory missing or corrupt")
    intervals=[(a,b) for a,b,_ in struct.iter_unpack("<III",pe.read_rva(pdata,size))
               if a<=MAIN<b]
    if len(intervals)!=1:
        raise RuntimeError("Expected exactly one unwind-backed main-entry interval")
    begin,finish=intervals[0]
    if MAIN-begin>8192 or finish-MAIN>16384:
        raise RuntimeError("Main-entry unwind interval outside bounded scope")
    cap=min(finish-MAIN,MAX_BLOCK_BYTES)
    dis=Cs(CS_ARCH_X86,CS_MODE_64)
    dis.detail=True
    block=[]
    stop=None
    consumed=0
    for ins in dis.disasm(pe.read_rva(MAIN,cap),MAIN):
        if ins.group(CS_GRP_JUMP) or ins.group(CS_GRP_CALL) or ins.group(CS_GRP_RET):
            stop=ins
            break
        if ins.mnemonic in {"int3","ud2","syscall","sysenter","hlt"}:
            raise RuntimeError("Unsupported original main prelude opcode: "+ins.mnemonic)
        block.append(ins)
        consumed+=ins.size
        if len(block)>MAX_BLOCK_INSNS:
            raise RuntimeError("Original main prelude exceeds native translation budget")
    if not stop:
        raise RuntimeError("No first real main control-flow boundary within 256 bytes")
    if not block:
        raise RuntimeError("Main entry immediately transfers control without a basic block")
    # Capture exact, privately owned source locations for the differential.
    # No original machine-code bytes or cookie values enter report artifacts.
    from capstone.x86 import X86_OP_MEM
    expected=[
        ("sub","rsp, 0x288"),
        ("mov","rax, qword ptr [rip + 0x25c182]"),
        ("xor","rax, rsp"),
        ("mov","qword ptr [rsp + 0x250], rax"),
        ("mov","qword ptr [rip + 0xd14af8], rcx"),
        ("mov","rcx, r8"),
        ("mov","qword ptr [rip + 0xd146c6], rdx"),
        ("mov","dword ptr [rip + 0xd14aef], r9d")
    ]
    if len(block)!=8 or [(i.mnemonic,i.op_str) for i in block]!=expected:
        raise RuntimeError("Original main first-eight instruction forms changed")
    def mem_va(ins,slot):
        operand=ins.operands[slot]
        if (operand.type!=X86_OP_MEM or
            ins.reg_name(operand.mem.base)!="rip" or
            operand.mem.index or operand.mem.segment):
            raise RuntimeError("Unexpected original RIP-relative guest location")
        return BASE+ins.address+ins.size+operand.mem.disp
    cookie_va=mem_va(block[1],1)
    arg0_va=mem_va(block[4],0)
    arg1_va=mem_va(block[6],0)
    show_va=mem_va(block[7],0)
    stop_va=BASE+stop.address
    section_end=max(rva+max(vsize,raw) for _,vsize,rva,raw,_,_ in pe.sections)
    if section_end>MAX_MAPPED_IMAGE:
        raise RuntimeError("Game image mapping exceeds bound")
    cpu=Uc(UC_ARCH_X86,UC_MODE_64)
    cpu.mem_map(BASE,align4k(section_end))
    headers=min(pe.size_of_headers if hasattr(pe,"size_of_headers") else 4096,len(pe.b))
    cpu.mem_write(BASE,pe.b[:headers])
    for name,vsize,rva,raw,ptr,flags in pe.sections:
        if raw:
            cpu.mem_write(BASE+rva,pe.b[ptr:ptr+raw])
    cpu.mem_map(STACK,0x20000)
    cpu.mem_map(TEB,4096)
    cpu.mem_write(TEB+0x30,struct.pack("<Q",TEB))
    cpu.mem_write(TEB+0x08,struct.pack("<Q",STACK+0x20000))
    cpu.mem_write(TEB+0x2c0,b"\0")
    rsp=STACK+0x20000-0x108
    cpu.mem_write(rsp,struct.pack("<Q",BASE+0x2ab18b))
    for reg,value in (
       (UC_X86_REG_RAX,10),(UC_X86_REG_RBX,0),
       (UC_X86_REG_RCX,BASE),(UC_X86_REG_RDX,0),
       (UC_X86_REG_R8,TEB+0x2c0),(UC_X86_REG_R9,10),
       (UC_X86_REG_RDI,TEB+0x2c0),(UC_X86_REG_RSI,0),
       (UC_X86_REG_RSP,rsp),(UC_X86_REG_RIP,BASE+MAIN),
       (UC_X86_REG_GS_BASE,TEB),(UC_X86_REG_EFLAGS,0x242)
    ):
        cpu.reg_write(reg,value)
    initial_cookie=struct.unpack("<Q",bytes(cpu.mem_read(cookie_va,8)))[0]
    executed=[]
    faults=[]
    writes=[]
    block_addresses={BASE+i.address for i in block}
    def on_instruction(uc,pc,size,_):
        if pc==stop_va:
            uc.emu_stop()
            return
        if pc not in block_addresses or len(executed)>=MAX_BLOCK_INSNS:
            faults.append({"reason":"unexpected control flow","rva":hex(pc-BASE)})
            uc.emu_stop()
            return
        executed.append(hex(pc-BASE))
    def on_invalid(uc,access,address,size,value,_):
        faults.append({"reason":"unmapped guest access","at_rva":
                      hex(uc.reg_read(UC_X86_REG_RIP)-BASE),
                      "address":hex(address),"size":size})
        return False
    def on_write(uc,access,address,size,value,_):
        if len(writes)<16:
            writes.append({"address":hex(address),"size":size})
    cpu.hook_add(UC_HOOK_CODE,on_instruction)
    cpu.hook_add(UC_HOOK_MEM_INVALID,on_invalid)
    cpu.hook_add(UC_HOOK_MEM_WRITE,on_write)
    try:
        cpu.emu_start(BASE+MAIN,stop_va,timeout=3_000_000,count=MAX_BLOCK_INSNS+2)
    except UcError as exc:
        faults.append({"reason":"Unicorn exception","detail":str(exc)})
    if faults or cpu.reg_read(UC_X86_REG_RIP)!=stop_va or len(executed)!=len(block):
        raise RuntimeError("Original main prelude execution did not reach verified boundary: "+
                           json.dumps({"faults":faults,"executed":len(executed),
                           "expected":len(block),"pc":hex(cpu.reg_read(UC_X86_REG_RIP))}))
    regs={name:hex(cpu.reg_read(reg)) for name,reg in (
        ("rax",UC_X86_REG_RAX),("rbx",UC_X86_REG_RBX),
        ("rcx",UC_X86_REG_RCX),("rdx",UC_X86_REG_RDX),
        ("r8",UC_X86_REG_R8),("r9",UC_X86_REG_R9),
        ("rsi",UC_X86_REG_RSI),("rdi",UC_X86_REG_RDI),
        ("rsp",UC_X86_REG_RSP))}
    direct=stop.operands[0].imm if (
        len(stop.operands)==1 and stop.operands[0].type==X86_OP_IMM) else None
    result={
        "original_executable_verified":True,
        "game_main_entry_rva":hex(MAIN),
        "unwind_interval_rva":[hex(begin),hex(finish)],
        "main_entry_is_unwind_start":MAIN==begin,
        "original_x64_instructions_executed":len(executed),
        "original_block_bytes_executed":consumed,
        "first_transfer_rva":hex(stop.address),
        "first_transfer_kind":stop.mnemonic,
        "first_transfer_target_rva":hex(direct) if direct is not None else None,
        "first_transfer_executed":False,
        "instruction_forms":[i.mnemonic for i in block],
        "original_instruction_operands":[{
            "rva":hex(i.address),"mnemonic":i.mnemonic,"operands":i.op_str
        } for i in block],
        "final_guest_registers":regs,
        "guest_stack_delta":cpu.reg_read(UC_X86_REG_RSP)-rsp,
        "guest_writes":writes,
        "actual_game_main_executed":True,
        "game_engine_initialized":False,
        "native_arm64_executed":False,
        "limitations":"First original x64 straight-line block only; no imports, engine or graphics executed."
    }
    if include_private_reference:
        result["_private_reference"]={
            "initial_cookie":initial_cookie,
            "cookie_va":cookie_va,
            "arg0_va":arg0_va,
            "arg1_va":arg1_va,
            "show_va":show_va,
            "initial_rsp":rsp,
            "final_rsp":cpu.reg_read(UC_X86_REG_RSP),
            "final_rax":cpu.reg_read(UC_X86_REG_RAX),
            "final_rcx":cpu.reg_read(UC_X86_REG_RCX),
            "saved_stack_cookie":struct.unpack("<Q",bytes(
                cpu.mem_read(cpu.reg_read(UC_X86_REG_RSP)+0x250,8)))[0],
            "stored_arg0":struct.unpack("<Q",bytes(cpu.mem_read(arg0_va,8)))[0],
            "stored_arg1":struct.unpack("<Q",bytes(cpu.mem_read(arg1_va,8)))[0],
            "stored_show":struct.unpack("<I",bytes(cpu.mem_read(show_va,4)))[0]
        }
    return result

def run(executable,out):
    out.mkdir(parents=True,exist_ok=True)
    data=probe(executable)
    (out/"main-first-block.json").write_text(json.dumps(data,indent=2)+"\n")
    lines=[
        "# MX Bikes original game-main first block",
        "",
        "- Original game entry: "+data["game_main_entry_rva"],
        "- Original x64 main instructions executed: **"+str(data["original_x64_instructions_executed"])+"**",
        "- Original guest bytes executed: "+str(data["original_block_bytes_executed"]),
        "- First control transfer (NOT executed): "+data["first_transfer_rva"]+" "+data["first_transfer_kind"],
        "- First transfer target: "+str(data["first_transfer_target_rva"]),
        "- Guest stack delta: "+str(data["guest_stack_delta"]),
        "- Instruction families: "+", ".join(data["instruction_forms"]),
        "",
        "## Actual x64 instruction forms (no machine-code bytes)",
        *["- "+i["rva"]+": "+i["mnemonic"]+" "+i["operands"] for i in data["original_instruction_operands"]],
        "",
        "**Scope: original x64 execution only, stopped before first control transfer. No native ARM64 main, engine, iOS or graphics boot.**"
    ]
    summary="\n".join(lines)+"\n"
    (out/"main-first-block.md").write_text(summary)
    print(summary)

if __name__=="__main__":
    if len(sys.argv)!=3:
        raise SystemExit("Usage: script.py original-mxbikes.exe private-report-dir")
    run(Path(sys.argv[1]),Path(sys.argv[2]))
