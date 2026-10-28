#!/usr/bin/env python3
"""One real original MX Bikes Win64 global-record writer -> AArch64 differential.

Uses actual unwind-backed x64 RVA 0x258bb0, automatically verifies and
lifts its full 17-instruction body to portable C. Tests destination memory,
global count, record slots, EAX return, and RBX callee-saved behavior
against original x64 execution across deterministic randomized cases.
Original bytes and derived code remain private, in ephemeral runner storage.
"""
import ctypes
import hashlib
import json
from pathlib import Path
import random
import struct
import subprocess
import sys

from unicorn import Uc,UC_ARCH_X86,UC_ARCH_ARM64,UC_MODE_64,UC_MODE_ARM
from unicorn.x86_const import UC_X86_REG_RIP,UC_X86_REG_RSP,UC_X86_REG_RCX,UC_X86_REG_RDX,UC_X86_REG_R8,UC_X86_REG_R9,UC_X86_REG_RBX,UC_X86_REG_RAX
from unicorn.arm64_const import UC_ARM64_REG_PC,UC_ARM64_REG_SP,UC_ARM64_REG_LR,UC_ARM64_REG_X0,UC_ARM64_REG_X1,UC_ARM64_REG_X2,UC_ARM64_REG_X3,UC_ARM64_REG_X4,UC_ARM64_REG_X5,UC_ARM64_REG_X6,UC_ARM64_REG_X7,UC_ARM64_REG_W0
from elftools.elf.elffile import ELFFile

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"arm64-lab"))
from tools.pe_probe import PE
from tools.x64_record_lift import lift_indexed_record_writer

SHA="4ae7de3854b4d0a18271679fb57a1f2fdf0b21804417b85dd82055078ea123b6"
BEGIN,END=0x258bb0,0x258bfc
BASE=0x140000000
CODE=0x100000
DATA=0x200000
STACK=0x300000
RETURN=0x400000
N=512


def guest(code, count_rva, array_rva, index, values, seed):
    uc=Uc(UC_ARCH_X86,UC_MODE_64)
    code_va=BASE+BEGIN
    guest_count=BASE+count_rva
    guest_array=BASE+array_rva
    uc.mem_map(code_va&~4095,4096)
    uc.mem_map(guest_count&~4095,8192)
    uc.mem_map(DATA,0x1000)
    uc.mem_map(STACK,0x10000)
    uc.mem_map(RETURN,0x1000)
    uc.mem_write(code_va,code)
    uc.mem_write(guest_count,struct.pack("<I",index))
    uc.mem_write(guest_array,seed)
    rsp=STACK+0x8008
    uc.mem_write(rsp,struct.pack("<Q",RETURN))
    # Caller-passed fifth/sixth arguments at [rsp+0x28]/[rsp+0x30].
    uc.mem_write(rsp+0x28,struct.pack("<Q",values[3]))
    uc.mem_write(rsp+0x30,struct.pack("<Q",values[4]))
    original_rbx=0xC6A5617289B10D22
    uc.reg_write(UC_X86_REG_RBX,original_rbx)
    uc.reg_write(UC_X86_REG_RSP,rsp)
    uc.reg_write(UC_X86_REG_RIP,code_va)
    uc.reg_write(UC_X86_REG_RCX,DATA+0x100)
    uc.reg_write(UC_X86_REG_RDX,values[0])
    uc.reg_write(UC_X86_REG_R8,values[1])
    uc.reg_write(UC_X86_REG_R9,values[2])
    uc.emu_start(code_va,RETURN,timeout=1_000_000,count=100)
    if uc.reg_read(UC_X86_REG_RIP)!=RETURN or uc.reg_read(UC_X86_REG_RSP)!=rsp+8:
        raise RuntimeError("Original x64 writer did not RET with expected stack")
    if uc.reg_read(UC_X86_REG_RBX)!=original_rbx or uc.reg_read(UC_X86_REG_RAX)!=0:
        raise RuntimeError("Original x64 writer did not preserve RBX or return EAX=0")
    return (struct.unpack("<I",uc.mem_read(DATA+0x100,4))[0],
            struct.unpack("<I",uc.mem_read(guest_count,4))[0],
            bytes(uc.mem_read(guest_array,N)),
            uc.reg_read(UC_X86_REG_RAX))


def load_arm(path):
    with path.open("rb") as fp:
        elf=ELFFile(fp)
        if elf["e_machine"]!="EM_AARCH64":raise RuntimeError("Object not ARM64")
        section=elf.get_section_by_name(".text")
        symbols=elf.get_section_by_name(".symtab")
        hits=symbols.get_symbol_by_name("lifted_record") if symbols else None
        if not section or not hits or len(hits)!=1:raise RuntimeError("Missing linked native function")
        reloc=elf.get_section_by_name(".rela.text")
        if reloc and list(reloc.iter_relocations()):
            raise RuntimeError("Unexpected unresolved relocation")
        start=int(hits[0]["st_value"]);size=int(hits[0]["st_size"])
        body=section.data()
        if not 0<size<=4096 or start+size>len(body) or len(body)>4096:
            raise RuntimeError("Unexpected native code extent")
        return body,start,size


def native_arm(code,entry,index,values,seed):
    uc=Uc(UC_ARCH_ARM64,UC_MODE_ARM)
    for base,sz in ((CODE,0x1000),(DATA,0x10000),(STACK,0x10000),(RETURN,0x1000)):
        uc.mem_map(base,sz)
    uc.mem_write(CODE,code)
    uc.mem_write(DATA+0x200,struct.pack("<I",index))
    uc.mem_write(DATA+0x400,seed)
    for reg,value in zip([UC_ARM64_REG_X0,UC_ARM64_REG_X1,UC_ARM64_REG_X2,
                          UC_ARM64_REG_X3,UC_ARM64_REG_X4,UC_ARM64_REG_X5,UC_ARM64_REG_X6,UC_ARM64_REG_X7],
                         [DATA+0x100,DATA+0x200,DATA+0x400,*values]):
        uc.reg_write(reg,value)
    uc.reg_write(UC_ARM64_REG_PC,CODE+entry)
    uc.reg_write(UC_ARM64_REG_SP,STACK+0x8000)
    uc.reg_write(UC_ARM64_REG_LR,RETURN)
    uc.emu_start(CODE+entry,RETURN,timeout=1_000_000,count=250)
    if uc.reg_read(UC_ARM64_REG_PC)!=RETURN:raise RuntimeError("ARM64 function did not return")
    return (struct.unpack("<I",uc.mem_read(DATA+0x100,4))[0],
            struct.unpack("<I",uc.mem_read(DATA+0x200,4))[0],
            bytes(uc.mem_read(DATA+0x400,N)),
            uc.reg_read(UC_ARM64_REG_W0))


def main():
    if len(sys.argv)!=3:raise SystemExit("usage: script.py ORIGINAL_EXE REPORT_DIR")
    pe=PE(Path(sys.argv[1]))
    if pe.inventory()["sha256"]!=SHA:raise RuntimeError("Wrong executable revision")
    p,sz=pe.directory(3)
    ranges={a:b for a,b,_ in struct.iter_unpack("<III",pe.read_rva(p,sz))}
    if ranges.get(BEGIN)!=END:raise RuntimeError("Target unwind boundary changed")
    code=pe.read_rva(BEGIN,END-BEGIN)
    generated,meta=lift_indexed_record_writer(code,BEGIN)
    temp=Path(sys.argv[2]).parent/"mxbikes-record-private"
    temp.mkdir(exist_ok=True)
    cfile=temp/"derived-record.c"
    hostso=temp/"derived-record.so"
    armobj=temp/"derived-record-aarch64.o"
    cfile.write_text(generated)
    subprocess.run(["clang","-O2","-shared","-fPIC","-ffreestanding",str(cfile),"-o",str(hostso)],check=True)
    subprocess.run(["clang","-O2","--target=aarch64-unknown-linux-gnu","-ffreestanding",
                    "-fno-builtin","-c",str(cfile),"-o",str(armobj)],check=True)
    arm,entry,size=load_arm(armobj)
    host=ctypes.CDLL(str(hostso))
    fn=host.lifted_record
    fn.restype=ctypes.c_uint32
    fn.argtypes=[ctypes.POINTER(ctypes.c_uint32),ctypes.POINTER(ctypes.c_uint32),
                 ctypes.POINTER(ctypes.c_ubyte)]+[ctypes.c_uint32]*5
    rng=random.Random(0x258bb0)
    cases=0
    for index in range(8):
        for trial in range(16):
            values=[rng.getrandbits(32) for _ in range(5)]
            seed=bytes(rng.getrandbits(8) for _ in range(N))
            reference=guest(code,int(meta["count_global_rva"],16),int(meta["array_global_rva"],16),
                            index,values,seed)
            dst=ctypes.c_uint32(0)
            counter=ctypes.c_uint32(index)
            buffer=(ctypes.c_ubyte*N).from_buffer_copy(seed)
            ret=fn(ctypes.byref(dst),ctypes.byref(counter),buffer,*values)
            host_result=(dst.value,counter.value,bytes(buffer),ret)
            arm_result=native_arm(arm,entry,index,values,seed)
            if host_result!=reference or arm_result!=reference:
                raise AssertionError(f"Mismatch at index={index} trial={trial}: host={host_result==reference}, arm={arm_result==reference}")
            cases+=1
    out=Path(sys.argv[2]);out.mkdir(exist_ok=True)
    report={
        "original_sha256":SHA,
        "original_rva":hex(BEGIN),
        "original_function_end":hex(END),
        "original_function_instruction_count":meta["original_instruction_count"],
        "original_global_counter_rva":meta["count_global_rva"],
        "original_global_record_array_rva":meta["array_global_rva"],
        "original_record_stride":meta["record_stride_bytes"],
        "original_indexed_field_offsets":meta["written_field_offsets"],
        "bitwise_x64_vs_host_vs_arm64_cases":cases,
        "host_mismatches":0,
        "arm64_mismatches":0,
        "aarch64_function_code_bytes":size,
        "preserved_rbx_in_x64_reference":True,
        "guest_fifth_and_sixth_stack_arguments_exercised":True,
        "game_booted":False,
        "native_ios_executed":False,
        "limitations":"Recognizes one specific indexed-record writer instruction pattern. Bounded counter 0..7 and accessible arrays supplied externally; not general Win64 global-state translation."
    }
    (out/"indexed-record-differential.json").write_text(json.dumps(report,indent=2)+"\n")
    lines=["# Original MX Bikes indexed-memory writer differential","",
           f"- Original function: **{hex(BEGIN)}**, {meta['original_instruction_count']} x64 instructions",
           f"- Native generated AArch64 function: {size} bytes",
           f"- x64 original vs generated native C vs generated ARM64: **{cases}/{cases} bitwise matches**",
           "- Guest integer stack arguments #5/#6 tested and RBX preservation checked on x64",
           "- Original global counter and indexed 72-byte record locations matched across architectures",
           "",
           "**One restricted original branch-free Win64 record-writer pattern. No whole-game compilation or original engine initialization on ARM64.**",""]
    summary="\n".join(lines)
    (out/"indexed-record-differential.md").write_text(summary)
    print(summary)

if __name__=="__main__":main()
