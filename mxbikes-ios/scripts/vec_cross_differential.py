#!/usr/bin/env python3
"""Private differential test of one x64 math routine; metadata-only outputs.

Target is a call-referenced 3D vector cross-product in a user-supplied MX Bikes
binary. Do not publish the extracted binary, original machine bytes, or generated
target code. A behavioral match only validates this individual function.
"""
from __future__ import annotations

import ctypes
import hashlib
import json
import os
import pathlib
import random
import struct
import subprocess
import sys

from capstone import Cs, CS_ARCH_X86, CS_MODE_64
from unicorn import Uc, UC_ARCH_X86, UC_MODE_64, UC_ARCH_ARM64, UC_MODE_ARM
from unicorn.x86_const import UC_X86_REG_RIP, UC_X86_REG_RSP, UC_X86_REG_RCX, UC_X86_REG_RDX, UC_X86_REG_R8
from unicorn.arm64_const import UC_ARM64_REG_PC, UC_ARM64_REG_SP, UC_ARM64_REG_LR, UC_ARM64_REG_X0, UC_ARM64_REG_X1, UC_ARM64_REG_X2
from elftools.elf.elffile import ELFFile

root = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(root / "arm64-lab"))
from tools.pe_probe import PE
from tools.x64_sse_lift import lift as lift_sse

EXPECTED_EXE_SHA = "4ae7de3854b4d0a18271679fb57a1f2fdf0b21804417b85dd82055078ea123b6"
START, END = 0x267AE0, 0x267B4D
CODE_BASE = 0x100000
DATA_BASE = 0x200000
STACK_BASE = 0x300000
RETURN_ADDR = 0x400000

SOURCE = """
/* Standalone portable vector math primitive. No original engine code. */
void cross3(float *dst, const float *a, const float *b) {
    float x = (b[2] * a[1]) - (b[1] * a[2]);
    float y = (b[0] * a[2]) - (a[0] * b[2]);
    float z = (a[0] * b[1]) - (b[0] * a[1]);
    dst[0] = x;
    dst[1] = y;
    dst[2] = z;
}
"""

EXPECTED_MNEMONICS = [
    "sub", "movss", "movss", "movss", "movaps", "movaps", "movaps",
    "mulss", "mulss", "mulss", "mulss", "movss", "subss", "movaps",
    "mulss", "mulss", "movss", "movaps", "subss", "subss",
    "movss", "movss", "add", "ret",
]


def run_guest(code: bytes, a, b) -> bytes:
    uc = Uc(UC_ARCH_X86, UC_MODE_64)
    uc.mem_map(CODE_BASE, 0x1000)
    uc.mem_map(DATA_BASE, 0x10000)
    uc.mem_map(STACK_BASE, 0x10000)
    uc.mem_map(RETURN_ADDR, 0x1000)
    uc.mem_write(CODE_BASE, code)
    uc.mem_write(DATA_BASE + 0x1000, struct.pack("<fff", *a))
    uc.mem_write(DATA_BASE + 0x2000, struct.pack("<fff", *b))
    guest_rsp = STACK_BASE + 0x8008  # Windows x64 function entry stack alignment.
    uc.mem_write(guest_rsp, struct.pack("<Q", RETURN_ADDR))
    uc.reg_write(UC_X86_REG_RIP, CODE_BASE)
    uc.reg_write(UC_X86_REG_RSP, guest_rsp)
    uc.reg_write(UC_X86_REG_RCX, DATA_BASE)
    uc.reg_write(UC_X86_REG_RDX, DATA_BASE + 0x1000)
    uc.reg_write(UC_X86_REG_R8, DATA_BASE + 0x2000)
    uc.emu_start(CODE_BASE, RETURN_ADDR, timeout=1000000, count=128)
    if uc.reg_read(UC_X86_REG_RIP) != RETURN_ADDR:
        raise RuntimeError("Guest function failed to return to expected address")
    return bytes(uc.mem_read(DATA_BASE, 12))


def read_arm64_object(path, symbol_name="cross3"):
    with path.open("rb") as stream:
        elf = ELFFile(stream)
        if elf["e_machine"] != "EM_AARCH64":
            raise ValueError("Not an ARM64 ELF object")
        section = elf.get_section_by_name(".text")
        symbols = elf.get_section_by_name(".symtab")
        if section is None or symbols is None:
            raise ValueError("ARM64 output missing code or symbol table")
        reloc = elf.get_section_by_name(".rela.text")
        if reloc is not None and list(reloc.iter_relocations()):
            raise ValueError("ARM64 cross product is not self-contained")
        symbol = symbols.get_symbol_by_name(symbol_name)
        if not symbol or len(symbol) != 1:
            raise ValueError("ARM64 cross3 function symbol missing")
        entry = symbol[0]
        offset, length = int(entry["st_value"]), int(entry["st_size"])
        code = section.data()
        if not length or offset + length > len(code) or len(code) > 4096:
            raise ValueError("Unexpected ARM64 code bounds")
        return code, offset, length


def run_arm64(code: bytes, entry: int, a, b) -> bytes:
    uc = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
    uc.mem_map(CODE_BASE, 0x1000)
    uc.mem_map(DATA_BASE, 0x10000)
    uc.mem_map(STACK_BASE, 0x10000)
    uc.mem_map(RETURN_ADDR, 0x1000)
    uc.mem_write(CODE_BASE, code)
    uc.mem_write(DATA_BASE + 0x1000, struct.pack("<fff", *a))
    uc.mem_write(DATA_BASE + 0x2000, struct.pack("<fff", *b))
    uc.reg_write(UC_ARM64_REG_PC, CODE_BASE + entry)
    uc.reg_write(UC_ARM64_REG_LR, RETURN_ADDR)
    uc.reg_write(UC_ARM64_REG_SP, STACK_BASE + 0x8000)
    uc.reg_write(UC_ARM64_REG_X0, DATA_BASE)
    uc.reg_write(UC_ARM64_REG_X1, DATA_BASE + 0x1000)
    uc.reg_write(UC_ARM64_REG_X2, DATA_BASE + 0x2000)
    uc.emu_start(CODE_BASE + entry, RETURN_ADDR, timeout=1000000, count=128)
    if uc.reg_read(UC_ARM64_REG_PC) != RETURN_ADDR:
        raise RuntimeError("ARM64 function failed to return")
    return bytes(uc.mem_read(DATA_BASE, 12))


def main():
    if len(sys.argv) != 3:
        raise SystemExit("Usage: vec_cross_differential.py <mxbikes.exe> <report_dir>")
    exe = pathlib.Path(sys.argv[1])
    out = pathlib.Path(sys.argv[2])
    out.mkdir(parents=True, exist_ok=True)
    pe = PE(exe)
    inv = pe.inventory()
    if inv["sha256"] != EXPECTED_EXE_SHA:
        raise RuntimeError("Input revision changed, refusing to run target-specific experiment")
    table_rva, table_size = pe.directory(3)
    candidates = {begin: end for begin,end,_ in struct.iter_unpack("<III", pe.read_rva(table_rva,table_size))}
    if candidates.get(START) != END:
        raise RuntimeError("Unexpected unwind record for cross-product candidate")
    code = pe.read_rva(START, END-START)
    decoder = Cs(CS_ARCH_X86, CS_MODE_64)
    instructions = list(decoder.disasm(code, START))
    if sum(i.size for i in instructions) != len(code):
        raise RuntimeError("Incomplete disassembly of target")
    if [i.mnemonic for i in instructions] != EXPECTED_MNEMONICS:
        raise RuntimeError("Unexpected x64 instruction signature for target function")

    temp = out.parent / "mxbikes-vector-temp"
    temp.mkdir(exist_ok=True)
    cfile = temp / "cross3.c"
    native_so = temp / "cross3.so"
    arm_object = temp / "cross3-aarch64.o"
    cfile.write_text(SOURCE)
    common = ["clang", "-O2", "-ffp-contract=off", "-fno-fast-math"]
    subprocess.run(common + ["-shared", "-fPIC", str(cfile), "-o", str(native_so)], check=True)
    subprocess.run(common + ["--target=aarch64-unknown-linux-gnu", "-ffreestanding",
                              "-c", str(cfile), "-o", str(arm_object)], check=True)
    machine = subprocess.check_output(["readelf", "-h", str(arm_object)], text=True)
    if "Machine:" not in machine or "AArch64" not in machine:
        raise RuntimeError("AArch64 compiler did not produce expected ELF machine")

    arm_text, arm_offset, arm_size = read_arm64_object(arm_object)
    # This second variant is generated instruction-by-instruction from the
    # original x64 function, unlike the manually written vector formula.
    auto_source, auto_insn_count = lift_sse(code, START)
    auto_cfile = temp / "automatically_lifted.c"
    auto_so = temp / "automatically_lifted.so"
    auto_obj = temp / "automatically_lifted_arm64.o"
    auto_cfile.write_text(auto_source)
    subprocess.run(common + ["-shared", "-fPIC", str(auto_cfile), "-o", str(auto_so)], check=True)
    subprocess.run(common + ["--target=aarch64-unknown-linux-gnu", "-ffreestanding",
                              "-c", str(auto_cfile), "-o", str(auto_obj)], check=True)
    auto_arm_text, auto_arm_offset, auto_arm_size = read_arm64_object(auto_obj, "lifted")
    auto_lib = ctypes.CDLL(str(auto_so))
    auto_fn = auto_lib.lifted
    auto_fn.argtypes = [ctypes.POINTER(ctypes.c_float)] * 3
    auto_fn.restype = None
    lib = ctypes.CDLL(str(native_so))
    fn = lib.cross3
    FloatTriple = ctypes.c_float * 3
    fn.argtypes = [ctypes.POINTER(ctypes.c_float)] * 3
    fn.restype = None

    cases = [
        ((1., 0., 0.), (0., 1., 0.)),
        ((0., 1., 0.), (0., 0., 1.)),
        ((1., 2., 3.), (4., 5., 6.)),
        ((0., 0., 0.), (3., -2., 5.)),
        ((1., 1., 1.), (1., 1., 1.)),
    ]
    rng = random.Random(267)
    cases += [
        (tuple(rng.uniform(-100, 100) for _ in range(3)),
         tuple(rng.uniform(-100, 100) for _ in range(3)))
        for _ in range(195)
    ]
    mismatches = []
    arm_mismatches = []
    auto_c_mismatches = []
    auto_arm_mismatches = []
    for index, (avec, bvec) in enumerate(cases):
        a = FloatTriple(*avec)
        b = FloatTriple(*bvec)
        actual = run_guest(code, a, b)
        c_output = FloatTriple(0., 0., 0.)
        fn(c_output, a, b)
        predicted = struct.pack("<fff", *c_output)
        arm_result = run_arm64(arm_text, arm_offset, a, b)
        auto_c_result = FloatTriple(0.,0.,0.)
        auto_fn(auto_c_result, a, b)
        auto_native_bytes = struct.pack("<fff", *auto_c_result)
        auto_arm_bytes = run_arm64(auto_arm_text, auto_arm_offset, a, b)
        if auto_native_bytes != actual:
            auto_c_mismatches.append(index)
        if auto_arm_bytes != actual:
            auto_arm_mismatches.append(index)
        if actual != arm_result:
            arm_mismatches.append({"case_index": index,
                                   "original_outputs": list(struct.unpack("<fff", actual)),
                                   "arm64_outputs": list(struct.unpack("<fff", arm_result))})
        if actual != predicted:
            mismatches.append({
                "case_index": index,
                "original_outputs": list(struct.unpack("<fff", actual)),
                "native_c_outputs": list(struct.unpack("<fff", predicted)),
                "same_bits": False,
            })
            if len(mismatches) >= 5:
                break
    report = {
        "original_exe_sha256": EXPECTED_EXE_SHA,
        "target_rva": hex(START),
        "target_instruction_count": len(instructions),
        "target_body_sha256": hashlib.sha256(code).hexdigest(),
        "native_x86_differential_cases": len(cases),
        "verified_bitwise_matches": len(cases) if not mismatches else None,
        "native_x86_mismatch_sample": mismatches,
        "aarch64_elf_object_compiled": True,
        "aarch64_function_bytes": arm_size,
        "arm64_object_executed": True,
        "arm64_vs_original_mismatch_count": len(arm_mismatches),
        "arm64_mismatch_samples": arm_mismatches[:5],
        "automatically_lifted_x64_instruction_count": auto_insn_count,
        "automatically_lifted_arm64_function_bytes": auto_arm_size,
        "automatic_c_mismatch_count": len(auto_c_mismatches),
        "automatic_arm64_mismatch_count": len(auto_arm_mismatches),
        "automatic_c_mismatch_indices": auto_c_mismatches[:5],
        "automatic_arm64_mismatch_indices": auto_arm_mismatches[:5],
        "game_engine_booted": False,
        "notes": [
            "Original isolated function was executed under Unicorn x64 CPU emulation.",
            "Portable C implementation is a standard 3D vector-cross-product primitive.",
            "A standalone cross-compiled AArch64 object is not an iOS app or general AOT recompilation.",
            "No game code or binaries are uploaded in report artifacts.",
        ],
    }
    (out/"vector-cross-check.json").write_text(json.dumps(report,indent=2)+"\n")
    summary = (
        "# MX Bikes native vector-math differential test\n\n"
        f"- Original function RVA: {hex(START)}\n"
        f"- x64 original instructions: {len(instructions)}\n"
        f"- Executed original x64 function under Unicorn: yes\n"
        f"- Test cases: {len(cases)}\n"
        f"- Bitwise mismatches: {len(mismatches)} (up to first 5 shown in JSON)\n"
        f"- C vector-cross-product compiled to AArch64 ELF: yes\n"
        f"- ARM64 machine code executed under Unicorn: yes\n"
        f"- ARM64 vs original x64 bitwise mismatches: {len(arm_mismatches)}\n"
        f"- Instructions automatically lifted to C: {auto_insn_count}\n"
        f"- Automatically generated C vs original mismatches: {len(auto_c_mismatches)}\n"
        f"- Automatically generated ARM64 code vs original mismatches: {len(auto_arm_mismatches)}\n\n"
        "**Scope:** This validates one isolated mathematical function, not broader game execution, "
        "the source translator, or an iPhone build.\n"
    )
    (out/"vector-cross-check.md").write_text(summary)
    print(summary)
    if mismatches or arm_mismatches or auto_c_mismatches or auto_arm_mismatches:
        raise AssertionError("Differential outputs disagree; inspect JSON before claiming function equivalence")


if __name__=="__main__":
    main()
