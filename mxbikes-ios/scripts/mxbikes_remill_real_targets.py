#!/usr/bin/env python3
"""Private, pinned original MX Bikes function selection for Remill proof.

Creates ephemeral HEX inputs in the job's temp directory for the official
Remill research container. Never upload this directory or LLVM outputs.
Public CI receives only aggregate metadata with no original code bytes.
"""
import hashlib
import json
from pathlib import Path
import struct
import sys
from capstone import Cs,CS_ARCH_X86,CS_MODE_64,CS_GRP_CALL,CS_GRP_JUMP,CS_GRP_RET

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"arm64-lab"))
from tools.pe_probe import PE

EXPECTED_SHA="4ae7de3854b4d0a18271679fb57a1f2fdf0b21804417b85dd82055078ea123b6"
# First three boundaries independently confirmed by Ghidra FunctionManager.
VERIFIED={
    0x2412e0: (0x2412f7,"linked-caller-a","ghidra-and-unwind"),
    0x241960: (0x241977,"linked-caller-b","ghidra-and-unwind"),
    0x15c240: (0x15c269,"shared-callee","ghidra-and-unwind"),
}
# These were validated previously with exact x64 vs generated-AArch64
# differential tests, but this new pass only tests IR/object feasibility.
OTHER={
    0x267ae0:"sse-cross-product",
    0x266d80:"sse-math-35",
    0x266e20:"sse-math-32a",
    0x266eb0:"sse-math-32b",
    0x258bb0:"indexed-record-writer",
}

def select(original:Path, destination:Path):
    pe=PE(original)
    inventory=pe.inventory()
    if inventory["sha256"]!=EXPECTED_SHA:
        raise ValueError("Original PE SHA-256 does not match the verified game")
    directory,length=pe.directory(3)
    records={b:e for b,e,_ in struct.iter_unpack("<III",pe.read_rva(directory,length))}
    destination.mkdir(parents=True,exist_ok=True)
    targets=[]
    for begin,(end,name,confidence) in VERIFIED.items():
        if records.get(begin)!=end:
            raise RuntimeError(f"Independent Ghidra function {begin:#x} differs from PE unwind")
        targets.append((begin,end,name,confidence))
    # Entry wrapper calls this verified PE-unwind interval directly.
    # Function-body completeness is not yet established by native translation.
    crt_begin,crt_end = 0x2ab954,0x2aba07
    if records.get(crt_begin) != crt_end:
        raise RuntimeError("First CRT initializer no longer matches pinned entry unwind")
    targets.append((crt_begin,crt_end,"crt-security-cookie-initializer","entry-call-and-unwind"))
    for begin,name in OTHER.items():
        end=records.get(begin)
        if end is None or not 1 <= end-begin<=512:
            raise RuntimeError(f"Missing or excessive x64 unwind range for {begin:#x}")
        targets.append((begin,end,name,"prior-differential-unwind"))
    manifest=[]
    decoder=Cs(CS_ARCH_X86,CS_MODE_64)
    decoder.detail=True
    for begin,end,name,confidence in targets:
        body=pe.read_rva(begin,end-begin)
        if not 1<=len(body)<=512:
            raise RuntimeError("Unexpected bounded original function body length")
        ins=list(decoder.disasm(body,begin))
        if not ins or sum(x.size for x in ins)!=len(body):
            raise RuntimeError(f"Original game body at {begin:#x} does not fully decode")
        first_end=ins[0].size
        first_control=next((x for x in ins if x.group(CS_GRP_CALL) or
                           x.group(CS_GRP_JUMP) or x.group(CS_GRP_RET)),None)
        basic_end=(first_control.address+first_control.size-begin if first_control is not None else len(body))
        if not 1<=first_end<=basic_end<=len(body):
            raise RuntimeError("Invalid inferred x64 first block extent")
        # All original bytes stay in this TEMP directory; never upload it.
        (destination/(name+".hex")).write_text(body.hex()+"\n")
        (destination/(name+".first")).write_text(body[:first_end].hex()+"\n")
        (destination/(name+".basic")).write_text(body[:basic_end].hex()+"\n")
        manifest.append({
            "name":name,"rva":hex(begin),"end":hex(end),
            "byte_length":len(body),"instruction_count":len(ins),
            "first_instruction_bytes":first_end,"initial_block_bytes":basic_end,
            "initial_block_instruction_count":sum(i.address+i.size-begin<=basic_end for i in ins),
            "first_control_mnemonic":first_control.mnemonic if first_control else None,
            "boundary_evidence":confidence,
            "original_sha256":hashlib.sha256(body).hexdigest(),
        })
    (destination/"manifest-private.json").write_text(json.dumps(manifest,indent=2)+"\n")
    print(f"Selected {len(manifest)} original function bodies from pinned PE; "
          f"{sum(x['byte_length'] for x in manifest)} total source bytes, private only.")
    return manifest

if __name__=="__main__":
    if len(sys.argv)!=3:raise SystemExit("usage: script.py original.exe PRIVATE_DIR")
    select(Path(sys.argv[1]),Path(sys.argv[2]))
