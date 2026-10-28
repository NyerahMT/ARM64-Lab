#!/usr/bin/env python3
"""Map and rank three authentic original MX Bikes filename separator exits.

The direct normal path uses 0x15b7e8; secondary backslash and zero-byte
branches are inventoried to prevent isolated one-by-one discovery.
Only disassembled metadata, no original executable bytes or rebuilt game.
"""
from pathlib import Path
import hashlib,json,sys
from capstone import Cs,CS_ARCH_X86,CS_MODE_64,CS_GRP_CALL,CS_GRP_JUMP,CS_GRP_RET
from capstone.x86 import X86_OP_IMM,X86_OP_MEM
from mxbikes_joined_strcpy_native import EXE_SHA
from mxbikes_strcpy_branch_successors import inspect
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/"arm64-lab"))
from tools.pe_probe import PE
ENTRY={
 "regular_filename_no_separator":0x15b7e8,
 "backslash_found":0x15b7f5,
 "separator_present_after_nul":0x15b809,
 "null_character":0x15b81b,
 "after_modeled_strrchr":0x15b82c,
 "post_separator_join":0x15b862,
 "strrchr_absent":0x15b854,
 "strrchr_present":0x15b839,
 "normal_loop_header":0x15b7c1
}

def scan(pe,md,entry):
    result=inspect(pe,md,entry)
    # Capture precise first-control byte length, including fallthrough of
    # the next conditional; require bounded original x64 instruction decode.
    pc=int(result["first_control_rva"],16)
    decoded=list(md.disasm(pe.read_rva(pc,16),pc))
    if not decoded:
        raise RuntimeError("Cannot decode next original control")
    inst=decoded[0]
    if inst.address!=pc:raise RuntimeError("Broken original control boundary")
    result["control_length"]=inst.size
    result["control_fallthrough_rva"]=hex(inst.address+inst.size)
    result["control_is_conditional"]=(
        bool(inst.group(CS_GRP_JUMP)) and inst.mnemonic!="jmp")
    result["control_is_return"]=bool(inst.group(CS_GRP_RET))
    return result

def run(original,out):
    pe=PE(original)
    if hashlib.sha256(pe.b).hexdigest()!=EXE_SHA:
        raise RuntimeError("Original executable SHA mismatch")
    md=Cs(CS_ARCH_X86,CS_MODE_64);md.detail=True
    first={
       0x15b7e6:("je","0x15b7f5"),
       0x15b807:("je","0x15b81b")
    }
    for va,(mn,op) in first.items():
        i=list(md.disasm(pe.read_rva(va,10),va))[0]
        if (i.mnemonic,i.op_str)!=(mn,op):
            raise RuntimeError("Original upstream separator Jcc changed")
    all_paths={name:scan(pe,md,addr) for name,addr in ENTRY.items()}
    out.mkdir(parents=True,exist_ok=True)
    info={"original_sha_verified":True,"entry_paths":all_paths,
          "native_passes":0,"original_x64_path_executions":0,
          "notes":"Strict authentic x64 static successor map, next native translation unverified"}
    (out/"filename-separator-deep-map.json").write_text(json.dumps(info,indent=2)+"\n")
    lines=["# MX Bikes next native filename-helper targets",""]
    for name,x in all_paths.items():
        lines.extend([
          "## "+name.replace("_"," ").capitalize(),
          "- Source RVA: **"+x["entry_rva"]+"**",
          "- Original instructions before control: **"+str(x["straightline_instructions"])+"**",
          "- First transfer: **"+x["first_control_rva"]+" "+
            x["first_control_mnemonic"]+" "+x["first_control_operands"]+"**",
          "- Branch fallthrough: **"+x["control_fallthrough_rva"]+"**",
          ""])
        lines.extend("- "+i["rva"]+" "+i["mnemonic"]+" "+i["operands"] for i in x["forms"])
        lines.append("")
    lines.append("**Static discovery only. No new native execution or game startup is claimed.**")
    summary="\n".join(lines)+"\n"
    (out/"filename-separator-deep-map.md").write_text(summary)
    print(summary)
    return info

if __name__=="__main__":
    if len(sys.argv)!=3:raise SystemExit("Usage: filename_depth.py original.exe outdir")
    run(Path(sys.argv[1]),Path(sys.argv[2]))
