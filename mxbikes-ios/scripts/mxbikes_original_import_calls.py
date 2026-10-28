#!/usr/bin/env python3
"""Private scan for genuine IAT-linked x64 call/jump instruction candidates.

The byte-pattern scan first finds possible RIP-relative FF /2 /4 instructions,
then Capstone validates full decoding and checks that the effective address
points to an actual imported-address-table slot. A match is not necessarily
the start of a genuine function or a reachable instruction; no original bytes
or generated C are exported.
"""
import collections
import json
from pathlib import Path
import sys
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
from capstone.x86 import X86_OP_MEM

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"arm64-lab"))
from tools.pe_probe import PE
from tools.x64_import_lift import lift_import_sequence, UnsupportedWin64Code
from mxbikes_first_callee_emu import import_slots

EXPECTED_SHA="4ae7de3854b4d0a18271679fb57a1f2fdf0b21804417b85dd82055078ea123b6"


def scan(executable):
    pe=PE(executable)
    meta=pe.inventory()
    if meta["sha256"]!=EXPECTED_SHA:
        raise ValueError("Unexpected MX Bikes executable revision")
    slots={rva:(dll,sym) for rva,dll,sym in import_slots(pe)}
    data,start=pe.text_section()
    md=Cs(CS_ARCH_X86,CS_MODE_64)
    md.detail=True
    out=[]
    for index in range(len(data)-5):
        if data[index]!=0xff or data[index+1] not in (0x15,0x25):
            continue
        rva=start+index
        inst=list(md.disasm(data[index:index+6],rva,count=1))
        if len(inst)!=1 or inst[0].size!=6 or inst[0].mnemonic not in ("call","jmp"):
            continue
        op=inst[0].operands
        if len(op)!=1 or op[0].type!=X86_OP_MEM or inst[0].reg_name(op[0].mem.base)!="rip":
            continue
        slot=rva+6+op[0].mem.disp
        if slot not in slots:
            continue
        dll,name=slots[slot]
        item={"rva":hex(rva),"kind":inst[0].mnemonic,"iat_rva":hex(slot),
              "dll":dll,"symbol":name}
        if inst[0].mnemonic=="jmp":
            try:
                lifted,info=lift_import_sequence(data[index:index+6],rva,{slot:(dll,name)})
                item["restricted_lifter_accepts"]=True
            except UnsupportedWin64Code:
                item["restricted_lifter_accepts"]=False
        else:
            item["restricted_lifter_accepts"]=False
        out.append(item)
    by_name=collections.Counter(f"{x['dll']}!{x['symbol']}" for x in out)
    supported={("kernel32.dll","gettickcount"),
               ("kernel32.dll","queryperformancecounter"),
               ("kernel32.dll","queryperformancefrequency"),
               ("kernel32.dll","getsystemtimeasfiletime"),
               ("kernel32.dll","sleep"),("winmm.dll","timegettime")}
    candidates=[x for x in out if x["kind"]=="jmp" and
                (x["dll"].casefold(),x["symbol"].casefold()) in supported and
                x["restricted_lifter_accepts"]]
    supported_calls=[x for x in out if x["kind"]=="call" and
                     (x["dll"].casefold(),x["symbol"].casefold()) in supported]
    return {
       "source": "private original game .text and verified imported-address-table slots",
       "original_executable_sha256":EXPECTED_SHA,
       "iat_slot_count":len(slots),
       "raw_rip_relative_import_hits":len(out),
       "matched_call_instructions":sum(x["kind"]=="call" for x in out),
       "matched_jump_instructions":sum(x["kind"]=="jmp" for x in out),
       "candidate_native_supported_import_jumps":len(candidates),
       "candidate_native_supported_import_calls":len(supported_calls),
       "potential_native_test_calls":supported_calls[:30],
       "potential_original_native_test_targets":candidates[:20],
       "most_common_matched_imports":by_name.most_common(25),
       "sample":out[:35],
       "limitations":[
           "RIP-relative IAT byte matches may begin inside another instruction or data.",
           "A matched JMP is not proven an independent callable game function.",
           "No original function was translated to ARM64 or executed in this scan.",
           "The Windows imports are synthetic/private test evidence, not iOS integration.",
       ]
    }


def main():
    if len(sys.argv)!=3:
        raise SystemExit("usage: python mxbikes_original_import_calls.py EXE REPORT_DIR")
    out=Path(sys.argv[2]);out.mkdir(parents=True,exist_ok=True)
    result=scan(sys.argv[1])
    (out/"real-import-callsite-scan.json").write_text(json.dumps(result,indent=2)+"\n")
    summary="\n".join([
        "# Original MX Bikes x64 imported-callsite scan","",
        f"- Verified IAT slots: {result['iat_slot_count']}",
        f"- Candidate RIP-relative IAT instruction hits: {result['raw_rip_relative_import_hits']}",
        f"- Candidate CALL instructions: {result['matched_call_instructions']}",
        f"- Candidate JMP instructions: {result['matched_jump_instructions']}",
        f"- Possible six-byte native-timing-import JMP targets for restricted translator: {result['candidate_native_supported_import_jumps']}",
        f"- Native-timing-import CALL instruction candidates (not full functions): {result['candidate_native_supported_import_calls']}",
        "", "## Candidate timing import CALL instructions", ""
    ]+[f"- {x['rva']}: {x['dll']}!{x['symbol']}" for x in result["potential_native_test_calls"][:15]]+[
        "", "## Candidate native-timing import thunks", ""
    ]+[f"- {x['rva']} -> {x['dll']}!{x['symbol']}" for x in result["potential_original_native_test_targets"]] + [
        "", "**These are candidate instruction positions, not validated function starts. No original code was executed or shared.**",""])
    (out/"real-import-callsite-scan.md").write_text(summary)
    print(summary)


if __name__=="__main__":
    main()
