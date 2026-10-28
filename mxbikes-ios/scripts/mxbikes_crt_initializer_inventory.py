#!/usr/bin/env python3
"""Private bounded survey of authentic original CRT initializer pointer tables.

The original CRT call sites pass two consecutive address ranges to MSVCR90
_initterm_e and _initterm. Classify all slots together and identify reachable
callback function families without publishing commercial bytes or code.
"""
from pathlib import Path
from collections import Counter
import hashlib,json,struct,sys

from capstone import Cs,CS_ARCH_X86,CS_MODE_64

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/"arm64-lab"))
from tools.pe_probe import PE
from tools.x64_semantics_gap import aggregate_callbacks
from tools.crt_import_cluster_lift import lift_crt_import_cluster,UnsupportedCluster
from tools.pe_call_clusters import unwind_functions
from mxbikes_first_callee_emu import import_slots
from capstone.x86 import X86_OP_IMM,X86_OP_MEM

SHA="4ae7de3854b4d0a18271679fb57a1f2fdf0b21804417b85dd82055078ea123b6"
BASE=0x140000000
TABLES=(
    # name, original LEA RCX instruction RVA, original LEA RDX RVA,
    # expected begin/end (cross-check only; source is the decoded LEA).
    ("msvcr90.dll::_initterm_e",0x2ab0af,0x2ab0a8,0x321a88,0x321aa0),
    ("msvcr90.dll::_initterm",0x2ab0e5,0x2ab0de,0x321a60,0x321a80)
)
MAX_UNWIND_INSPECT=4096

def inventory(path):
    pe=PE(path)
    if hashlib.sha256(pe.b).hexdigest()!=SHA:
        raise RuntimeError("Original private executable has changed")
    image=pe.inventory()
    if int(image["image_base"],16)!=BASE:
        raise RuntimeError("Original game PE base changed")
    section_end=max(int(rva)+max(int(raw),int(vsize))
                    for _,vsize,rva,raw,_,_ in pe.sections)
    uw_start,uw_size=pe.directory(3)
    if not uw_start or uw_size%12:
        raise RuntimeError("Original x64 unwind table is invalid")
    unwind=[(begin,end) for begin,end,_ in
            struct.iter_unpack("<III",pe.read_rva(uw_start,uw_size))
            if begin<end]
    md=Cs(CS_ARCH_X86,CS_MODE_64)
    md.detail=True
    def original_lea_target(rva):
        decoded=list(md.disasm(pe.read_rva(rva,7),rva))
        if len(decoded)!=1 or decoded[0].size!=7 or decoded[0].mnemonic!="lea":
            raise RuntimeError("Original CRT callback-array LEA shape changed")
        ins=decoded[0]
        if len(ins.operands)!=2:
            raise RuntimeError("Original callback-array LEA operands changed")
        dest,source=ins.operands
        if (dest.type!=1 or source.type!=3 or
            ins.reg_name(source.mem.base)!="rip" or source.mem.index!=0):
            raise RuntimeError("Original initializer callback pointer address not RIP-relative")
        return ins.address+ins.size+source.mem.disp
    imports={rva:(dll.lower(),name) for rva,dll,name in import_slots(pe)}
    table_output=[]
    for name,begin_site,end_site,expected_begin,expected_end in TABLES:
        begin=original_lea_target(begin_site)
        end=original_lea_target(end_site)
        if (begin,end)!=(expected_begin,expected_end):
            raise RuntimeError("Original CRT callback LEA targets moved")
        if (begin&7 or end&7 or not begin<end<=section_end or
            end-begin>512):
            raise RuntimeError("Unsafe original CRT callback table bounds")
        raw=pe.read_rva(begin,end-begin)
        values=struct.unpack("<"+"Q"*((end-begin)//8),raw)
        entries=[]
        for index,value in enumerate(values):
            item={"slot_index":index,"slot_rva":hex(begin+8*index),
                  "null":value==0}
            if value:
                rva=value-BASE
                if not 0<=rva<section_end:
                    raise RuntimeError("CRT callback pointer outside original PE image")
                matches=[(a,b) for a,b in unwind if a<=rva<b]
                if len(matches)>1:
                    raise RuntimeError("Overlapping unwind function intervals")
                if matches:
                    a,b=matches[0]
                    length=min(b-a,MAX_UNWIND_INSPECT)
                else:
                    a=rva
                    length=64
                code=pe.read_rva(a,length)
                inst=list(md.disasm(code,a))
                if not inst:
                    raise RuntimeError("Original initializer callback function undecodable")
                mnemonics=Counter(x.mnemonic for x in inst)
                deps=[]
                for x in inst:
                    if x.mnemonic not in ("call","jmp") or len(x.operands)!=1:
                        continue
                    o=x.operands[0]
                    if o.type==X86_OP_IMM:
                        deps.append({"kind":x.mnemonic,"callee_rva":hex(o.imm)})
                    elif (o.type==X86_OP_MEM and
                          x.reg_name(o.mem.base)=="rip" and o.mem.index==0):
                        slot=x.address+x.size+o.mem.disp
                        dep=imports.get(slot)
                        deps.append({"kind":x.mnemonic,
                                     "iat_import":dep[0]+"::"+dep[1] if dep else None,
                                     "iat_rva":hex(slot)})
                item["bounded_callgraph"]=deps
                print("PRIVATE CALLBACK FIRST INSTRUCTIONS "+
                      name+" slot="+str(index)+" RVA="+hex(rva))
                for x in inst[:12]:
                    print(" PRIVATE FORM "+hex(x.address)+" "+x.mnemonic+" "+x.op_str)
                item.update({
                    "target_rva":hex(rva),
                    "unwind_bounded":bool(matches),
                    "exact_function_entry":rva==a,
                    "inspected_decoded_instructions":len(inst),
                    "inspected_mnemonics":dict(sorted(mnemonics.items())),
                    "has_calls":any(x.mnemonic=="call" for x in inst),
                    "original_callback_executed":False
                })
            entries.append(item)
        table_output.append({"symbol":name,"begin_rva":hex(begin),
                             "end_rva":hex(end),"slots":len(entries),
                             "non_null":sum(not x["null"] for x in entries),
                             "entries":entries})
    return {
        "original_executable_SHA_matched":True,
        "tables":table_output,
        "total_pointer_slots":sum(x["slots"] for x in table_output),
        "non_null_initializer_callbacks":sum(x["non_null"] for x in table_output),
        "limitations":[
            "Original callback tables are inventoried statically, not executed.",
            "Callback pointers may be relocated at runtime; these values are preferred-base addresses.",
            "An empty initializer range does not prove every other Windows startup subsystem is initialized.",
            "No native ARM64 or iOS game startup is claimed."
        ]
    }

def run(exe,output):
    result=inventory(exe)
    output.mkdir(parents=True,exist_ok=True)
    (output/"crt-initializer-tables.json").write_text(json.dumps(result,indent=2)+"\n")
    lines=["# Original MX Bikes CRT initializer callback inventory","",
           "- Total original pointer slots: **"+str(result["total_pointer_slots"])+"**",
           "- Non-null callbacks requiring actual execution or validated no-op semantics: **"+
            str(result["non_null_initializer_callbacks"])+"**","",
           "| Original imported CRT function | Pointer slots | Non-null callbacks |",
           "| --- | ---: | ---: |"]
    for x in result["tables"]:
        lines.append("| "+x["symbol"]+" | "+str(x["slots"])+" | "+str(x["non_null"])+" |")
    lines.extend(["","## Five original callback dependencies","","| Table | Slot | Callback RVA | Unwind bounded | Decoded instructions inspected |",
                  "| --- | ---: | --- | --- | ---: |"])
    for table in result["tables"]:
        for e in table["entries"]:
            if e["null"]:
                continue
            lines.append("| "+table["symbol"]+" | "+str(e["slot_index"])+" | "+
                         e["target_rva"]+" | "+
                         ("yes" if e["unwind_bounded"] else "no")+" | "+
                         str(e["inspected_decoded_instructions"])+" |")
            # Metadata-only private CI logs (no PE bytes or disassembly export).
            print("PRIVATE CRT CALLBACK METADATA: "+json.dumps({
                "table":table["symbol"],"slot":e["slot_index"],
                "target_rva":e["target_rva"],"unwind":e["unwind_bounded"],
                "exact_entry":e["exact_function_entry"],
                "inspected_instructions":e["inspected_decoded_instructions"],
                "mnemonics":e["inspected_mnemonics"],
                "dependencies":e["bounded_callgraph"]
            },sort_keys=True))
    # Analyze the remaining three related callbacks together, using only
    # per-function aggregate mnemonic counts rather than original code bytes.
    unresolved={"0x2ab234","0x2aafc4","0x320770"}
    candidate_profiles={
        entry["target_rva"]:entry["inspected_mnemonics"]
        for table in result["tables"] for entry in table["entries"]
        if not entry["null"] and entry["target_rva"] in unresolved
    }
    if set(candidate_profiles)!=unresolved:
        raise RuntimeError("The three original CRT callback families changed")
    summary=aggregate_callbacks(candidate_profiles)
    joint=summary["grouped_instruction_profile"]
    if joint["instruction_total"]!=77:
        raise RuntimeError("Pinned CRT callback instruction inventory drifted")
    lines += ["","## Three unresolved callbacks, grouped translator readiness","",
              "| Callback RVA | Original decoded instructions | Recognized instruction names | Unrecognized instruction names |",
              "| --- | ---: | ---: | ---: |"]
    for rva in sorted(candidate_profiles):
        item=summary["callbacks"][rva]
        lines.append("| "+rva+" | "+
                     str(item["instruction_total"])+" | "+
                     str(item["mnemonics_currently_recognized"])+" | "+
                     str(item["mnemonics_needing_extensions"])+" |")
    lines.extend(["","- Recognized instruction **names** across all three: **"+
                  str(joint["mnemonics_currently_recognized"])+"/"+
                  str(joint["instruction_total"])+"**",
                  "- Operand widths/encodings, direct callee bodies, imported CRT services, branching and guest effects **not verified** by this summary.",
                  "- Do not confuse a recognized mnemonic with a successfully translated or executed callback.",""])
    (output / "crt-callback-family-gaps.json").write_text(
        json.dumps(summary,indent=2)+"\\n")
    # Compile both first-blocker callbacks plus the adjacent _initterm
    # callback (with verified direct tail-call target) in one bounded batch.
    # Generated game-derived C and objects exist ONLY in
    # the ephemeral private runner; public and private Actions artifacts
    # receive metadata, never recovered code or compiler diagnostic snippets.
    import tempfile
    import subprocess
    pe=PE(exe)
    spans=unwind_functions(pe)
    iat={rva:(dll,name) for rva,dll,name in import_slots(pe)}
    compile_batches={
        0x2ab234:("lifted_original_init_e1",{0x2ab7fc,0x2ab950}),
        0x2aafc4:("lifted_original_init_i1",{0x2ab7e4,0x2ab72c}),
        0x320770:("lifted_original_init_i2",{0x2d2a70,0x2ab7e4}),
    }
    readiness=[]
    with tempfile.TemporaryDirectory(prefix="mx-crt-private-compile-frontier-") as td:
        private=Path(td)
        for rva,(fn,locals_allowed) in compile_batches.items():
            # A short tail thunk may have no unwind record; its exact
            # endpoint is the verified next callback's table target.
            end=(0x320790 if rva==0x320770 else spans.get(rva))
            if not end or end<=rva or end-rva>768:
                raise RuntimeError("Bounded original CRT callback changed")
            record={"callback_rva":hex(rva),
                    "local_targets":[hex(x) for x in sorted(locals_allowed)],
                    "function_lowered":False,
                    "aarch64_object_compiled":False,
                    "authentic_arm64_execution_verified":False,
                    "imported_crt_services_executed":False}
            try:
                source,meta=lift_crt_import_cluster(
                    pe.read_rva(rva,end-rva),rva,iat,{},BASE,
                    local_targets=locals_allowed,function_name=fn)
            except UnsupportedCluster as e:
                record["blocker_kind"]="lifter_unsupported"
                record["blocker_description"]=str(e)[:160]
            else:
                record["function_lowered"]=True
                record["ins_count"]=meta["decoded_instructions"]
                record["import_call_sites"]=meta["import_calls"]
                record["local_call_sites"]=meta["local_call_sites"]
                record["external_service_names"]=meta["unique_import_services"]
                original_source=private/(fn+".c")
                compiled_object=private/(fn+".o")
                original_source.write_text(source)
                command=[
                    "clang","--target=aarch64-unknown-linux-gnu",
                    "-std=c11","-O2","-Wall","-Wextra","-Werror",
                    "-ffreestanding","-fno-builtin","-fno-stack-protector",
                    "-I"+str(ROOT/"arm64-lab"/"runtime"),
                    "-c",str(original_source),"-o",str(compiled_object)
                ]
                compilation=subprocess.run(command,capture_output=True,text=True)
                record["aarch64_object_compiled"]=(
                    compilation.returncode==0 and compiled_object.is_file())
                if not record["aarch64_object_compiled"]:
                    record["blocker_kind"]="compiler_error"
                    record["compiler_exit_code"]=compilation.returncode
            readiness.append(record)
    (output/"crt-callback-aot-readiness.json").write_text(
        json.dumps(readiness,indent=2)+"\\n")
    lines.extend(["","## Three remaining original callbacks: AArch64 object feasibility","","| Callback RVA | Lowered C | AArch64 object | Local calls | CRT imports |",
                  "| --- | --- | --- | ---: | ---: |"])
    for item in readiness:
        lines.append("| "+item["callback_rva"]+" | "+
                     ("yes" if item["function_lowered"] else "no")+" | "+
                     ("yes" if item["aarch64_object_compiled"] else "no")+" | "+
                     str(item.get("local_call_sites","—"))+" | "+
                     str(item.get("import_call_sites","—"))+" |")
        if item.get("blocker_kind"):
            lines.append("- "+item["callback_rva"]+" compiler frontier: "+
                         item["blocker_kind"]+" ("+
                         item.get("blocker_description","see private CI metadata")+")")
    lines.extend(["","**A compiled AArch64 object is NOT a verified differential or CRT callback execution. Its native local-callee mappings, imported CRT services and guest state remain unresolved.**",""])

    lines+=["","**Static inventory only: no original callback functions or MSVCR90.dll have executed.**",""]
    summary="\n".join(lines)
    (output/"crt-initializer-tables.md").write_text(summary)
    print(summary)

if __name__=="__main__":
    if len(sys.argv)!=3:
        raise SystemExit("usage: script.py /private/original-game.exe report-dir")
    run(Path(sys.argv[1]),Path(sys.argv[2]))
