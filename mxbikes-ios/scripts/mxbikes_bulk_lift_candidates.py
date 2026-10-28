#!/usr/bin/env python3
"""Choose a balanced full-game Remill pilot from the verified static map.

Only original hex input and private manifests go into the ephemeral CI temp dir.
No lifted code, original bytes or executable goes into repository/artifacts.
All statuses initially unproven; compiler and execution outcomes checked later.
"""
from collections import Counter
from pathlib import Path
import json
import sys

from capstone import Cs,CS_ARCH_X86,CS_MODE_64,CS_GRP_CALL,CS_GRP_JUMP,CS_GRP_RET
from mxbikes_whole_game_map import map_executable
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/"arm64-lab"))
from tools.pe_probe import PE

MAX_PILOT=48
MAX_BYTES=2048

def select(exe,dest):
    inventory=map_executable(exe)
    pe=PE(exe)
    rows=[x for x in inventory["interval_map"] if
          x["status"]=="decoded_linear" and 4<=x["bytes"]<=MAX_BYTES]
    pools={
      "closest_to_game_main":sorted(
         (x for x in rows if x.get("depth_from_known_roots") is not None),
         key=lambda x:(x.get("depth_from_known_roots",99),x["bytes"])),
      "calls":sorted((x for x in rows if x["direct_calls"]>=2),
                    key=lambda x:(-x["direct_calls"],x["bytes"])),
      "import_boundaries":sorted((x for x in rows if x["import_thunk_calls"]>=1),
                                key=lambda x:(-x["import_thunk_calls"],x["bytes"])),
      "medium_functions":sorted((x for x in rows if 128<=x["bytes"]<=512),
                                key=lambda x:(x["bytes"],int(x["rva"],16))),
      "larger_functions":sorted((x for x in rows if 512<x["bytes"]<=MAX_BYTES),
                                key=lambda x:(x["bytes"],int(x["rva"],16))),
      "simple_leaf":sorted((x for x in rows if not x["direct_calls"] and
                           not x["indirect_calls"] and not x["import_thunk_calls"] and
                           x["ret_count"]>=1 and 12<=x["bytes"]<=128),
                          key=lambda x:(x["bytes"],int(x["rva"],16))),
    }
    quotas={"closest_to_game_main":8,"calls":8,"import_boundaries":8,
            "medium_functions":8,"larger_functions":8,"simple_leaf":8}
    selected=[]
    visited=set()
    for label,pool in pools.items():
        count=0
        for row in pool:
            start=int(row["rva"],16)
            if start in visited:
                continue
            visited.add(start)
            selected.append((label,row))
            count+=1
            if count>=quotas[label] or len(selected)>=MAX_PILOT:
                break
    if len(selected)<12:
        raise RuntimeError("Insufficient original function diversity for Remill batch")
    dest.mkdir(parents=True,exist_ok=True)
    decoder=Cs(CS_ARCH_X86,CS_MODE_64)
    decoder.detail=True
    records=[]
    for group,row in selected:
        start=int(row["rva"],16)
        blob=pe.read_rva(start,row["bytes"])
        instructions=list(decoder.disasm(blob,start))
        if not instructions or sum(i.size for i in instructions)!=len(blob):
            raise RuntimeError("Selected function no longer completely decodes")
        first=next((i for i in instructions if i.group(CS_GRP_CALL) or
                      i.group(CS_GRP_JUMP) or i.group(CS_GRP_RET)),None)
        basic_len=(first.address+first.size-start if first else len(blob))
        key=f"fn_{start:08x}"
        (dest/(key+".hex")).write_text(blob.hex()+"\n")
        (dest/(key+".basic")).write_text(blob[:basic_len].hex()+"\n")
        records.append({"key":key,"rva":hex(start),"bytes":len(blob),
                        "instructions":row["instructions"],"group":group,
                        "first_basic_block_bytes":basic_len,
                        "has_direct_calls":row["direct_calls"]>0,
                        "has_indirect_calls":row["indirect_calls"]>0,
                        "has_import_call":row["import_thunk_calls"]>0})
    manifest={"whole_executable_unwind_count":inventory["statistics"]["unique_unwind_intervals"],
              "whole_executable_decoded_count":inventory["statistics"]["fully_linear_decoded_intervals"],
              "pilot_selected_count":len(records),"pilot":records}
    (dest/"pilot-private.json").write_text(json.dumps(manifest,indent=2)+"\n")
    print(f"Selected {len(records)} original functions across {dict(Counter(x['group'] for x in records))}; "
          f"{sum(x['bytes'] for x in records)} total original bytes, held only in private CI.")
    return manifest

if __name__=="__main__":
    if len(sys.argv)!=3:
        raise SystemExit("usage: script.py owned-mxbikes.exe private-work-dir")
    select(Path(sys.argv[1]),Path(sys.argv[2]))
