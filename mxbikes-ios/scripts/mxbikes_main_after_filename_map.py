#!/usr/bin/env python3
"""SHA-pinned authentic original game-main next control after filename RET.

Bounded *original x64* static successor shape, with no original bytes,
translated code or generated native object written to public files. Both
a mapped straightline path and its first conditional successors are grouped
to avoid one-function-at-a-time discovery. Only metadata is persisted.
"""
from pathlib import Path
import hashlib,json,sys
from capstone import Cs,CS_ARCH_X86,CS_MODE_64,CS_GRP_CALL,CS_GRP_JUMP,CS_GRP_RET
from capstone.x86 import X86_OP_IMM,X86_OP_MEM
from mxbikes_first_callee_emu import import_slots
from mxbikes_joined_strcpy_native import EXE_SHA
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/"arm64-lab"))
from tools.pe_probe import PE

AFTER_FILENAME_RETURN=0x136769
MAX_BYTES=320
MAX_STRAIGHT=48
MAX_DEPTH=2
MAX_NODES=12

def block(pe,decoder,entry,symbols):
    forms=[]
    control=None
    for ins in decoder.disasm(pe.read_rva(entry,MAX_BYTES),entry):
        if ins.group(CS_GRP_CALL) or ins.group(CS_GRP_JUMP) or ins.group(CS_GRP_RET):
            control=ins
            break
        if ins.mnemonic in ("syscall","sysenter","hlt","ud2","int3"):
            raise RuntimeError("Unsupported original post-filename instruction "+hex(ins.address))
        forms.append(ins)
        if len(forms)>MAX_STRAIGHT:
            raise RuntimeError("Post-filename x64 block exceeds cap")
    if control is None:
        raise RuntimeError("No original main control within bounded decode")
    info={
        "entry_rva":hex(entry),
        "straightline_original_instructions":len(forms),
        "first_control_rva":hex(control.address),
        "first_control_mnemonic":control.mnemonic,
        "first_control_operands":control.op_str,
        "first_control_size":control.size,
        "original_guest_executed":False,
        "native_arm64_executed":False,
        "forms":[
            {"rva":hex(ins.address),"mnemonic":ins.mnemonic,"operands":ins.op_str}
            for ins in forms
        ],
    }
    follow=[]
    if control.group(CS_GRP_JUMP) and control.mnemonic!="jmp":
        follow.append(control.address+control.size)
    if len(control.operands)==1 and control.operands[0].type==X86_OP_IMM:
        dest=int(control.operands[0].imm)
        info["original_direct_destination_rva"]=hex(dest)
        if control.mnemonic.startswith("j"):
            follow.append(dest)
    elif len(control.operands)==1 and control.operands[0].type==X86_OP_MEM:
        op=control.operands[0]
        if control.reg_name(op.mem.base)=="rip" and not op.mem.index:
            slot=control.address+control.size+op.mem.disp
            info["original_indirect_pointer_rva"]=hex(slot)
            if slot in symbols:
                info["named_original_import"]=symbols[slot]
    if control.group(CS_GRP_CALL):
        follow.append(control.address+control.size)
    return info,follow

def run(executable,out):
    pe=PE(executable)
    if hashlib.sha256(pe.b).hexdigest()!=EXE_SHA:
        raise RuntimeError("Original executable SHA drift")
    decoder=Cs(CS_ARCH_X86,CS_MODE_64);decoder.detail=True
    symbols={slot:{"dll":dll,"symbol":symbol}
             for slot,dll,symbol in import_slots(pe)}
    visited=set()
    queue=[(AFTER_FILENAME_RETURN,0)]
    mapped=[]
    while queue and len(mapped)<MAX_NODES:
        rva,depth=queue.pop(0)
        if rva in visited:
            continue
        visited.add(rva)
        shape,children=block(pe,decoder,rva,symbols)
        shape["depth"]=depth
        mapped.append(shape)
        if depth<MAX_DEPTH:
            queue.extend((child,depth+1) for child in children
                         if child>=0x1000 and child<0x800000)
    # Discover the next original direct callee as one bounded dependency
    # cluster. This is static-only discovery, never a claim of execution.
    callee_root=0x133e80
    pending=[(callee_root,0)]
    callee_seen=set()
    callee_group=[]
    while pending and len(callee_group)<8:
        pc,depth=pending.pop(0)
        if pc in callee_seen:
            continue
        callee_seen.add(pc)
        try:
            original,children=block(pe,decoder,pc,symbols)
        except RuntimeError as exc:
            callee_group.append({
                "entry_rva":hex(pc),
                "status":"unresolved_original_decode_boundary",
                "reason":str(exc),
                "native_arm64_executed":False
            })
            continue
        original["depth"]=depth
        callee_group.append(original)
        if depth<1:
            pending.extend((x,depth+1) for x in children
                           if 0x1000<=x<0x800000)
    report={
        "original_sha_verified":True,
        "game_main_resumed_rva":hex(AFTER_FILENAME_RETURN),
        "static_bounded_successors":mapped,
        "next_direct_callee_rva":hex(callee_root),
        "next_callee_static_dependency_cluster":callee_group,
        "next_callee_native_aarch64_executed":False,
        "unknown_original_dynamic_callees_are_native_ready":False,
        "original_x64_continuation_executed":False,
        "native_arm64_continuation_executed":False,
        "notes":"Only bounded original x64 direct-CFG discovery; follow-up dynamic x64/ARM64 still required",
    }
    out.mkdir(parents=True,exist_ok=True)
    (out/"post-filename-main-map.json").write_text(json.dumps(report,indent=2)+"\n")
    lines=["# Original MX Bikes game main after filename helper RET","",
           "- Entry **"+hex(AFTER_FILENAME_RETURN)+"**",
           "- Mapped bounded original x64 blocks: **"+str(len(mapped))+"**",""]
    for item in mapped:
        lines += ["## "+item["entry_rva"],"",
            "- Original straight-line instructions: **"+str(item["straightline_original_instructions"])+"**",
            "- First control: **"+item["first_control_rva"]+" "+
               item["first_control_mnemonic"]+" "+item["first_control_operands"]+"**",
            "- Named imported service: **"+str(item.get("named_original_import") or "none")+"**",""]
        lines.extend("- "+x["rva"]+" "+x["mnemonic"]+" "+x["operands"] for x in item["forms"])
        lines.append("")
    lines.extend(["## Next original game-internal callee dependency cluster","",
                  "- Direct target: **"+hex(callee_root)+"**",
                  "- Bounded blocks: **"+str(len(callee_group))+"**",""])
    for item in callee_group:
        lines.append("- "+item["entry_rva"]+": "+
                     (item.get("first_control_rva","unresolved")+" "+
                      item.get("first_control_mnemonic","decoder budget/fault"))+
                     " (native unexecuted)")
        for ins in item.get("forms",[]):
            lines.append("  - "+ins["rva"]+" "+ins["mnemonic"]+" "+ins["operands"])
    lines.extend(["","**Discovery only. Native and original full-path dynamic continuation not yet executed.**"])
    summary="\n".join(lines)+"\n"
    (out/"post-filename-main-map.md").write_text(summary)
    print(summary)
    return report

if __name__=="__main__":
    if len(sys.argv)!=3:
        raise SystemExit("usage: script.py PRIVATE_ORIGINAL_EXE METADATA_OUTPUT")
    run(Path(sys.argv[1]),Path(sys.argv[2]))
