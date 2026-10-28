#!/usr/bin/env python3
"""Privacy-safe original startup CALL dependency graph for ARM64 planning.

Scan the exact .pdata ranges observed in private original x64 execution. Do
not infer full CFG, translate machine bytes, invent Steamworks authorization,
or mark functions native. Classify direct relative calls, literal RIP-relative
IAT calls, other indirect calls, and control transfers. Only bounded metadata
(RVA, class, import symbol) leaves the ephemeral original game runner.
"""
from capstone import Cs,CS_ARCH_X86,CS_MODE_64,CS_GRP_CALL
from capstone.x86 import X86_OP_IMM,X86_OP_MEM
from collections import Counter

MAX_FUNCTIONS=128
MAX_LENGTH=32768
MAX_CALL_EDGES=4096
MAX_NAMED_TARGETS=20

def _imports(slots):
    result={}
    if len(slots)>4096:
        raise ValueError("Too many original imports")
    for rva,lib,name in slots:
        if rva in result:raise ValueError("Duplicate original IAT RVA")
        result[rva]=(lib,name)
    return result

def classify_original_startup_calls(pe,priority,imports,*,base):
    data=priority.get("prioritized_original_functions")
    if not isinstance(data,list) or len(data)>MAX_FUNCTIONS:
        raise ValueError("Unbounded original dynamic startup queue")
    imp=_imports(imports)
    decoder=Cs(CS_ARCH_X86,CS_MODE_64)
    decoder.detail=True
    items=[]
    totals=Counter()
    for row in data:
        start=int(row["original_function_entry_rva"],16)
        end=int(row["original_unwind_end_rva"],16)
        if end<=start or end-start>MAX_LENGTH:
            raise ValueError("Unbounded original x64 function interval")
        try:raw=bytes(pe.read_rva(start,end-start))
        except (ValueError,OverflowError):
            items.append({"original_function_entry_rva":hex(start),
                          "status":"original_unwind_window_unreadable",
                          "native_function_verified":False})
            continue
        ins=list(decoder.disasm(raw,base+start))
        if sum(i.size for i in ins)!=len(raw):
            items.append({"original_function_entry_rva":hex(start),
                          "status":"partial_original_linear_decode",
                          "native_function_verified":False})
            continue
        names=[]
        destinations=[]
        group=Counter()
        call_count=0
        for code in ins:
            if not code.group(CS_GRP_CALL):
                continue
            call_count+=1
            if call_count>MAX_CALL_EDGES:
                raise ValueError("Excessive original CALL edges")
            op=code.operands[0] if code.operands else None
            if op is not None and op.type==X86_OP_IMM:
                target=op.imm-base
                if target<0:
                    group["external_direct_CALL"]+=1
                else:
                    group["original_direct_CALL"]+=1
                    if len(destinations)<MAX_NAMED_TARGETS:
                        destinations.append(hex(target))
                continue
            if op is not None and op.type==X86_OP_MEM:
                m=op.mem
                if code.reg_name(m.base)=="rip" and not m.index:
                    slot=code.address+code.size+m.disp-base
                    if slot in imp:
                        lib,symbol=imp[slot]
                        cls=("Steamworks_authorization_external" if
                             lib.lower() in ("steam_api64.dll","steam_api.dll")
                             else "Windows_or_CRT_import")
                        group[cls]+=1
                        if len(names)<MAX_NAMED_TARGETS:
                            names.append(lib+"::"+symbol)
                        continue
            group["unresolved_indirect_CALL"]+=1
        totals.update(group)
        items.append({
            "original_function_entry_rva":hex(start),
            "original_original_x64_function_linearly_decoded":True,
            "observed_original_instruction_hits":row["post_main_instruction_hits"],
            "original_callsites":call_count,
            "call_edge_classes":dict(group),
            "direct_original_callee_rvas":sorted(set(destinations),key=lambda x:int(x,16)),
            "named_iat_imports":sorted(set(names)),
            "requires_native_call_or_service_linkage":bool(call_count),
            "native_function_verified":False,
            "original_bytes_exported":False,
        })
    return {
        "schema":1,
        "source":"original SHA-pinned x64 PE .pdata ranges prioritized by observed x64 startup PCs",
        "original_function_windows_examined":len(data),
        "full_callsite_edge_classes":dict(totals),
        "functions_with_original_direct_calls":sum(
            x.get("call_edge_classes",{}).get("original_direct_CALL",0)>0 for x in items),
        "functions_with_original_IAT_imports":sum(
            (x.get("call_edge_classes",{}).get("Windows_or_CRT_import",0)+
             x.get("call_edge_classes",{}).get("Steamworks_authorization_external",0))>0
            for x in items),
        "startup_original_function_dependencies":items,
        "contains_proprietary_machine_bytes":False,
        "native_ARM64_original_functions_verified_by_this_scan":0,
        "steamworks_authorization_bypassed":False,
        "game_executed_on_ARM64":False,
    }
