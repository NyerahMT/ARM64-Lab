#!/usr/bin/env python3
"""Privacy-safe dynamic startup function priority from actual original x64 PCs.

Maps executed instruction RVAs to SHA-pinned PE .pdata unwind intervals. This
is an *observed original x64 instruction trace*, not verified ARM64 functions,
not translation readiness, and not a Steam bypass. Unwind gaps are explicitly
unowned; never manufacture function start addresses from those PCs.

Emits metadata (RVA, counts, category) only. No machine bytes, assets,
disassembly, guest memory, private file contents, or authorization tokens.
"""
from bisect import bisect_right
from collections import defaultdict
from math import isqrt

MAX_PC_KEYS=300000
MAX_UNWIND_INTERVALS=600000
MAX_WAVE_ENTRIES=128

def prioritize_original_startup(unwind, all_pc_hits, main_pc_hits, *,
                                main_rva, entry_rva, crt_rva, top=64):
    if not 1<=top<=MAX_WAVE_ENTRIES:
        raise ValueError("Unbounded original startup translation queue")
    if (not isinstance(unwind,dict) or len(unwind)>MAX_UNWIND_INTERVALS or
        len(all_pc_hits)>MAX_PC_KEYS or len(main_pc_hits)>MAX_PC_KEYS):
        raise ValueError("Original PC/unwind inventory exceeds bounded profile")
    spans=sorted(unwind.items())
    starts=[lo for lo,_ in spans]
    ends=[hi for _,hi in spans]
    if any(not isinstance(lo,int) or not isinstance(hi,int) or
           lo<0 or hi<=lo or hi>1<<32 for lo,hi in spans):
        raise ValueError("Invalid original PE unwind range")
    if any(ends[i]>starts[i+1] for i in range(len(spans)-1)):
        raise ValueError("Overlapping original function intervals")
    for root in (main_rva,entry_rva,crt_rva):
        if not isinstance(root,int) or root<0 or root>=1<<32:
            raise ValueError("Invalid original executable startup root")
    def owner(pc):
        i=bisect_right(starts,pc)-1
        return starts[i] if i>=0 and pc<ends[i] else None
    aggregate=defaultdict(lambda:{"original_instruction_hits":0,
                                  "post_main_instruction_hits":0,
                                  "unique_original_pc_rvas":0,
                                  "unique_post_main_pc_rvas":0})
    misses={"total_hits":0,"after_main_hits":0,"unique_unowned_pc_rvas":0}
    all_count=0
    main_count=0
    for pc,hits in all_pc_hits.items():
        if not isinstance(pc,int) or not 0<=pc<1<<32 or not isinstance(hits,int) or hits<=0:
            raise ValueError("Untrusted original x64 PC hit counts")
        after=main_pc_hits.get(pc,0)
        if not isinstance(after,int) or after<0 or after>hits:
            raise ValueError("Post-main original trace must be subset of all hits")
        all_count+=hits
        main_count+=after
        entry=owner(pc)
        if entry is None:
            misses["total_hits"]+=hits
            misses["after_main_hits"]+=after
            misses["unique_unowned_pc_rvas"]+=1
            continue
        row=aggregate[entry]
        row["original_instruction_hits"]+=hits
        row["post_main_instruction_hits"]+=after
        row["unique_original_pc_rvas"]+=1
        if after>0:row["unique_post_main_pc_rvas"]+=1
    for pc,count in main_pc_hits.items():
        if pc not in all_pc_hits:
            raise ValueError("Post-main trace refers to unexecuted PC")
        if not isinstance(count,int) or count<0:
            raise ValueError("Invalid post-main hit count")
    priorities=[]
    roots={"game_main":main_rva,"crt_startup":crt_rva,"pe_entry":entry_rva}
    for function,row in aggregate.items():
        # Prioritize confirmed post-main use and multiple distinct executed PCs;
        # cap loop frequency so tight steam DLL file-reading loops don't
        # eclipse unique engine initialization dependency coverage.
        post=row["post_main_instruction_hits"]
        distinct=row["unique_post_main_pc_rvas"]
        score=distinct*1000+isqrt(min(post,100000))*25+min(post,2000)
        lane="game_main_observed" if post>0 else "crt_or_entry_observed"
        matched=[name for name,root in roots.items() if owner(root)==function]
        priorities.append({
            "original_function_entry_rva":hex(function),
            "original_unwind_end_rva":hex(unwind[function]),
            "phase":lane,
            "root_labels":matched,
            "priority_score":score if post>0 else row["unique_original_pc_rvas"],
            "candidate_only_no_native_proof":True,
            **row,
        })
    priorities.sort(key=lambda x:(
        0 if x["post_main_instruction_hits"] else 1,
        -x["priority_score"],
        -x["unique_original_pc_rvas"],
        int(x["original_function_entry_rva"],16)))
    root_status={}
    for name,root in roots.items():
        function=owner(root)
        root_status[name]={
            "requested_root_rva":hex(root),
            "containing_unwind_function_rva":hex(function) if function is not None else None,
            "original_function_observed":function in aggregate if function is not None else False,
            "native_arm64_execution_proved":False,
        }
    return {
        "schema":1,
        "evidence":"actual original SHA-pinned x64 Unicorn guest instruction PCs",
        "meaning":"native translator batch priority; these original functions have NOT been ARM64 translated or verified",
        "total_original_x64_instruction_hits":all_count,
        "observed_original_instructions_after_main_entry":main_count,
        "unique_original_x64_instruction_rvas":len(all_pc_hits),
        "original_pdata_unwind_intervals":len(unwind),
        "distinct_observed_pdata_function_intervals":len(aggregate),
        "distinct_observed_after_main_pdata_intervals":sum(
            x["post_main_instruction_hits"]>0 for x in aggregate.values()),
        "unowned_original_pc_trace":misses,
        "roots":root_status,
        "queue_entries_total":len(priorities),
        "queue_entries_emitted":min(len(priorities),top),
        "queue_truncated":len(priorities)>top,
        "prioritized_original_functions":priorities[:top],
        "original_game_booted_on_native_arm64":False,
        "steamworks_authorization_implemented":False,
        "guest_asset_or_binary_bytes_exported":False,
    }
