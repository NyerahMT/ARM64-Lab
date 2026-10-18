"""Read-only import compatibility audit: static names + observed x64 diagnostic calls.

This tool only classifies known interface names, not executable DLL code.
Unknown IAT entries are *not* presumed functions: PE import tables do not
distinguish functions from imported data in a general, reliable way.
"""
from collections import Counter
import zipfile

SYSTEM = set("kernel32.dll kernelbase.dll ntdll.dll user32.dll gdi32.dll opengl32.dll winmm.dll shell32.dll ole32.dll oleaut32.dll advapi32.dll version.dll comdlg32.dll comctl32.dll shlwapi.dll ws2_32.dll dinput8.dll dsound.dll imm32.dll setupapi.dll".split())
CRT = set("msvcr90.dll msvcp90.dll msvcrt.dll vcruntime140.dll ucrtbase.dll".split())
TIMING = set("kernel32.dll!gettickcount winmm.dll!timegettime kernel32.dll!queryperformancecounter kernel32.dll!queryperformancefrequency kernel32.dll!getsystemtimeasfiletime kernel32.dll!sleep".split())
CONFIRMED_DATA = {"msvcr90.dll!_acmdln"}
FILE_BRIDGE = set("msvcr90.dll!fopen msvcr90.dll!fread msvcr90.dll!fseek msvcr90.dll!ftell msvcr90.dll!fclose msvcr90.dll!fgetc msvcr90.dll!feof msvcr90.dll!ferror msvcr90.dll!rewind".split())
SYNTHETIC = set("kernel32.dll!getstartupinfoa kernel32.dll!getcurrentprocessid kernel32.dll!getcurrentthreadid kernel32.dll!getmodulefilenamea kernel32.dll!setcurrentdirectorya kernel32.dll!setunhandledexceptionfilter msvcr90.dll!__set_app_type msvcr90.dll!_initterm msvcr90.dll!_initterm_e msvcr90.dll!_encode_pointer msvcr90.dll!_decode_pointer msvcr90.dll!_ismbblead msvcr90.dll!_onexit msvcr90.dll!__getmainargs msvcr90.dll!strcpy steam_api64.dll!steamapi_restartappifnecessary".split())
STEAM_REQUIRED = {"steam_api64.dll!steamapi_init"}
assert len(TIMING|CONFIRMED_DATA|FILE_BRIDGE|SYNTHETIC|STEAM_REQUIRED)==sum(len(x) for x in (TIMING,CONFIRMED_DATA,FILE_BRIDGE,SYNTHETIC,STEAM_REQUIRED))

def norm_dll(name):
    if not isinstance(name,str) or not name or '/' in name or '\\' in name or '..' in name:
        raise ValueError("DLL must be a simple basename")
    return name.casefold()

def status(dll,sym):
    key=dll+'!'+sym.casefold()
    if key in CONFIRMED_DATA:return "confirmed_data_import"
    if key in TIMING:return "portable_timing_core_not_wired_to_game"
    if key in FILE_BRIDGE:return "private_x64_file_bridge_only"
    if key in SYNTHETIC:return "synthetic_x64_response_only"
    if key in STEAM_REQUIRED:return "needs_real_steam_integration"
    return "unclassified_or_not_implemented"

def archive_index(archives):
    result={}
    for archive in archives:
        with zipfile.ZipFile(archive) as z:
            for member in z.infolist():
                if member.is_dir():continue
                name=member.filename.replace('\\','/').split('/')[-1].casefold()
                if name.endswith('.dll'):
                    result.setdefault(name,[]).append({"archive":archive.name,"size_bytes":member.file_size})
    return result

def audit_inventory(inventory,trace=None,archives=None):
    imported=inventory.get('imports')
    if not isinstance(imported,dict) or not imported:raise ValueError("Missing PE import inventory")
    trace=trace or {}
    counts=trace.get("windows_imports_called",{})
    if not isinstance(counts,dict):raise ValueError("Expected call counters")
    observed={}
    for key,n in counts.items():
        if "::" not in key or not isinstance(n,int) or n<0:raise ValueError("Malformed x64 import trace")
        dll,sym=key.split("::",1)
        norm=norm_dll(dll)+'!'+sym.casefold()
        observed[norm]=observed.get(norm,0)+n
    archives=archives or {}
    rows=[];libs=[];totals=Counter();matched=set()
    for original,syms in sorted(imported.items(),key=lambda x:x[0].casefold()):
        dll=norm_dll(original)
        if not isinstance(syms,list):raise ValueError("Import symbols must be list")
        libcalls=0
        for sym in syms:
            if not isinstance(sym,str) or not sym:raise ValueError("Invalid import symbol")
            kind=status(dll,sym)
            key=dll+'!'+sym.casefold()
            calls=observed.get(key,0)
            if calls:matched.add(key)
            libcalls+=calls
            totals[kind]+=1
            rows.append({"dll":dll,"symbol":sym,"kind":"data" if kind=="confirmed_data_import" else "unknown_data_or_function","status":kind,"observed_x64_calls":calls})
        role="steam" if dll.startswith("steam_api") else ("crt" if dll in CRT else ("windows_system" if dll in SYSTEM else "other"))
        libs.append({"dll":dll,"category":role,"imports":len(syms),"observed_x64_calls":libcalls,"private_archive_copies":archives.get(dll,[])})
    return {
        "input_sha256":inventory.get("sha256"),"total_imports":len(rows),"dll_count":len(libs),
        "trace_calls_matched":sum(r["observed_x64_calls"] for r in rows),
        "trace_calls_unmatched":[{"import":k,"calls":observed[k]} for k in sorted(set(observed)-matched)],
        "classification_counts":dict(totals),"libraries":libs,
        "imports":sorted(rows,key=lambda r:(-r["observed_x64_calls"],r["dll"],r["symbol"])),
        "trace_stopped_at":trace.get("unimplemented_import"),
        "caveats":[
            "Static PE imports cannot reliably distinguish all data and function symbols.",
            "Private x64 diagnostic shims are not native ARM64/Metal/iOS implementations.",
            "Archived DLL presence does not imply DLL executability on iOS.",
            "GetProcAddress and late-loaded DLL dependencies may be absent from static imports.",
            "SteamAPI_Init needs authentic service behavior; no production Steam runtime has been demonstrated.",
        ],
    }

def markdown_summary(r):
    lines=["# MX Bikes DLL compatibility inventory","",
           f"- Imported libraries: **{r['dll_count']}**",
           f"- Imported symbols: **{r['total_imports']}**",
           f"- Observed import invocations in bounded x64 trace: **{r['trace_calls_matched']}**",
           f"- Unmatched traced names: **{len(r['trace_calls_unmatched'])}**",
           f"- Current blocker: **{r['trace_stopped_at'] or 'not recorded'}**","",
           "| Library | Class | Static imports | Calls in x64 trace | Archived DLL? |",
           "| --- | --- | ---: | ---: | --- |"]
    for lib in r["libraries"]:
        lines.append(f"| {lib['dll']} | {lib['category']} | {lib['imports']} | {lib['observed_x64_calls']} | {'Yes' if lib['private_archive_copies'] else 'No'} |")
    lines += ["","## Status of statically imported symbols","","| Evidence category | Count |","| --- | ---: |"]
    for key,n in sorted(r["classification_counts"].items()):lines.append(f"| {key} | {n} |")
    lines += ["","## Actually invoked imports","","| Imported symbol | Calls | Current status |","| --- | ---: | --- |"]
    for row in r["imports"]:
        if row["observed_x64_calls"]:
            lines.append(f"| {row['dll']}!{row['symbol']} | {row['observed_x64_calls']} | {row['status']} |")
    if r["trace_calls_unmatched"]:
        lines+=["","## Traced names absent from static inventory",""]
        lines += [f"- {q['import']}: {q['calls']}" for q in r["trace_calls_unmatched"]]
    lines+=["","## Limitations",""]+["- "+c for c in r["caveats"]]
    return "\n".join(lines)+"\n"
