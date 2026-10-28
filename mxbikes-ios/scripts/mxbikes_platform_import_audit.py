#!/usr/bin/env python3
"""Source-verified desktop import dependency inventory for original MX Bikes.

SHA-pin the owned executable and inventory import address table. Distinguish
Steamworks desktop-only dependencies, CRT adapters and graphics/input APIs.
Only import names, counts and addresses are exported; no game binaries,
assets, DLL bytes, keys, sessions, or unsupported Steam behaviors.
"""
from collections import Counter
from pathlib import Path
import hashlib,json,sys
from capstone import Cs,CS_ARCH_X86,CS_MODE_64
from capstone.x86 import X86_OP_MEM
from mxbikes_first_callee_emu import import_slots
from mxbikes_whole_game_map import INPUT_SHA

CALL_RVA=0x1306ed
EXPECTED_NAME="SteamAPI_RestartAppIfNecessary"
APP_ID=0xa008c
MAX_IMPORTS=4096
GRAPHICS={"d3d9.dll","d3d11.dll","d3d12.dll","dxgi.dll",
          "opengl32.dll","gdi32.dll","ddraw.dll","glu32.dll"}
INPUT={"xinput1_3.dll","xinput9_1_0.dll","dinput8.dll",
       "dsound.dll","winmm.dll"}
STEAM={"steam_api.dll","steam_api64.dll"}
CRT={"msvcr90.dll","msvcr90d.dll"}

def run(executable,out):
    from tools.pe_probe import PE
    pe=PE(executable)
    if hashlib.sha256(pe.b).hexdigest()!=INPUT_SHA:
        raise ValueError("Unexpected original game SHA")
    slots=import_slots(pe)
    if not 0<len(slots)<=MAX_IMPORTS:
        raise ValueError("Original IAT outside bounded audit")
    items=[]
    for iat,lib,symbol in slots:
        group=("steamworks" if lib.lower() in STEAM else
               "graphics" if lib.lower() in GRAPHICS else
               "input_audio" if lib.lower() in INPUT else
               "legacy_crt" if lib.lower() in CRT else "other")
        items.append({"iat_rva":hex(iat),"module":lib,
                      "symbol":symbol,"category":group})
    steam=[x for x in items if x["category"]=="steamworks"]
    if not any(x["symbol"]==EXPECTED_NAME for x in steam):
        raise ValueError("Original game missing exact Steam imported function")
    # Verify the *original instruction* at known Steam CALL, not just
    # string occurrences or arbitrarily chosen imported symbols.
    decoder=Cs(CS_ARCH_X86,CS_MODE_64)
    ins=list(decoder.disasm(pe.read_rva(CALL_RVA,6),CALL_RVA))
    if len(ins)!=1 or ins[0].mnemonic!="call":
        raise ValueError("Original code no longer has direct IAT CALL")
    expected_slot=CALL_RVA+ins[0].size+0x1f1325
    exact=[x for x in steam if
           int(x["iat_rva"],16)==expected_slot and x["symbol"]==EXPECTED_NAME]
    if len(exact)!=1:
        raise ValueError("Real original Steam CALL IAT slot changed: "+str(expected_slot))
    grouping=Counter(x["category"] for x in items)
    libs=Counter(x["module"] for x in items)
    report={
      "original_exe_sha256":INPUT_SHA,
      "original_import_slot_count":len(items),
      "original_import_modules":len(libs),
      "import_categories":dict(sorted(grouping.items())),
      "steamworks_import_count":len(steam),
      "steamworks_imports":steam,
      "graphics_and_input_imports":[x for x in items if
          x["category"] in ("graphics","input_audio")],
      "import_modules_and_symbol_counts":dict(sorted(libs.items())),
      "first_original_steam_call_rva":hex(CALL_RVA),
      "original_steam_call_slot_rva":hex(expected_slot),
      "original_steam_appid_argument":hex(APP_ID),
      "steam_desktop_client_implemented_for_ios":False,
      "native_game_engine_started":False
    }
    out.mkdir(parents=True,exist_ok=True)
    (out/"original-platform-imports.json").write_text(json.dumps(report,indent=2)+"\n")
    lines=["# MX Bikes — SHA-verified original platform dependency inventory","",
       "- Original imported symbols: **"+str(len(items))+"**",
       "- Original imported DLL modules: **"+str(len(libs))+"**",
       "- Imported Steamworks symbols: **"+str(len(steam))+"**",
       "- Original first Steam imported CALL: **"+hex(CALL_RVA)+"**",
       "- Game app-ID argument: **"+hex(APP_ID)+"**",
       "","## Original Steamworks IAT imports"]
    lines+=["- "+x["symbol"]+" (IAT RVA "+x["iat_rva"]+")" for x in steam]
    lines.extend(["","## Original Windows graphics and input imports"])
    selected=[x for x in items if x["category"] in ("graphics","input_audio")]
    lines+=["- "+x["module"]+"!"+x["symbol"] for x in selected[:100]]
    lines.extend(["","## All imported DLL modules"])
    lines+=["- "+lib+": "+str(n)+" imported symbols" for lib,n in sorted(libs.items())]
    lines.extend(["",
      "This is a dependency inventory; importing a function does not prove",
      "that every game launch path calls it. No Steam license result,",
      "client init, render driver, iPhone port or original assets executed.",""])
    (out/"original-platform-imports.md").write_text("\n".join(lines))
    print("\n".join(lines))
    return report

if __name__=="__main__":
    if len(sys.argv)!=3:
        raise SystemExit("usage: platform_import_audit.py original.exe metadata-dir")
    run(Path(sys.argv[1]),Path(sys.argv[2]))
