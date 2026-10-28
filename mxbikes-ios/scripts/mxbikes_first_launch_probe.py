#!/usr/bin/env python3
"""First honest MX Bikes startup probe, not an iOS/gameplay launch.

Executes exact SHA-pinned original Windows x64 PE entry under Unicorn,
past the previously proven CRT first initializer if possible. The executable
is mapped privately during CI; recognized time/identity Win32 APIs use the
existing explicitly synthetic initializer model. At the FIRST unknown import,
external memory/CPU exception, or hard instruction budget, stop instead of
making up API behavior. A companion *native readiness* gate refuses to claim
ARM64 startup when entry, CRT or main don't have complete verified native
function proofs. Outputs are metadata only, no original code, game data or
derived binaries. A passing CI test does NOT mean the game booted.
"""
from __future__ import annotations
import argparse
from collections import Counter,deque
import hashlib
import json
from pathlib import Path
import struct
import sys
import time

from unicorn import (Uc,UcError,UC_ARCH_X86,UC_MODE_64,UC_HOOK_CODE,
                     UC_HOOK_MEM_READ_UNMAPPED,UC_HOOK_MEM_WRITE_UNMAPPED,
                     UC_HOOK_MEM_FETCH_UNMAPPED)
from unicorn.x86_const import (UC_X86_REG_RAX,UC_X86_REG_RBX,UC_X86_REG_RCX,
    UC_X86_REG_RDX,UC_X86_REG_R8,UC_X86_REG_R9,UC_X86_REG_RSI,UC_X86_REG_RDI,UC_X86_REG_RBP,
    UC_X86_REG_RIP,UC_X86_REG_RSP)
from capstone import Cs,CS_ARCH_X86,CS_MODE_64
from capstone.x86 import X86_OP_MEM
from mxbikes_first_callee_emu import (
    IMAGE_BASE,STUB_BASE,STACK_BASE,STACK_SIZE,MAX_IMAGE_SIZE,
    APIS_RECOGNIZED,round4k,import_slots
)
from mxbikes_whole_game_map import INPUT_SHA,ENTRY_RVA,CRT_RVA,MAIN_RVA,walk_unwind
from mxbikes_dynamic_startup_wave import prioritize_original_startup
from mxbikes_startup_native_family_audit import analyze_original_native_gates
from mxbikes_win64_thread_env import (build_win64_thread_environment,TEB_BASE,PEB_BASE,
    PARAMS_BASE,HEAP_BASE,CRT_ARGS_BASE,install_guest_main_arguments,model_win64_crt_getmainargs)
from mxbikes_win64_string_api import (_bounded_original_c_string,
    model_guest_strcpy,model_guest_strrchr,
    model_guest_strlen,model_guest_strchr,model_guest_strcmp)
from mxbikes_win64_file_api import OriginalGuestFileIO,FILE_HANDLE_PAGE
from mxbikes_win64_module_api import model_getmodulefilenamea,model_setcurrentdirectorya
from mxbikes_win64_crt_data import (CRT_DATA_BASE,install_crt_data_globals,
    address_for_original_crt_data_import)
from mxbikes_win64_crt_dispatch import (install_original_crt_dispatch_thunks,
    synthesized_dispatch_address,inside_synthetic_crt_dispatch)

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/"arm64-lab"))
from tools.pe_probe import PE
from tools.entry_wrapper import decode_entry_wrapper

MAX_INSTRUCTIONS=5000000
MAX_TIME_MICROSECONDS=45000000
MAX_IMPORTS=2048
MAX_NATIVE_PROOFS=40000
MAX_IMAGE_WRITES=250000
STARTUPINFOA_SIZE=104
SUPPORTED_STARTUP_IMPORTS=APIS_RECOGNIZED|{"getstartupinfoa"}
MAX_CRT_INITIALIZERS=256
CRT_APP_TYPES={0:"unknown",1:"console",2:"gui"}
GUEST_POINTER_COOKIE=0xa53330fdeadbeef1
U64_MASK=(1<<64)-1

def modeled_encode_pointer(ptr):
    """Synthetic per-process bijection, not the real Windows secret cookie."""
    value=(ptr^GUEST_POINTER_COOKIE)&U64_MASK
    return ((value>>17)|(value<<47))&U64_MASK

def modeled_decode_pointer(encoded):
    value=((encoded<<17)|(encoded>>47))&U64_MASK
    return (value^GUEST_POINTER_COOKIE)&U64_MASK

MAX_MODELED_ATEXIT=128

def safe_ascii_ismbblead(value):
    """All seven-bit ASCII bytes are non-lead bytes in Windows DBCS pages."""
    byte=value&0xffffffff
    return False if 0<=byte<=127 else None

def model_crt_exit_callback_registration(uc,pointer,executable_ranges,registry,*,is_atexit=False):
    """Register original code pointer; do not silently run/skip it at exit."""
    if (pointer==0 or len(registry)>=MAX_MODELED_ATEXIT or
        not any(lo<=pointer<hi for lo,hi in executable_ranges)):
        return False
    registry.append(pointer)
    uc.reg_write(UC_X86_REG_RAX,0 if is_atexit else pointer)
    return True

def model_unhandled_exception_filter(uc,pointer,executable_ranges,state):
    """Conservative process-local Win32 filter registration, no exception dispatch."""
    if (pointer!=0 and not any(lo<=pointer<hi for lo,hi in executable_ranges)):
        return False
    previous=state["handler"]
    uc.reg_write(UC_X86_REG_RAX,previous)
    state["handler"]=pointer
    state["registrations"]+=1
    return True

def external_steamworks_launch_service(lib,symbol):
    """Real Steamworks imports are external launch/auth services, never stubs."""
    return lib.lower() in ("steam_api64.dll","steam_api.dll") and symbol.lower().startswith("steamapi_")

def read_guest_ascii_import_argument(uc,ptr,readable_ranges):
    """Read bounded import argument text, never inferred host filesystem bytes."""
    raw=_bounded_original_c_string(uc,ptr,readable_ranges,max_bytes=512)
    if raw is None:return None
    return raw[:-1].decode("utf-8",errors="replace")

def modeled_crt_app_type(value):
    """Validate the documented CRT startup app-type enum."""
    return CRT_APP_TYPES.get(value)

def inspect_original_crt_initializer_array(uc,first,last,executable_ranges):
    """Fail-closed on nonempty CRT callbacks; empty arrays permit exact no-op."""
    if (not isinstance(first,int) or not isinstance(last,int) or
        first>last or first<IMAGE_BASE or (first%8) or (last%8) or
        last-first>MAX_CRT_INITIALIZERS*8):
        return {"status":"untrusted_original_crt_array_bounds"}
    number=(last-first)//8
    try:
        contents=bytes(uc.mem_read(first,last-first)) if number else b""
    except (UcError,ValueError):
        return {"status":"original_crt_array_unreadable"}
    pointers=[struct.unpack_from("<Q",contents,i*8)[0] for i in range(number)]
    callbacks=[val for val in pointers if val]
    if not callbacks:
        return {"status":"empty_original_crt_initializer_array","slot_count":number,
                "callback_count":0}
    first_callback=callbacks[0]
    valid=all(any(lo<=addr<hi for lo,hi in executable_ranges) for addr in callbacks)
    return {"status":("original_crt_callbacks_require_execution" if valid
                      else "original_crt_callback_pointer_not_executable"),
            "slot_count":number,"callback_count":len(callbacks),
            "first_callback_rva":(hex(first_callback-IMAGE_BASE)
                                  if IMAGE_BASE<=first_callback<IMAGE_BASE+MAX_IMAGE_SIZE else None)}


def model_getstartupinfoa(uc,ptr,writable_sections):
    """Minimal deterministic STARTUPINFOA, not a real Windows implementation.

    Matches Win64 structure size and writes only into an explicit mapped
    writable Win32 guest stack or writable original-image data section.
    """
    writable=(STACK_BASE<=ptr and ptr+STARTUPINFOA_SIZE<=STACK_BASE+STACK_SIZE)
    if not writable:
        writable=any(lo<=ptr and ptr+STARTUPINFOA_SIZE<=hi
                     for lo,hi in writable_sections)
    if not writable:
        return False
    structure=struct.pack("<I",STARTUPINFOA_SIZE)+bytes(STARTUPINFOA_SIZE-4)
    uc.mem_write(ptr,structure)
    return True

def native_readiness(mapping,verified,entry):
    if mapping.get("input_sha256")!=INPUT_SHA or mapping.get("original_file_verified") is not True:
        raise ValueError("Unpinned original game map")
    if not isinstance(verified,list) or len(verified)>MAX_NATIVE_PROOFS:
        raise ValueError("Invalid native function proof manifest")
    native={}
    for row in verified:
        rva=int(row["original_rva"],16)
        if rva in native:raise ValueError("Duplicate original native proof RVA")
        if (row.get("full_function_behavior_verified") is True and
            row.get("win64_guest_call_abi_verified") is True and
            row.get("code_presence")=="ephemeral_ci_elf_only" and
            row.get("differential_test_run_url")):
            native[rva]=row
    if entry!=ENTRY_RVA:
        raise ValueError("Original pinned PE entry RVA changed")
    roots={"pe_entry":ENTRY_RVA,"crt_startup":CRT_RVA,"game_main":MAIN_RVA}
    direct={int(k,16):{int(x,16) for x in dests}
            for k,dests in mapping.get("direct_call_graph",{}).items()}
    main_callees=direct.get(MAIN_RVA,set())
    return {
        "native_verified_original_complete_functions":len(native),
        "native_roots":{label:{"rva":hex(rva),"whole_native_function_verified":rva in native}
                        for label,rva in roots.items()},
        "game_main_direct_callees_in_static_map":len(main_callees),
        "game_main_direct_callees_with_verified_native_code":sum(c in native for c in main_callees),
        "native_arm64_entrypoint_can_execute_game":ENTRY_RVA in native and CRT_RVA in native and MAIN_RVA in native
             and main_callees<=native.keys(),
        "native_iphone_ipa_exists":False,
    }

def probe_original(pe,*,limit=MAX_INSTRUCTIONS,private_game_dir=None):
    if not 1<=limit<=MAX_INSTRUCTIONS:
        raise ValueError("Original x64 startup instruction budget exceeded")
    info=pe.inventory()
    if info.get("sha256")!=INPUT_SHA or int(info["image_base"],16)!=IMAGE_BASE:
        raise ValueError("Unrecognized original PE image")
    entry=int(info["entry_rva"],16)
    if entry!=ENTRY_RVA:raise ValueError("Original PE entry drift")
    wrapper=decode_entry_wrapper(pe.read_rva(entry,18),entry)
    first=int(wrapper["direct_call_rva"],16)
    tail=int(wrapper["tail_jmp_rva"],16)
    max_image=max(int(rva)+max(int(vsz),int(sz))
                  for _,vsz,rva,sz,_,_ in pe.sections)
    if max_image<=0 or max_image>MAX_IMAGE_SIZE:
        raise ValueError("Unsafe original executable image extent")
    imports=import_slots(pe)
    if len(imports)>MAX_IMPORTS:
        raise ValueError("Excessive original Windows imports for bounded probe")
    uc=Uc(UC_ARCH_X86,UC_MODE_64)
    uc.mem_map(IMAGE_BASE,round4k(max_image))
    sections=[]
    readable_sections=[]
    writable_sections=[]
    for name,vsz,rva,rawsize,rawptr,characteristics in pe.sections:
        if rawsize:
            uc.mem_write(IMAGE_BASE+rva,pe.b[rawptr:rawptr+rawsize])
        if characteristics&0x20000000:
            sections.append((IMAGE_BASE+rva,IMAGE_BASE+rva+max(vsz,rawsize)))
        if max(vsz,rawsize):
            readable_sections.append((IMAGE_BASE+rva,IMAGE_BASE+rva+max(vsz,rawsize)))
        if characteristics&0x80000000:
            writable_sections.append((IMAGE_BASE+rva,IMAGE_BASE+rva+max(vsz,rawsize)))
    if not sections:raise ValueError("Missing executable section")
    uc.mem_map(STUB_BASE,0x10000)
    guest_file_io=(OriginalGuestFileIO.from_private_game_directory(private_game_dir)
        if private_game_dir is not None else None)
    if guest_file_io is not None:guest_file_io.install(uc)
    crt_thunks=install_original_crt_dispatch_thunks(uc)
    uc.mem_map(STACK_BASE,STACK_SIZE)
    thread_model=build_win64_thread_environment(uc,stack_base=STACK_BASE,
        stack_size=STACK_SIZE,image_base=IMAGE_BASE)
    argv_model=install_guest_main_arguments(uc)
    crt_data_model=install_crt_data_globals(uc)
    stubs={}
    typed_data_import_names=[]
    for idx,(rva,lib,name) in enumerate(imports):
        original_data=address_for_original_crt_data_import(lib,name)
        if original_data is not None:
            uc.mem_write(IMAGE_BASE+rva,struct.pack("<Q",original_data))
            typed_data_import_names.append(lib+"::"+name)
            continue
        special=synthesized_dispatch_address(lib,name)
        va=special if special is not None else STUB_BASE+idx*16
        stubs[va]=(lib,name)
        if special is None:uc.mem_write(va,b"\xc3")
        uc.mem_write(IMAGE_BASE+rva,struct.pack("<Q",va))
    rsp=STACK_BASE+STACK_SIZE-0x108
    uc.mem_write(rsp,struct.pack("<Q",0x12345678))
    uc.reg_write(UC_X86_REG_RIP,IMAGE_BASE+entry)
    uc.reg_write(UC_X86_REG_RSP,rsp)
    mark={
        "pe_entry":IMAGE_BASE+entry,
        "first_crt_initializer":IMAGE_BASE+first,
        "crt_tail":IMAGE_BASE+tail,
        "crt_startup":IMAGE_BASE+CRT_RVA,
        "game_main":IMAGE_BASE+MAIN_RVA,
    }
    milestones={k:False for k in mark}
    seen=Counter()
    api_counter=Counter()
    crt_inspections=[]
    crt_model_state={"app_type":None}
    exception_filter={"handler":0,"registrations":0}
    original_exit_callbacks=[]
    guest_fs_state={"cwd":None,"changes":0}
    mapped_readable=(readable_sections+[(STACK_BASE,STACK_BASE+STACK_SIZE),
        (CRT_ARGS_BASE,CRT_ARGS_BASE+0x1000),
        (CRT_DATA_BASE,CRT_DATA_BASE+0x1000),
        (TEB_BASE,TEB_BASE+0x1000),
        (PEB_BASE,PEB_BASE+0x1000),
        (PARAMS_BASE,PARAMS_BASE+0x1000),
        (HEAP_BASE,HEAP_BASE+0x1000)])
    mapped_writable=(writable_sections+[(STACK_BASE,STACK_BASE+STACK_SIZE),
        (CRT_ARGS_BASE,CRT_ARGS_BASE+0x1000),
        (CRT_DATA_BASE,CRT_DATA_BASE+0x1000),
        (HEAP_BASE,HEAP_BASE+0x1000)])
    stop={"type":None,"import":None,"detail":None}
    total=[0]
    original_only=[0]
    executed_rvas=[]
    original_register_trace=deque(maxlen=24)
    original_pc_counts=Counter()
    post_main_pc_counts=Counter()
    trace_decoder=Cs(CS_ARCH_X86,CS_MODE_64)
    def code_hook(emulator,address,size,_):
        if stop["type"]:emulator.emu_stop();return
        total[0]+=1
        if any(lo<=address<hi for lo,hi in sections):
            original_only[0]+=1
            original_pc_counts[address-IMAGE_BASE]+=1
            if milestones["game_main"] or address==IMAGE_BASE+MAIN_RVA:
                post_main_pc_counts[address-IMAGE_BASE]+=1
            if original_only[0]%256==0:
                row={"rva":hex(address-IMAGE_BASE),
                 "rax":hex(emulator.reg_read(UC_X86_REG_RAX)),
                 "rdi":hex(emulator.reg_read(UC_X86_REG_RDI)),
                 "rcx":hex(emulator.reg_read(UC_X86_REG_RCX)),
                 "rdx":hex(emulator.reg_read(UC_X86_REG_RDX))}
                try:
                    ins=next(trace_decoder.disasm(bytes(pe.read_rva(address-IMAGE_BASE,15)),address,count=1),None)
                    row["opcode_family"]=ins.mnemonic if ins else "unknown"
                except (ValueError,OverflowError):
                    row["opcode_family"]="unmapped"
                original_register_trace.append(row)
        if IMAGE_BASE<=address<IMAGE_BASE+max_image:
            executed_rvas.append(hex(address-IMAGE_BASE))
            if len(executed_rvas)>12:executed_rvas.pop(0)
        for key,va in mark.items():
            if address==va:milestones[key]=True
        if address in stubs:
            lib,symbol=stubs[address]
            api_counter[lib.lower()+"::"+symbol]+=1
            name=symbol.lower()
            if name not in SUPPORTED_STARTUP_IMPORTS and not (
                lib.lower()=="msvcr90.dll" and name in ("_initterm_e","_initterm","__set_app_type","_encode_pointer","_decode_pointer","_onexit","atexit","__getmainargs","_ismbblead","strcpy","strrchr","strlen","strchr","strcmp",
                    "fopen","fread","fseek","ftell","fclose")) and not (
                lib.lower()=="kernel32.dll" and name in ("setunhandledexceptionfilter","getmodulefilenamea","setcurrentdirectorya")):
                if external_steamworks_launch_service(lib,symbol):
                    stop["type"]="steamworks_authorized_runtime_dependency_not_present"
                    stop["steamworks_symbol"]=symbol
                    stop["steamworks_launch_authorized"]=False
                else:
                    stop["type"]="first_unimplemented_win32_import"
                stop["import"]=lib+"::"+symbol
                if lib.lower()=="msvcr90.dll" and name=="fopen":
                    stop["unimplemented_fopen_request"]={
                        "filename":read_guest_ascii_import_argument(emulator,
                            emulator.reg_read(UC_X86_REG_RCX),mapped_readable),
                        "mode":read_guest_ascii_import_argument(emulator,
                            emulator.reg_read(UC_X86_REG_RDX),mapped_readable)}
                emulator.emu_stop()
                return
            if lib.lower()=="msvcr90.dll" and name=="_ismbblead":
                result=safe_ascii_ismbblead(emulator.reg_read(UC_X86_REG_RCX))
                if result is None:
                    stop["type"]="nonascii_multibyte_locale_table_not_modeled"
                    stop["import"]=lib+"::"+symbol
                    emulator.emu_stop();return
                emulator.reg_write(UC_X86_REG_RAX,0)
            elif lib.lower()=="msvcr90.dll" and name in ("fopen","fread","fseek","ftell","fclose"):
                ok=False
                if guest_file_io is not None:
                    a=emulator.reg_read(UC_X86_REG_RCX)
                    b=emulator.reg_read(UC_X86_REG_RDX)
                    if name=="fopen":
                        file_name=read_guest_ascii_import_argument(emulator,a,mapped_readable)
                        mode=read_guest_ascii_import_argument(emulator,b,mapped_readable)
                        ok=guest_file_io.fopen(emulator,file_name,mode,
                            cwd=guest_fs_state["cwd"])
                    elif name=="fread":
                        ok=guest_file_io.fread(emulator,a,b,
                            emulator.reg_read(UC_X86_REG_R8),
                            emulator.reg_read(UC_X86_REG_R9),
                            writable_ranges=mapped_writable)
                    elif name=="fseek":
                        ok=guest_file_io.fseek(emulator,a,b,
                            emulator.reg_read(UC_X86_REG_R8)&0xffffffff)
                    elif name=="ftell":ok=guest_file_io.ftell(emulator,a)
                    elif name=="fclose":ok=guest_file_io.fclose(emulator,a)
                if not ok:
                    stop["type"]="missing_original_file_or_unimplemented_readonly_crt_file_operation"
                    stop["import"]=lib+"::"+symbol
                    emulator.emu_stop();return
            elif lib.lower()=="msvcr90.dll" and name in ("strlen","strchr","strcmp"):
                first=emulator.reg_read(UC_X86_REG_RCX)
                second=emulator.reg_read(UC_X86_REG_RDX)
                if name=="strlen":
                    ok=model_guest_strlen(emulator,first,readable_ranges=mapped_readable)
                elif name=="strchr":
                    ok=model_guest_strchr(emulator,first,second,readable_ranges=mapped_readable)
                else:
                    ok=model_guest_strcmp(emulator,first,second,readable_ranges=mapped_readable)
                if not ok:
                    stop["type"]="invalid_crt_string_family_guest_memory"
                    stop["import"]=lib+"::"+symbol
                    emulator.emu_stop();return
            elif lib.lower()=="msvcr90.dll" and name=="strrchr":
                source=emulator.reg_read(UC_X86_REG_RCX)
                find=emulator.reg_read(UC_X86_REG_RDX)
                if not model_guest_strrchr(emulator,source,find,
                    readable_ranges=mapped_readable):
                    stop["type"]="invalid_crt_strrchr_guest_memory_or_unterminated_string"
                    stop["import"]=lib+"::"+symbol
                    emulator.emu_stop();return
            elif lib.lower()=="msvcr90.dll" and name=="strcpy":
                dest=emulator.reg_read(UC_X86_REG_RCX)
                src=emulator.reg_read(UC_X86_REG_RDX)
                if not model_guest_strcpy(emulator,dest,src,
                    readable_ranges=mapped_readable,
                    writable_ranges=mapped_writable):
                    stop["type"]="invalid_crt_strcpy_guest_memory_or_unterminated_string"
                    stop["import"]=lib+"::"+symbol
                    emulator.emu_stop();return
            elif lib.lower()=="kernel32.dll" and name=="setcurrentdirectorya":
                guest_path=emulator.reg_read(UC_X86_REG_RCX)
                if not model_setcurrentdirectorya(emulator,guest_path,
                    readable_ranges=mapped_readable,process_state=guest_fs_state):
                    stop["type"]="unavailable_or_unmapped_synthetic_guest_working_directory"
                    stop["import"]=lib+"::"+symbol
                    emulator.emu_stop();return
            elif lib.lower()=="kernel32.dll" and name=="getmodulefilenamea":
                module=emulator.reg_read(UC_X86_REG_RCX)
                destination=emulator.reg_read(UC_X86_REG_RDX)
                capacity=emulator.reg_read(UC_X86_REG_R8)&0xffffffff
                if not model_getmodulefilenamea(emulator,module,destination,
                    capacity,image_base=IMAGE_BASE,stack_base=STACK_BASE,
                    stack_size=STACK_SIZE,writable_sections=writable_sections):
                    stop["type"]="invalid_getmodulefilenamea_guest_parameters"
                    stop["import"]=lib+"::"+symbol
                    emulator.emu_stop();return
            elif lib.lower()=="msvcr90.dll" and name=="__getmainargs":
                ok=model_win64_crt_getmainargs(emulator,
                    emulator.reg_read(UC_X86_REG_RCX),
                    emulator.reg_read(UC_X86_REG_RDX),
                    emulator.reg_read(UC_X86_REG_R8),
                    writable_sections,stack_base=STACK_BASE,stack_size=STACK_SIZE,
                    wildcard=emulator.reg_read(UC_X86_REG_R9))
                if not ok:
                    stop["type"]="invalid_or_unmapped_win64_crt_getmainargs_arguments"
                    stop["import"]=lib+"::"+symbol
                    emulator.emu_stop();return
                emulator.reg_write(UC_X86_REG_RAX,0)
            elif lib.lower()=="msvcr90.dll" and name in ("_onexit","atexit"):
                ptr=emulator.reg_read(UC_X86_REG_RCX)
                if not model_crt_exit_callback_registration(emulator,ptr,sections,
                    original_exit_callbacks,is_atexit=(name=="atexit")):
                    stop["type"]="invalid_or_excessive_original_exit_callback_registration"
                    stop["import"]=lib+"::"+symbol
                    emulator.emu_stop();return
            elif lib.lower()=="kernel32.dll" and name=="setunhandledexceptionfilter":
                ptr=emulator.reg_read(UC_X86_REG_RCX)
                if not model_unhandled_exception_filter(emulator,ptr,sections,exception_filter):
                    stop["type"]="unmapped_or_noncode_exception_filter_pointer"
                    stop["import"]=lib+"::"+symbol
                    emulator.emu_stop();return
            elif lib.lower()=="msvcr90.dll" and name in ("_encode_pointer","_decode_pointer"):
                value=emulator.reg_read(UC_X86_REG_RCX)
                result=(modeled_encode_pointer(value) if name=="_encode_pointer"
                        else modeled_decode_pointer(value))
                emulator.reg_write(UC_X86_REG_RAX,result)
            elif lib.lower()=="msvcr90.dll" and name=="__set_app_type":
                model=modeled_crt_app_type(emulator.reg_read(UC_X86_REG_RCX))
                if model is None:
                    stop["type"]="invalid_original_crt_app_type"
                    stop["import"]=lib+"::"+symbol
                    emulator.emu_stop();return
                crt_model_state["app_type"]=model
            elif lib.lower()=="msvcr90.dll" and name in ("_initterm_e","_initterm"):
                begin=emulator.reg_read(UC_X86_REG_RCX)
                end=emulator.reg_read(UC_X86_REG_RDX)
                outcome=inspect_original_crt_initializer_array(emulator,begin,end,sections)
                crt_inspections.append({"import":name,**outcome})
                if outcome["status"] not in ("empty_original_crt_initializer_array",
                                             "original_crt_callbacks_require_execution"):
                    stop["type"]=outcome["status"]
                    stop["import"]=lib+"::"+symbol
                    stop["original_callback_rva"]=outcome.get("first_callback_rva")
                    emulator.emu_stop();return
                # Continue into our ABI-conforming machine-code dispatcher,
                # which calls every genuine original initializer callback.
            elif name=="getstartupinfoa":
                ptr=emulator.reg_read(UC_X86_REG_RCX)
                if not model_getstartupinfoa(emulator,ptr,writable_sections):
                    stop["type"]="model_getstartupinfoa_unmapped_or_nonwritable_guest_pointer"
                    stop["import"]=lib+"::"+symbol
                    emulator.emu_stop();return
            elif name in ("getsystemtimeasfiletime","queryperformancecounter"):
                ptr=emulator.reg_read(UC_X86_REG_RCX)
                if not STACK_BASE<=ptr<=STACK_BASE+STACK_SIZE-8:
                    stop["type"]="modeled_win32_out_pointer_not_guest_stack"
                    stop["import"]=lib+"::"+symbol
                    emulator.emu_stop();return
                value=116444736012345678 if name=="getsystemtimeasfiletime" else 1234567890
                emulator.mem_write(ptr,struct.pack("<Q",value))
                if name=="queryperformancecounter":
                    emulator.reg_write(UC_X86_REG_RAX,1)
            elif name=="getcurrentprocessid":emulator.reg_write(UC_X86_REG_RAX,0x1234)
            elif name=="getcurrentthreadid":emulator.reg_write(UC_X86_REG_RAX,0x5678)
            elif name=="gettickcount":emulator.reg_write(UC_X86_REG_RAX,0x9abc)
            return
        if inside_synthetic_crt_dispatch(address):
            seen["synthetic_crt_dispatcher_instructions"]+=1
            return
        if not any(lo<=address<hi for lo,hi in sections):
            stop["type"]="execution_outside_original_executable_sections"
            stop["detail"]="nonoriginal_or_unmapped_code"
            emulator.emu_stop();return
        if milestones["game_main"]:
            seen["executed_after_main_entry"]+=1
        elif milestones["crt_tail"]:
            seen["executed_after_first_initializer"]+=1
        else:
            seen["executed_entry_and_first_initializer"]+=1
    def invalid_memory(emulator,kind,addr,size,value,context):
        stop["type"]="unmapped_guest_memory"
        stop["access_kind"]={UC_HOOK_MEM_READ_UNMAPPED:"read",
                             UC_HOOK_MEM_WRITE_UNMAPPED:"write",
                             UC_HOOK_MEM_FETCH_UNMAPPED:"instruction_fetch"}.get(kind,"unknown")
        pc=emulator.reg_read(UC_X86_REG_RIP)
        stop["fault_pc_rva"]=hex(pc-IMAGE_BASE) if IMAGE_BASE<=pc<IMAGE_BASE+max_image else None
        stop["unmapped_guest_address"]=hex(addr)
        stop["access_width_bytes"]=size
        stop["last_original_executed_rvas"]=list(executed_rvas)
        stop["last_original_opcode_and_register_trace"]=list(original_register_trace)
        stop["registers_pointing_to_synthetic_import_stubs"]={
            n:lib+"::"+fn for n,reg in (
                ("rax",UC_X86_REG_RAX),("rbx",UC_X86_REG_RBX),
                ("rcx",UC_X86_REG_RCX),("rdx",UC_X86_REG_RDX),
                ("rdi",UC_X86_REG_RDI),("rsi",UC_X86_REG_RSI))
            for value in [emulator.reg_read(reg)] if value in stubs
            for lib,fn in [stubs[value]]}
        tracked=(("rax",UC_X86_REG_RAX),("rbx",UC_X86_REG_RBX),
                 ("rcx",UC_X86_REG_RCX),("rdx",UC_X86_REG_RDX),
                 ("rsi",UC_X86_REG_RSI),("rdi",UC_X86_REG_RDI),
                 ("rbp",UC_X86_REG_RBP),("rsp",UC_X86_REG_RSP))
        stop["original_cpu_registers_at_fault"]={n:hex(emulator.reg_read(reg))
                                                  for n,reg in tracked}
        if IMAGE_BASE<=pc<IMAGE_BASE+max_image:
            try:
                md=Cs(CS_ARCH_X86,CS_MODE_64)
                md.detail=True
                ins=next(md.disasm(bytes(pe.read_rva(pc-IMAGE_BASE,15)),pc,count=1),None)
                if ins is not None:
                    stop["faulting_original_instruction_family"]=ins.mnemonic
                    stop["faulting_memory_operand_bases"]=[{
                        "base":ins.reg_name(o.mem.base),
                        "index":ins.reg_name(o.mem.index),
                        "segment":ins.reg_name(o.mem.segment),
                        "width":o.size}
                        for o in ins.operands if o.type==X86_OP_MEM]
            except (ValueError,OverflowError,StopIteration):
                pass
        stop["detail"]=("original_image" if IMAGE_BASE<=addr<IMAGE_BASE+MAX_IMAGE_SIZE
                        else "guest_stack" if STACK_BASE<=addr<STACK_BASE+STACK_SIZE+65536
                        else "modeled_win64_thread_process" if TEB_BASE<=addr<HEAP_BASE+0x2000
                        else "external_win64_process_address")
        return False
    uc.hook_add(UC_HOOK_CODE,code_hook)
    uc.hook_add(UC_HOOK_MEM_READ_UNMAPPED|UC_HOOK_MEM_WRITE_UNMAPPED|
                UC_HOOK_MEM_FETCH_UNMAPPED,invalid_memory)
    started=time.perf_counter()
    try:
        uc.emu_start(IMAGE_BASE+entry,0,timeout=MAX_TIME_MICROSECONDS,count=limit)
    except UcError as exc:
        stop["type"]=stop["type"] or "unicorn_execution_fault"
        stop["detail"]=stop["detail"] or type(exc).__name__
    duration=time.perf_counter()-started
    if stop["type"] is None:
        stop["type"]=("original_x64_instruction_budget_reached" if total[0]>=limit
            else "original_x64_time_budget_reached" if duration>=MAX_TIME_MICROSECONDS/1e6*0.90
            else "original_x64_emulation_stopped_without_known_import_or_exception")
    if not stop.get("fault_pc_rva"):
        pc=uc.reg_read(UC_X86_REG_RIP)
        stop["fault_pc_rva"]=hex(pc-IMAGE_BASE) if IMAGE_BASE<=pc<IMAGE_BASE+max_image else None
    original_unwind,_,_,_=walk_unwind(pe)
    dynamic_priority=prioritize_original_startup(
        original_unwind,original_pc_counts,post_main_pc_counts,
        main_rva=MAIN_RVA,entry_rva=ENTRY_RVA,crt_rva=CRT_RVA,top=64)
    native_family_audit=analyze_original_native_gates(pe,dynamic_priority,base=IMAGE_BASE)
    return {
        "schema":1,
        "original_sha256":INPUT_SHA,
        "probe":"executed_original_windows_x64_entry_unicorn_with_explicit_synthetic_win32_api_subset",
        "entry_rva":hex(entry),
        "first_original_initializer_rva":hex(first),
        "crt_tail_rva":hex(tail),
        "budget_original_instructions":limit,
        "original_instructions_reached":original_only[0],
        "total_original_plus_synthetic_instruction_events":total[0],
        "elapsed_original_x64_probe_seconds":round(duration,3),
        "unique_original_instruction_rvas_executed":len(original_pc_counts),
        "dynamic_original_x64_function_priority":dynamic_priority,
        "dynamic_original_x64_function_family_audit":native_family_audit,
        "hottest_original_instruction_rvas":[{"rva":hex(rva),"hits":hits} for rva,hits in original_pc_counts.most_common(12)],
        "actual_original_callback_execution_allowed":True,
        "synthetic_crt_dispatcher_instructions":seen["synthetic_crt_dispatcher_instructions"],
        "original_process_milestones_reached":milestones,
        "phase_instruction_counts":dict(seen),
        "thread_process_environment":thread_model,
        "synthetic_command_line_environment":argv_model,
        "synthetic_guest_filesystem_state":guest_fs_state,
        "original_private_file_io":guest_file_io.events if guest_file_io else None,
        "steam_api64_library_executed":False,
        "actual_steamworks_runtime_authorized":False,
        "synthetic_crt_data_import_model":crt_data_model,
        "original_crt_data_imports_bound_as_data":typed_data_import_names,
        "synthetically_modeled_win32_calls":dict(api_counter),
        "original_crt_initializer_array_inspections":crt_inspections,
        "synthetic_crt_state":crt_model_state,
        "simulated_crt_ismbblead_ascii_only":True,
        "synthetic_unhandled_exception_filter_registrations":exception_filter["registrations"],
        "actual_unhandled_exception_dispatch_implemented":False,
        "synthetic_original_exit_callback_registrations":len(original_exit_callbacks),
        "actual_registered_exit_callbacks_executed":False,
        "synthetic_crt_pointer_cookie":"deterministic_process_local_reversible_model_not_windows_cookie",
        "startupinfoa_model_scope":"minimal_zero_initialized_WIN64_STARTUPINFOA_size_104_no_real_process_handles",
        "first_stopping_boundary":stop,
        "original_import_count":len(imports),
        "native_arm64_game_executed":False,
        "actual_win32_dll_executed":False,
        "actual_dx_graphics_initialized":False,
        "user_visible_game_menu":False,
        "iphone_build_launched":False,
        "game_assets_exported":False,
    }

def run(executable,map_path,verified_path,outdir):
    pe=PE(executable)
    if hashlib.sha256(pe.b).hexdigest()!=INPUT_SHA:
        raise ValueError("Original game revision not pinned")
    mapping=json.loads(map_path.read_text())
    verified=json.loads(verified_path.read_text())
    entry=int(pe.inventory()["entry_rva"],16)
    gate=native_readiness(mapping,verified,entry)
    actual=probe_original(pe)
    result={"original_x64_startup_probe":actual,
            "native_arm64_startup_readiness":gate}
    outdir.mkdir(parents=True,exist_ok=True)
    (outdir/"first-launch-startup-probe.json").write_text(json.dumps(result,indent=2)+"\n")
    milestones=actual["original_process_milestones_reached"]
    lines=["# MX Bikes first launch startup probe","",
           "- SHA-verified original Windows x64 PE entry EXECUTED under bounded Unicorn: **YES**",
           "- Original x64 instructions executed before safe stop: **"+str(actual["original_instructions_reached"])+"**",
           "- Synthetic CRT dispatcher instruction count: **"+str(actual["synthetic_crt_dispatcher_instructions"])+"**",
           "- Original CRT tail reached: **"+str(milestones["crt_tail"])+"**",
           "- Original game main reached: **"+str(milestones["game_main"])+"**",
           "- First safe-stop reason: **"+actual["first_stopping_boundary"]["type"]+"**",
           "- Named unresolved import: **"+str(actual["first_stopping_boundary"]["import"])+"**",
           "- Last original instruction RVA: **"+str(actual["first_stopping_boundary"].get("fault_pc_rva"))+"**",
           "- Guest fault address: **"+str(actual["first_stopping_boundary"].get("unmapped_guest_address"))+"**",
           "- First requested original fopen filename and mode: **"+str(actual["first_stopping_boundary"].get("unimplemented_fopen_request"))+"**",
           "- Faulting original instruction: **"+str(actual["first_stopping_boundary"].get("faulting_original_instruction_family"))+"**",
           "- Fault memory operand bases: **"+str(actual["first_stopping_boundary"].get("faulting_memory_operand_bases"))+"**",
           "- First original CRT callback RVA: **"+str(actual["first_stopping_boundary"].get("original_callback_rva"))+"**",
           "- Native original Win64 game entry callable: **"+str(gate["native_arm64_entrypoint_can_execute_game"])+"**",
           "- Original full ARM64 functions verified: **"+str(gate["native_verified_original_complete_functions"])+"**",
           "- Direct game-main call edges native: **"+str(gate["game_main_direct_callees_with_verified_native_code"])+"/"+str(gate["game_main_direct_callees_in_static_map"])+"**",
           "- Graphics engine initialized / menu launched / iPhone IPA: **NO**","",
           "Original x64 Unicorn startup with synthetic imports is a dependency probe, NOT native ARM64 game launch.",
           "Both input game and generated native code stay private; this report contains metadata only.",""]
    (outdir/"first-launch-startup-probe.md").write_text("\n".join(lines))
    print("\n".join(lines))
    return result

if __name__=="__main__":
    p=argparse.ArgumentParser()
    p.add_argument("original_exe",type=Path)
    p.add_argument("original_game_map",type=Path)
    p.add_argument("verified_complete_native_functions",type=Path)
    p.add_argument("output_directory",type=Path)
    a=p.parse_args()
    run(a.original_exe,a.original_game_map,
        a.verified_complete_native_functions,a.output_directory)
