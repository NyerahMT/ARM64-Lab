#!/usr/bin/env python3
"""Bounded x64 reference execution of the publisher's unmodified beta21e demo.

This does not unlock the demo, change any licensing decision, start a game
session, or translate x64 instructions to ARM64. Only basic Windows clock,
process identity, bounded startup environment and both CRT callback-table
walkers are modeled. Everything else stops before return.
No executable bytes, memory contents or modified binaries are emitted.
"""
from __future__ import annotations
import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import struct
import sys

ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT))
from tools.pe_probe import PE
from mxbikes_first_callee_emu import import_slots
from mxb_gl_callsite import prove_callsite
from mxb_demo_conditional_callsite import prove_conditional_callsite
from mxb_demo_win64_environment import startup_info_a, thread_environment, checked_write, TEB_PAGE_SIZE, process_strings, process_service, PROCESS_ENVIRONMENT_APIS
from mxb_demo_crt_process import CRT_DATA, data_address, data_page, Process, APIS as CRT_PROCESS_APIS
from mxb_demo_win64_environment import COMMAND_LINE_A
from mxb_demo_native_crt import NativeCRT, APIS as NATIVE_CRT_APIS
from mxb_demo_native_startup import NativeStartup, HEAP_BASE, HEAP_CAP, CLOCKS
from unicorn import Uc, UcError, UC_ARCH_X86, UC_MODE_64, UC_HOOK_CODE, UC_HOOK_MEM_INVALID, UC_PROT_READ, UC_PROT_WRITE, UC_PROT_EXEC
from unicorn.x86_const import UC_X86_REG_RIP, UC_X86_REG_RSP, UC_X86_REG_RAX, UC_X86_REG_RCX, UC_X86_REG_RDX, UC_X86_REG_R8, UC_X86_REG_GS_BASE, UC_X86_REG_RBX, UC_X86_REG_RSI, UC_X86_REG_RDI, UC_X86_REG_R9

DEMO_SHA="b75ba091fea6425ea9e5e372d2c41bf19f7d3f20a1ff1890130389e9f51f8742"
PAGE=4096
STACK=0x700000000
STACK_SIZE=0x100000
STUB=0x710000000
END=0x720000000
TEB=0x730000000
PROCESS_STRINGS=0x740000000
CRT_WALK=0x750000000
# Independently authored Win64 _initterm_e loop. Preserve RSI/RDI/RBX,
# allocate 32-byte shadow space, call each non-null pointer, stop on nonzero EAX.
# Offsets 0x20=CALL RBX, 0x22=callback return, 0x2f=RET.
CRT_WALK_CODE=bytes.fromhex('5657534883ec204889ce4889d731c04839fe7314488b1e4883c6084885db74efffd385c07502ebe74883c4205b5f5ec3')
# Void _initterm ignores callback EAX, unlike _initterm_e.
CRT_VOID=CRT_WALK+0x100
CRT_VOID_CODE=bytes.fromhex('5657534883ec204889ce4889d74839fe7310488b1e4883c6084885db74efffd3ebeb4883c4205b5f5ec3')
CRT_VARIANTS={
    "_initterm_e":(CRT_WALK,CRT_WALK_CODE,0x20,0x22,0x2f,True),
    "_initterm":(CRT_VOID,CRT_VOID_CODE,0x1e,0x20,0x29,False),
}
MAX_IMAGE=128*1024*1024
MAX_INSTRUCTIONS=1000000
WINMAIN_RVA=0x136c60
WINMAIN_CALL_RVA=0x2ab666
ENVIRONMENT={"getsystemtimeasfiletime","getcurrentthreadid","getcurrentprocessid",
             "queryperformancecounter","queryperformancefrequency","gettickcount","gettickcount64",
             "getstartupinfoa","setunhandledexceptionfilter"} | PROCESS_ENVIRONMENT_APIS


def align(n):
    return (n+PAGE-1)&~(PAGE-1)


def execute(pe, limit=MAX_INSTRUCTIONS, native_crt_library=None, stop_at_winmain=False,
            native_startup_library=None, asset_paths=(), demo_assets_dir=None):
    if not 1<=limit<=MAX_INSTRUCTIONS:raise ValueError("invalid_instruction_budget")
    if hashlib.sha256(pe.b).hexdigest()!=DEMO_SHA:raise ValueError("public_demo_SHA_mismatch")
    if native_crt_library is not None and native_startup_library is not None:
        raise ValueError("multiple_native_backends")
    metadata=pe.inventory()
    if any(lib.lower() in ("steam_api.dll","steam_api64.dll") for lib in metadata["imports"]):
        raise ValueError("unexpected_Steam_import")
    base=int(metadata["image_base"],16)
    startup=NativeStartup(native_startup_library,base) if native_startup_library is not None else None
    native=startup if startup is not None else (NativeCRT(native_crt_library) if native_crt_library is not None else None)
    if (asset_paths or demo_assets_dir is not None) and startup is None:
        raise ValueError("asset_mounts_require_native_startup")
    if asset_paths and demo_assets_dir is not None:raise ValueError("multiple_asset_mount_modes")
    if len(asset_paths)>16:raise ValueError("too_many_asset_mounts")
    if startup is not None:
        try:
            if demo_assets_dir is not None:startup.mount_demo_directory(demo_assets_dir)
            else:
                for path in asset_paths:startup.mount_asset_path(path)
        except BaseException:
            startup.close_assets();raise
    asset_mount_count=startup.assets.count if startup is not None else 0
    entry=int(metadata["entry_rva"],16)
    image_size=pe.u32(pe.opt+56)
    header_size=pe.u32(pe.opt+60)
    if not 0<header_size<=len(pe.b) or not 0<image_size<=MAX_IMAGE or base%PAGE:
        raise ValueError("invalid_PE_mapping")
    u=Uc(UC_ARCH_X86,UC_MODE_64)
    u.mem_map(base,align(image_size),UC_PROT_READ|UC_PROT_WRITE)
    u.mem_write(base,pe.b[:header_size])
    permissions={}
    executable=[]
    writable=[]
    immutable_data=[]
    for _,vsize,rva,raw,off,flags in pe.sections:
        end=rva+max(vsize,raw)
        if end>image_size or raw and off+raw>len(pe.b) or rva<header_size:
            raise ValueError("invalid_PE_section")
        if raw:u.mem_write(base+rva,pe.b[off:off+raw])
        prot=0
        if flags&0x40000000:prot|=UC_PROT_READ
        if flags&0x80000000:prot|=UC_PROT_WRITE;writable.append((base+rva,base+end))
        if flags&0x20000000:prot|=UC_PROT_EXEC;executable.append((base+rva,base+rva+raw))
        if flags&0xe0000000==0x40000000 and raw:
            immutable_data.append((base+rva,base+rva+raw))
        for p in range(rva&~(PAGE-1),align(end),PAGE):
            permissions[p]=permissions.get(p,0)|prot
    if not any(lo<=base+entry<hi for lo,hi in executable):raise ValueError("entry_not_executable")
    slots=import_slots(pe)
    if not 0<len(slots)<=4096 or len({r for r,_,_ in slots})!=len(slots):
        raise ValueError("invalid_import_slots")
    u.mem_map(STUB,align(16*len(slots)),UC_PROT_READ|UC_PROT_WRITE)
    targets={}
    typed_data_imports={}
    iat={rva:(lib.lower(),name) for rva,lib,name in slots}
    for i,(rva,lib,name) in enumerate(slots):
        if rva+8>image_size:raise ValueError("invalid_IAT_RVA")
        data_va=native.data_address(lib,name) if native else data_address(lib,name)
        if data_va is not None:
            u.mem_write(base+rva,struct.pack("<Q",data_va))
            typed_data_imports[lib+"!"+name]=hex(data_va-CRT_DATA)
            continue
        addr=STUB+16*i
        targets[addr]=(lib,name)
        if lib.lower()=="msvcr90.dll" and name in CRT_VARIANTS:
            u.mem_write(addr,b"\xe9"+struct.pack("<i",CRT_VARIANTS[name][0]-(addr+5)))
        else:u.mem_write(addr,b"\xc3")
        u.mem_write(base+rva,struct.pack("<Q",addr))
    u.mem_protect(STUB,align(16*len(slots)),UC_PROT_READ|UC_PROT_EXEC)
    u.mem_map(CRT_WALK,PAGE,UC_PROT_READ|UC_PROT_WRITE)
    u.mem_write(CRT_WALK,CRT_WALK_CODE)
    u.mem_write(CRT_VOID,CRT_VOID_CODE)
    u.mem_protect(CRT_WALK,PAGE,UC_PROT_READ|UC_PROT_EXEC)
    for p in range(0,align(image_size),PAGE):
        prot=permissions.get(p,UC_PROT_READ)
        if prot&UC_PROT_EXEC and prot&UC_PROT_WRITE:raise ValueError("writable_executable_page")
        u.mem_protect(base+p,PAGE,prot)
    u.mem_map(STACK,STACK_SIZE,UC_PROT_READ|UC_PROT_WRITE)
    writable.append((STACK,STACK+STACK_SIZE))
    u.mem_map(TEB,TEB_PAGE_SIZE,UC_PROT_READ|UC_PROT_WRITE)
    u.mem_write(TEB,thread_environment(TEB,STACK+STACK_SIZE,STACK,0x1234,0x5678))
    u.reg_write(UC_X86_REG_GS_BASE,TEB)
    writable.append((TEB,TEB+TEB_PAGE_SIZE))
    a_off,w_off,strings=process_strings(PAGE)
    u.mem_map(PROCESS_STRINGS,PAGE,UC_PROT_READ|UC_PROT_WRITE)
    u.mem_write(PROCESS_STRINGS,strings)
    u.mem_protect(PROCESS_STRINGS,PAGE,UC_PROT_READ)
    u.mem_map(CRT_DATA,PAGE,UC_PROT_READ|UC_PROT_WRITE)
    build_data=native.data_page if native else data_page
    u.mem_write(CRT_DATA,build_data(PROCESS_STRINGS+a_off,PROCESS_STRINGS+w_off,COMMAND_LINE_A))
    writable.append((CRT_DATA,CRT_DATA+PAGE))
    if startup is not None:
        u.mem_map(HEAP_BASE,HEAP_CAP,UC_PROT_READ|UC_PROT_WRITE)
        writable.append((HEAP_BASE,HEAP_BASE+HEAP_CAP))
    crt_process=native if native else Process()
    process_apis=NATIVE_CRT_APIS if native else CRT_PROCESS_APIS
    exception_filter=0
    winmain_reached=False
    sp=STACK+STACK_SIZE-0x108
    u.mem_write(sp,struct.pack("<Q",END))
    u.reg_write(UC_X86_REG_RSP,sp)
    counts=Counter()
    visits=Counter()
    original=0
    stop={}
    serviced=Counter()
    recent=[]
    memory_fault={}
    crt_active=None
    crt_reports=[]
    def halt(status,**details):
        stop.update(status=status,**details)
        u.emu_stop()
    def write_qword(ptr,value):
        checked_write(u.mem_write,writable,ptr,struct.pack("<Q",value))
    def prove_origin(cpu,return_va,pc,lib,name):
        direct=prove_callsite(pe,iat,base,cpu.mem_read,return_va,pc,lib,name)
        if direct is not None:return direct
        return prove_conditional_callsite(pe,iat,base,cpu.mem_read,return_va,pc,lib,name,
                                          [int(rva,16) for rva in recent])
    def hook(cpu,pc,size,_):
        nonlocal original,crt_active,exception_filter,winmain_reached
        if CRT_WALK<=pc<CRT_WALK+PAGE:
            if crt_active is None:
                halt("unexpected_crt_walker_entry");return
            start,code,call_off,return_off,ret_off,checked=crt_active["variant"]
            if not start<=pc<pc+size<=start+len(code):
                halt("unexpected_crt_walker_entry");return
            report=crt_active["report"]
            offset=pc-start
            if offset==call_off:
                n=report["callbacks_entered"]
                callbacks=crt_active["callbacks"]
                if (n>=len(callbacks) or cpu.reg_read(UC_X86_REG_RBX)!=callbacks[n]
                        or cpu.reg_read(UC_X86_REG_RSP)!=crt_active["rsp"]-56
                        or report["callbacks_entered"]!=report["callbacks_returned"]
                        or (checked and report["last_callback_status"]!=0)):
                    halt("invalid_crt_callback_target_or_stack");return
                crt_active["callback_registers"]=tuple(cpu.reg_read(r) for r in
                    (UC_X86_REG_RBX,UC_X86_REG_RSI,UC_X86_REG_RDI))
                report["callbacks_entered"]+=1
            elif offset==return_off:
                if (report["callbacks_returned"]+1!=report["callbacks_entered"] or
                        cpu.reg_read(UC_X86_REG_RSP)!=crt_active["rsp"]-56 or
                        tuple(cpu.reg_read(r) for r in (UC_X86_REG_RBX,UC_X86_REG_RSI,UC_X86_REG_RDI))
                        !=crt_active["callback_registers"]):
                    halt("invalid_crt_callback_return");return
                report["callbacks_returned"]+=1
                if checked:report["last_callback_status"]=cpu.reg_read(UC_X86_REG_RAX)&0xffffffff
            elif offset==ret_off:
                try:
                    rsp=cpu.reg_read(UC_X86_REG_RSP)
                    ret=struct.unpack("<Q",cpu.mem_read(rsp,8))[0]
                    status=cpu.reg_read(UC_X86_REG_RAX)&0xffffffff
                    if (rsp!=crt_active["rsp"] or ret!=crt_active["return"] or
                            report["callbacks_entered"]!=report["callbacks_returned"] or
                            tuple(cpu.reg_read(r) for r in (UC_X86_REG_RBX,UC_X86_REG_RSI,UC_X86_REG_RDI))
                            !=crt_active["entry_registers"] or
                            ((not checked or status==0) and report["callbacks_returned"]!=len(crt_active["callbacks"])) or
                            (checked and status!=report["last_callback_status"])):
                        halt("invalid_crt_walker_return");return
                    report["completed"]=True
                    report["return_status"]=status if checked else None
                    serviced[crt_active["key"]]+=1
                    crt_active=None
                except (UcError,struct.error):halt("invalid_crt_walker_return")
            return
        if pc in targets:
            lib,name=targets[pc]
            low=name.lower()
            key=lib+"!"+name
            counts[key]+=1
            is_crt=lib.lower()=="msvcr90.dll" and name in CRT_VARIANTS
            is_crt_process=lib.lower()=="msvcr90.dll" and name in process_apis
            native_startup_import=startup is not None and startup.supports(lib,name)
            supported=is_crt or is_crt_process or native_startup_import or (lib.lower() in ("kernel32.dll","kernelbase.dll") and low in ENVIRONMENT)
            if not supported:
                # Record proven import origin even for the next unsupported dependency.
                try:
                    rsp=cpu.reg_read(UC_X86_REG_RSP)
                    ret=struct.unpack("<Q",cpu.mem_read(rsp,8))[0]
                    evidence=prove_origin(cpu,ret,pc,lib,name)
                except (ValueError,UcError,struct.error):
                    evidence=None
                halt("unsupported_import",import_name=key,callsite=evidence)
                return
            if cpu.reg_read(UC_X86_REG_RSP)&15!=8:
                halt("invalid_Win64_import_stack",import_name=key)
                return
            try:
                rsp=cpu.reg_read(UC_X86_REG_RSP)
                return_va=struct.unpack("<Q",cpu.mem_read(rsp,8))[0]
                evidence=prove_origin(cpu,return_va,pc,lib,name)
                if evidence is None:
                    halt("unverified_environment_import_callsite",import_name=key)
                    return
                ptr=cpu.reg_read(UC_X86_REG_RCX)
                if is_crt:
                    if crt_active is not None:
                        halt("nested_crt_initializer_unsupported",import_name=key);return
                    end=cpu.reg_read(UC_X86_REG_RDX)
                    if (not ptr or ptr&7 or end&7 or not 0<=end-ptr<=512 or
                            not any(lo<=ptr<=end<=hi for lo,hi in immutable_data) or
                            not STACK+64<=rsp<=STACK+STACK_SIZE-8):
                        halt("invalid_crt_initializer_table",import_name=key);return
                    data=bytes(cpu.mem_read(ptr,end-ptr)) if end>ptr else b""
                    if data and data!=pe.read_rva(ptr-base,len(data)):
                        halt("changed_crt_initializer_table",import_name=key);return
                    callbacks=[value for (value,) in struct.iter_unpack("<Q",data) if value]
                    if any(not any(lo<=fn<hi for lo,hi in executable) for fn in callbacks):
                        halt("invalid_crt_initializer_callback",import_name=key);return
                    report={"import":key,"callsite":evidence,"table_rva":hex(ptr-base),
                            "table_slots":len(data)//8,"nonnull_callbacks":len(callbacks),
                            "callbacks_entered":0,"callbacks_returned":0,
                            "last_callback_status":0,"completed":False}
                    crt_reports.append(report)
                    crt_active={"report":report,"callbacks":callbacks,"rsp":rsp,
                                "return":return_va,"key":key,"variant":CRT_VARIANTS[name],
                                "entry_registers":tuple(cpu.reg_read(r) for r in
                                    (UC_X86_REG_RBX,UC_X86_REG_RSI,UC_X86_REG_RDI))}
                    # The actual guest JMP and CALL instructions execute; no fabricated return.
                    return
                if native_startup_import:
                    if name in CLOCKS:startup.advance_to_instruction(original)
                    args=(ptr,cpu.reg_read(UC_X86_REG_RDX),cpu.reg_read(UC_X86_REG_R8),cpu.reg_read(UC_X86_REG_R9))
                    value=startup.dispatch_import(lib,name,args,read=cpu.mem_read,
                        write=cpu.mem_write,writable=writable,rsp=rsp,
                        executable=executable,rax=cpu.reg_read(UC_X86_REG_RAX))
                    cpu.reg_write(UC_X86_REG_RAX,value)
                elif is_crt_process:
                    args=(ptr,cpu.reg_read(UC_X86_REG_RDX),
                          cpu.reg_read(UC_X86_REG_R8),cpu.reg_read(UC_X86_REG_R9))
                    extra={"executable":executable,"rax":cpu.reg_read(UC_X86_REG_RAX)} if native else {}
                    value=crt_process.dispatch(name,args,read=cpu.mem_read,
                        write=cpu.mem_write,writable=writable,rsp=rsp,**extra)
                    if value is not None:cpu.reg_write(UC_X86_REG_RAX,value)
                elif low in PROCESS_ENVIRONMENT_APIS:
                    value=process_service(low,(ptr,cpu.reg_read(UC_X86_REG_RDX),cpu.reg_read(UC_X86_REG_R8)),image_base=base,command_a=PROCESS_STRINGS+a_off,command_w=PROCESS_STRINGS+w_off,write=cpu.mem_write,writable=writable)
                    cpu.reg_write(UC_X86_REG_RAX,value)
                elif low=="setunhandledexceptionfilter":
                    # Registration only; never claim that exceptions are dispatched.
                    if ptr and not any(lo<=ptr<hi for lo,hi in executable):
                        halt("invalid_exception_filter_target",import_name=key);return
                    cpu.reg_write(UC_X86_REG_RAX,exception_filter)
                    exception_filter=ptr
                elif low=="getstartupinfoa":checked_write(cpu.mem_write,writable,ptr,startup_info_a())
                elif low=="getsystemtimeasfiletime":write_qword(ptr,116444736012345678)
                elif low=="queryperformancecounter":write_qword(ptr,1234567890);cpu.reg_write(UC_X86_REG_RAX,1)
                elif low=="queryperformancefrequency":write_qword(ptr,10000000);cpu.reg_write(UC_X86_REG_RAX,1)
                else:cpu.reg_write(UC_X86_REG_RAX,{"getcurrentthreadid":0x5678,
                    "getcurrentprocessid":0x1234,"gettickcount":0x9abc,"gettickcount64":0x9abc}[low])
                serviced[key]+=1
            except (ValueError,UcError,struct.error):
                halt("rejected_environment_output",import_name=key)
            return
        if not any(lo<=pc and pc+size<=hi for lo,hi in executable):
            halt("outside_original_executable_sections")
            return
        if not winmain_reached and pc==base+WINMAIN_RVA:
            try:
                call=pe.read_rva(WINMAIN_CALL_RVA,5)
                ret=struct.unpack("<Q",cpu.mem_read(cpu.reg_read(UC_X86_REG_RSP),8))[0]
                proof=(len(call)==5 and call[0]==0xe8 and
                       WINMAIN_CALL_RVA+5+struct.unpack_from("<i",call,1)[0]==WINMAIN_RVA and
                       bytes(cpu.mem_read(base+WINMAIN_CALL_RVA,5))==call and
                       ret==base+WINMAIN_CALL_RVA+5)
            except (ValueError,UcError,struct.error):proof=False
            if not proof or crt_active is not None:
                halt("unverified_winmain_handoff");return
            winmain_reached=True
            if stop_at_winmain:
                halt("winmain_entry_reached",callsite_rva=hex(WINMAIN_CALL_RVA));return
        original+=1
        visits[pc-base]+=1
        recent.append(hex(pc-base))
        if len(recent)>16:del recent[0]
    def fault(cpu,access,address,size,value,_):
        pc=cpu.reg_read(UC_X86_REG_RIP)
        memory_fault.update(access=access,address=hex(address),size=size,
                            instruction_rva=hex(pc-base) if base<=pc<base+image_size else None)
        return False
    u.hook_add(UC_HOOK_CODE,hook)
    u.hook_add(UC_HOOK_MEM_INVALID,fault)
    try:u.emu_start(base+entry,END,count=limit,timeout=5_000_000)
    except UcError as exc:
        if not stop:stop.update(status="guest_emulation_fault",reason=str(exc))
    finally:
        if startup is not None:startup.close_assets()
    pc=u.reg_read(UC_X86_REG_RIP)
    if not stop:
        stop.update(status=("incomplete_crt_initializer" if crt_active is not None and pc==END
                            else "entry_returned" if pc==END else "execution_budget_or_timeout"))
    if crt_active is not None:
        stop["active_crt_initializer"]=crt_active["key"]
    stop["original_rva"]=hex(pc-base) if base<=pc<base+image_size else None
    tls_rva,tls_size=pe.directory(9)
    return {"target":"publisher_distributed_beta21e_demo","verified_sha256":DEMO_SHA,
            "entry_rva":hex(entry),"original_x64_instruction_executions":original,
            "unique_original_instruction_addresses":len(visits),"observed_import_calls":dict(counts),
            "hottest_original_rvas":[{"rva":hex(r),"executions":n} for r,n in visits.most_common(8)],
            "serviced_environment_calls":dict(serviced),
            "recent_original_instruction_rvas":recent,
            "memory_fault":memory_fault or None,
            "crt_initializer_tables":crt_reports,
            "typed_crt_data_imports":typed_data_imports,
            "crt_process_state":{"app_type":crt_process.app_type,"locale_mode":crt_process.locale_mode,
                                 "exit_callbacks_registered":native.exit_count if native else 0},
            "crt_backend":"native_startup_c" if startup else "native_c" if native else "python_reference",
            "native_startup_heap_mapped":startup is not None,
            "native_asset_mount_count":asset_mount_count,
            "verified_demo_directory_requested":demo_assets_dir is not None,
            "native_winsock_initialization_refs":startup.startup.winsock.refs if startup else 0,
            "network_transport_implemented":False,
            "native_heap_live_blocks":sum(bool(b.address) for b in startup.startup.heap.blocks) if startup else 0,
            "exception_filter_registered":bool(startup.startup.exception_filter if startup else exception_filter),
            "exception_dispatch_implemented":False,
            "winmain_entry_reached":winmain_reached,
            "tls_directory_present":bool(tls_rva and tls_size),
            "tls_callbacks_executed":False,
            "stop":stop,"environment_mode":"bounded_clock_process_identity_and_minimal_startup_environment",
            "minimal_teb_mapped":True,"immutable_process_strings_mapped":True,"peb_implemented":False,
            "demo_restrictions_modified":False,"native_arm64_engine_executed":False,
            "actual_game_menu_rendered":False}


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("--demo-exe",type=Path,required=True)
    native_group=p.add_mutually_exclusive_group()
    native_group.add_argument("--native-crt-library",type=Path,help="Locally compiled trusted native CRT shared library")
    native_group.add_argument("--native-startup-library",type=Path,help="Locally compiled trusted combined native startup library")
    p.add_argument("--instruction-limit",type=int,default=MAX_INSTRUCTIONS)
    asset_group=p.add_mutually_exclusive_group()
    asset_group.add_argument("--asset",type=Path,action="append",default=[],help="Explicit original read-only streamed asset; guest sees only its basename")
    asset_group.add_argument("--demo-assets-dir",type=Path,help="Extracted beta21e directory; verify exe and core.ini hashes plus data file sizes")
    p.add_argument("--stop-at-winmain",action="store_true",help="Stop at the proven standalone WinMain call target")
    args=p.parse_args()
    if not args.demo_exe.is_file() or not 0<args.demo_exe.stat().st_size<=MAX_IMAGE:
        p.error("missing_or_oversized_demo")
    if not 1<=args.instruction_limit<=MAX_INSTRUCTIONS:p.error("invalid_instruction_budget")
    result=execute(PE(args.demo_exe),limit=args.instruction_limit,native_crt_library=args.native_crt_library,
                   native_startup_library=args.native_startup_library,stop_at_winmain=args.stop_at_winmain,
                   asset_paths=args.asset,demo_assets_dir=args.demo_assets_dir)
    print(json.dumps(result,indent=2))
    if result["original_x64_instruction_executions"]<=0:
        raise SystemExit("No genuine demo instructions executed")


if __name__=="__main__":main()
