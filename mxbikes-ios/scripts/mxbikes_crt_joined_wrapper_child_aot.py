#!/usr/bin/env python3
"""Authentic nested x64 CRT wrapper+child vs generated host C/AArch64.

Original owned PE x64 wrapper (8 instructions) CALLs the original 39-
instruction registration child; NO synthetic child return. Six MSVCR90
imports are injected deterministic test doubles on original x64 and native
host C/AArch64. Verified wrapper->child CALL/RET guest stack, registers,
flags, both CRT globals and imported call order are compared across 16 cases.

Derived native source/ELF and commercial PE stay in ephemeral PRIVATE CI.
Does not execute actual Windows CRT, initializer array, Steam, game or iOS.
"""
from pathlib import Path
from collections import Counter
import hashlib
import json
import struct
import sys
import tempfile

from unicorn import Uc,UC_ARCH_X86,UC_MODE_64,UC_HOOK_CODE
from unicorn.x86_const import (
    UC_X86_REG_RAX,UC_X86_REG_RBX,UC_X86_REG_RCX,UC_X86_REG_RDX,
    UC_X86_REG_R8,UC_X86_REG_RDI,UC_X86_REG_RSI,UC_X86_REG_R11,
    UC_X86_REG_RSP,UC_X86_REG_RIP,UC_X86_REG_EFLAGS,
)
from capstone.x86 import X86_OP_IMM,X86_OP_REG,X86_OP_MEM

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/"arm64-lab"))
sys.path.insert(0,str(ROOT/"arm64-lab"/"tests"))
from tools.pe_probe import PE
from tools.crt_import_cluster_lift import lift_crt_import_cluster
from tools.import_aot_smoke import execute_arm64_elf
from test_crt_import_cluster_lift import HARNESS,encode
from mxbikes_first_callee_emu import import_slots
from mxbikes_crt_exception_callback_differential import (
    SHA,BASE,SP,STOP,STACK,disassembler,unwind_ranges,
)
from mxbikes_crt_shared_helper_differential import (
    ENTRY as WRAPPER, CALLEE, LENGTH as WRAPPER_LENGTH,
)
from mxbikes_crt_child_path_reference import (
    ENTRY,END,GLOBALS,SLOTS,THUNKS,STUB,cases,prepare,
)
from mxbikes_crt_child_aot_differential import fixture,checked

TAIL_CALLBACK=0x320790
TAIL_LENGTH=12
TAIL_ARGUMENT=0x3207b0

REGS={
    "rax":UC_X86_REG_RAX,"rbx":UC_X86_REG_RBX,
    "rcx":UC_X86_REG_RCX,"rdx":UC_X86_REG_RDX,
    "r8":UC_X86_REG_R8,"rdi":UC_X86_REG_RDI,
    "rsi":UC_X86_REG_RSI,"r11":UC_X86_REG_R11,
}

def verify(pe):
    if hashlib.sha256(pe.b).hexdigest()!=SHA:
        raise RuntimeError("Original executable SHA mismatch")
    allowed=prepare(pe)
    if CALLEE!=ENTRY or WRAPPER!=0x2ab7e4 or WRAPPER_LENGTH!=0x17:
        raise RuntimeError("Original wrapper/child identities changed")
    code=pe.read_rva(WRAPPER,WRAPPER_LENGTH)
    ins=list(disassembler().disasm(code,WRAPPER))
    if (len(ins)!=8 or [x.mnemonic for x in ins]!=[
        "sub","call","neg","sbb","neg","dec","add","ret"] or
        ins[1].operands[0].type!=X86_OP_IMM or
        ins[1].operands[0].imm!=ENTRY or
        not any(a==WRAPPER and b==WRAPPER+WRAPPER_LENGTH
                for a,b in unwind_ranges(pe))):
        raise RuntimeError("Original wrapper nested CALL structure changed")
    return allowed,{BASE+x.address for x in ins}

def verify_tail(pe):
    forms=list(disassembler().disasm(
        pe.read_rva(TAIL_CALLBACK,TAIL_LENGTH),TAIL_CALLBACK))
    if (len(forms)!=2 or [x.mnemonic for x in forms]!=["lea","jmp"] or
        [x.size for x in forms]!=[7,5]):
        raise RuntimeError("Original initializer callback tail boundary changed")
    lea,jump=forms
    reg,mem=lea.operands
    if (reg.type!=X86_OP_REG or lea.reg_name(reg.reg)!="rcx" or
        mem.type!=X86_OP_MEM or lea.reg_name(mem.mem.base)!="rip" or
        mem.mem.index or lea.address+lea.size+mem.mem.disp!=TAIL_ARGUMENT or
        jump.operands[0].type!=X86_OP_IMM or
        jump.operands[0].imm!=WRAPPER):
        raise RuntimeError("Original initializer callback does not tail-jump to wrapper")
    return {BASE+x.address for x in forms}

def reference_original(pe,case,allowed,wrapper_pcs,tail=False):
    uc=Uc(UC_ARCH_X86,UC_MODE_64)
    pages={(BASE+ENTRY)&~4095,(BASE+0x321000)&~4095,
           (BASE+GLOBALS[0])&~4095}
    if tail:
        pages.add((BASE+TAIL_CALLBACK)&~4095)
    for page in pages:
        uc.mem_map(page,4096)
    uc.mem_map(STUB,4096)
    uc.mem_map(STACK,0x10000)
    uc.mem_write(BASE+ENTRY,pe.read_rva(ENTRY,END-ENTRY))
    uc.mem_write(BASE+WRAPPER,pe.read_rva(WRAPPER,WRAPPER_LENGTH))
    if tail:
        uc.mem_write(BASE+TAIL_CALLBACK,pe.read_rva(TAIL_CALLBACK,TAIL_LENGTH))
    for thunk in THUNKS:
        uc.mem_write(BASE+thunk,pe.read_rva(thunk,6))
    handlers={}
    for idx,(slot,name) in enumerate(SLOTS.items()):
        address=STUB+16*idx
        uc.mem_write(BASE+slot,struct.pack("<Q",address))
        uc.mem_write(address,b"\xc3")
        handlers[address]=name
    for i,rva in enumerate(GLOBALS):
        uc.mem_write(BASE+rva,struct.pack("<Q",case["global"+str(i)]))
    uc.mem_write(SP,struct.pack("<Q",STOP))
    initial=fixture(case)
    for name,reg in REGS.items():
        uc.reg_write(reg,initial[name])
    uc.reg_write(UC_X86_REG_RIP,BASE+(TAIL_CALLBACK if tail else WRAPPER))
    uc.reg_write(UC_X86_REG_RSP,SP)
    uc.reg_write(UC_X86_REG_EFLAGS,0x202|((initial["zf"]&1)<<6))
    visited_wrapper=set()
    visited_child=set()
    visited_tail=set()
    tail_pcs=({BASE+TAIL_CALLBACK,BASE+TAIL_CALLBACK+7} if tail else set())
    calls=Counter()
    trace=[]
    valid_thunks={BASE+x for x in THUNKS}

    def hook(emu,pc,size,ctx):
        if pc in tail_pcs:
            visited_tail.add(pc-BASE)
            return
        if pc in wrapper_pcs:
            visited_wrapper.add(pc-BASE)
            return
        if pc in allowed:
            visited_child.add(pc-BASE)
            return
        if pc in valid_thunks:
            return
        if pc not in handlers:
            raise RuntimeError("Authentic joined x64 control flow escaped caller/callee")
        name=handlers[pc]
        index=calls[name]
        calls[name]+=1
        if emu.reg_read(UC_X86_REG_RSP)!=SP-0x60:
            raise RuntimeError("Nested Win64 child import ABI moved")
        rcx=emu.reg_read(UC_X86_REG_RCX)
        trace.append(name)
        if name in ("_lock","_unlock"):
            if rcx!=8:
                raise RuntimeError("Original joined CRT selected unexpected lock")
            return
        if name=="_decode_pointer":
            if index>=3:raise RuntimeError("More than three decode calls")
            val=case["decode"][index]
        elif name=="_encode_pointer":
            if index>=3:raise RuntimeError("More than three encode calls")
            val=case["encode"][index]
        elif name=="_onexit":
            val=case["onexit"]
        elif name=="__dllonexit":
            val=case["dll"]
            if case["update"]:
                left=emu.reg_read(UC_X86_REG_RDX)
                right=emu.reg_read(UC_X86_REG_R8)
                if (left,right)!=(SP-0x20,SP-0x18):
                    raise RuntimeError("Nested __dllonexit Win64 pointer locations moved")
                emu.mem_write(left,struct.pack("<Q",case["start"]))
                emu.mem_write(right,struct.pack("<Q",case["end"]))
        else:
            raise RuntimeError("Unknown Win64 test service")
        emu.reg_write(UC_X86_REG_RAX,val)

    uc.hook_add(UC_HOOK_CODE,hook)
    uc.emu_start(BASE+(TAIL_CALLBACK if tail else WRAPPER),
                 STOP,timeout=3500000,count=160)
    if (uc.reg_read(UC_X86_REG_RSP)!=SP+8 or
        uc.reg_read(UC_X86_REG_RIP)!=STOP or
        len(visited_wrapper)!=8 or (tail and len(visited_tail)!=2)):
        raise RuntimeError("Original nested wrapper did not return")
    expect=(["_decode_pointer","_onexit"] if case["short"] else
            ["_decode_pointer","_lock","_decode_pointer","_decode_pointer",
             "_encode_pointer","__dllonexit","_encode_pointer",
             "_encode_pointer","_unlock"])
    if trace!=expect:
        raise RuntimeError("Joined original x64 MSVCR90 call ordering changed")
    retval=case["onexit"] if case["short"] else case["dll"]
    if uc.reg_read(UC_X86_REG_RAX)!=(0 if retval else 0xffffffff):
        raise RuntimeError("Original wrapper success/failure return diverged")
    out={name:uc.reg_read(reg) for name,reg in REGS.items()}
    out.update({
        "rsp":uc.reg_read(UC_X86_REG_RSP),
        "rip":uc.reg_read(UC_X86_REG_RIP),
        "zf":int(bool(uc.reg_read(UC_X86_REG_EFLAGS)&64)),
        "g0":struct.unpack("<Q",bytes(uc.mem_read(BASE+GLOBALS[0],8)))[0],
        "g1":struct.unpack("<Q",bytes(uc.mem_read(BASE+GLOBALS[1],8)))[0],
        "stack":bytes(uc.mem_read(SP-128,256)),
        "trace":trace,
        "visited_child":visited_child,
        "visited_tail":visited_tail,
    })
    return out

def native_harness(rows,tail=False):
    # Reuse the same tested public generic generated-function harness with
    # a nested CALL bridge, full register effects and original guest layout.
    p=HARNESS
    p=p.replace('#include "mx_crt_cluster_guest.h"',
                '#include "mx_crt_joined_wrapper.h"')
    p=p.replace("REPLACE_SP",str(SP))
    p=p.replace("REPLACE_WIN",str(SP-128))
    p=p.replace("REPLACE_G0",str(BASE+GLOBALS[0]))
    p=p.replace("REPLACE_ENTRY",str(BASE+(TAIL_CALLBACK if tail else WRAPPER)))
    p=p.replace("REPLACE_STOP",str(STOP))
    p=p.replace('#define ENTRY UINT64_C(',
                '#define CHILD UINT64_C('+str(BASE+ENTRY)+')\n'
                '#define BASE_G1 UINT64_C('+str(BASE+GLOBALS[1])+')\n'
                '#define ENTRY UINT64_C(')
    p=p.replace("{BASE_G,global_bytes,16}",
                "{BASE_G1,global_bytes,16}")
    p=p.replace("BASE_G+8U","BASE_G1")
    p=p.replace("callee_rsp!=SP-0x30U","callee_rsp!=SP-0x60U")
    p=p.replace("if(lifted_crt_import_cluster(&s,&mem,hook,&ctx)!=",
                "if(mx_crt_joined_wrapper8(&s,&mem,ENTRY,CHILD,\n"
                "             lifted_crt_import_cluster,hook,&ctx)!=")
    if tail:
        old_bridge=('if(mx_crt_joined_wrapper8(&s,&mem,ENTRY,CHILD,\n'
                    '             lifted_crt_import_cluster,hook,&ctx)!=')
        new_bridge=('if(mx_crt_tail_callback2_to_wrapper(&s,&mem,ENTRY,'
                    'UINT64_C('+str(BASE+TAIL_ARGUMENT)+'),\n'
                    ' UINT64_C('+str(BASE+WRAPPER)+'),CHILD,\n'
                    '             lifted_crt_import_cluster,hook,&ctx)!=')
        if old_bridge not in p:
            raise RuntimeError("Native verified wrapper bridge not found for tail callback")
        p=p.replace(old_bridge,new_bridge)
    p=p.replace("REPLACE_CASES",encode(rows))
    if "REPLACE_" in p or "callee_rsp!=SP-0x30U" in p:
        raise RuntimeError("Joined native wrapper source is incompletely rendered")
    if (("mx_crt_tail_callback2_to_wrapper" if tail
         else "mx_crt_joined_wrapper8") not in p):
        raise RuntimeError("Original nested wrapper/child bridge was not emitted")
    return p

def run(exe,output):
    pe=PE(exe)
    allowed,wrapper_pcs=verify(pe)
    iat={rva:(dll,name) for rva,dll,name in import_slots(pe)}
    thunks={rva:pe.read_rva(rva,6) for rva in THUNKS}
    generated,meta=lift_crt_import_cluster(
        pe.read_rva(ENTRY,END-ENTRY),ENTRY,iat,thunks,BASE)
    if meta["decoded_instructions"]!=39 or meta["import_calls"]!=10:
        raise RuntimeError("Original child no longer matches generic bounded lifter")
    rows=[]
    covered=set()
    for case in cases():
        orig=reference_original(pe,case,allowed,wrapper_pcs)
        covered.update(orig["visited_child"])
        rows.append((fixture(case),orig))
    if (len(rows)!=16 or len(covered)!=39 or
        sum(len(ref["trace"])==2 for _,ref in rows)!=8):
        raise RuntimeError("Joined authentic branch coverage incomplete")
    joined=native_harness(rows)
    with tempfile.TemporaryDirectory(prefix="private-mx-joined-wrapper-child-") as td:
        work=Path(td)
        translated=work/"joined-original-child.c"
        harness=work/"joined-original-wrapper.c"
        translated.write_text(generated)
        harness.write_text(joined)
        flags=["-O2","-std=c11","-Wall","-Wextra","-Werror",
               "-I"+str(ROOT/"arm64-lab"/"runtime")]
        host=work/"host"
        checked(["cc",*flags,"-DHOST",str(translated),str(harness),
                 "-o",str(host)])
        checked([str(host)])
        arm=work/"joined-arm64.elf"
        checked([
            "clang","--target=aarch64-unknown-linux-gnu",
            "-fuse-ld=lld","-nostdlib","-static","-ffreestanding",
            "-fno-stack-protector","-fno-builtin",
            *flags,"-Wl,-e,smoke","-Wl,-z,max-page-size=4096",
            "-Wl,--build-id=none",str(translated),str(harness),
            "-o",str(arm),
        ])
        verified=execute_arm64_elf(arm,instruction_budget=1300000,
                                   timeout_us=11000000)
    output.mkdir(parents=True,exist_ok=True)
    result={
        "authentic_original_x64_parent_rva":hex(WRAPPER),
        "authentic_original_x64_child_rva":hex(ENTRY),
        "original_wrapper_instructions":8,
        "original_child_instructions":39,
        "original_child_coverage":len(covered),
        "original_nested_x64_vs_host_C_vs_AArch64":len(rows),
        "registered_short_cases":8,
        "registered_long_cases":8,
        "parent_calls_genuine_generated_native_child":True,
        "synthetic_direct_child_return":False,
        "guest_memory_and_volatile_registers_compared":True,
        "imported_win64_msvcr90_services_test_doubles":True,
        "initializer_table_executed":False,
        "steam_service_integrated":False,
        "native_engine_or_iOS_booted":False,
        "arm64_exit":verified["arm64_smoke_exit"],
    }
    (output/"crt-joined-wrapper-child-arm64.json").write_text(
        json.dumps(result,indent=2)+"\n")
    summary="\n".join([
        "# Authentic MX Bikes wrapper → CRT child joined ARM64 differential","",
        "- Original x64 wrapper: **8 actual instructions** at "+hex(WRAPPER),
        "- Original x64 callee: **39 actual instructions** at "+hex(ENTRY),
        "- Original reference vs generated C vs executed AArch64: **"+
          str(len(rows))+"/"+str(len(rows))+" matched**",
        "- Both original registration branches covered: **8/8 short and 8/8 long**",
        "- Native wrapper calls genuine generated native child, no fake child RET",
        "- Nested CALL return slots, Win64 imported ABI, entire guest stack",
        "  window, volatile and preserved registers and both CRT globals matched",
        "- ARM64 ELF status: **"+str(verified["arm64_smoke_exit"])+"**","",
        "**Six MSVCR90 imported services remain deterministic test doubles.",
        "No native initializer table, Steam runtime, engine, rendering",
        "or signed iPhone build has executed.**",""
    ])
    (output/"crt-joined-wrapper-child-arm64.md").write_text(summary)
    print(summary)

if __name__=="__main__":
    if len(sys.argv)!=3:
        raise SystemExit("usage: script.py owned-original-exe private-report-dir")
    run(Path(sys.argv[1]),Path(sys.argv[2]))
