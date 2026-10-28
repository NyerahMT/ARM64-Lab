#!/usr/bin/env python3
"""One real MX Bikes imported CALL -> native ARM64 runtime differential test.

Uses the authentic six-byte x64 call at RVA 0x2ab9ae to GetTickCount.
The instruction is run under Unicorn x64 with a synthetic Kernel32 import
return. The same instruction is independently lifted into C and compiled
together with the real ARM64 portable time services and import registry.
No surrounding original function is lifted and no commercial code or
object leaves the private CI runner.
"""
from __future__ import annotations

import json
from pathlib import Path
import struct
import subprocess
import sys
import tempfile

from unicorn import Uc, UC_ARCH_X86, UC_MODE_64, UC_HOOK_CODE
from unicorn.x86_const import UC_X86_REG_RIP, UC_X86_REG_RSP, UC_X86_REG_RAX

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"arm64-lab"))
from tools.pe_probe import PE
from tools.x64_import_lift import lift_import_call_site
from tools.import_aot_smoke import execute_arm64_elf
from mxbikes_first_callee_emu import import_slots

EXE_SHA="4ae7de3854b4d0a18271679fb57a1f2fdf0b21804417b85dd82055078ea123b6"
IMAGE=0x140000000
CALL_RVA=0x2ab9ae
EXPECTED_DLL="kernel32.dll"
EXPECTED_SYMBOL="GetTickCount"
STACK=0x700000000
STUB=0x600000000


def original_call_reference(code,iat_rva):
    uc=Uc(UC_ARCH_X86,UC_MODE_64)
    mapped=set()
    def map_page(addr):
        page=addr & ~4095
        if page not in mapped:
            uc.mem_map(page,4096)
            mapped.add(page)
    target=IMAGE+CALL_RVA
    slot=IMAGE+iat_rva
    map_page(target);map_page(slot);map_page(STUB)
    uc.mem_map(STACK,0x10000)
    uc.mem_write(target,code)
    uc.mem_write(slot,struct.pack("<Q",STUB))
    uc.mem_write(STUB,b"\xc3")
    guest_rsp=STACK+0xffe0  # Caller RSP 0 mod 16 before call; 32 shadow bytes
    uc.reg_write(UC_X86_REG_RSP,guest_rsp)
    uc.reg_write(UC_X86_REG_RIP,target)
    entered=[]
    def on_code(machine,addr,size,user):
        if addr==STUB:
            if machine.reg_read(UC_X86_REG_RSP)!=guest_rsp-8:
                raise AssertionError("Win64 CALL did not push an eight-byte return address")
            entered.append(addr)
            machine.reg_write(UC_X86_REG_RAX,1234)
    uc.hook_add(UC_HOOK_CODE,on_code)
    uc.emu_start(target,target+len(code),timeout=1_000_000,count=8)
    if len(entered)!=1 or uc.reg_read(UC_X86_REG_RIP)!=target+len(code):
        raise RuntimeError("Original imported CALL did not return from synthetic Win32 stub")
    if uc.reg_read(UC_X86_REG_RSP)!=guest_rsp or uc.reg_read(UC_X86_REG_RAX)!=1234:
        raise RuntimeError("Original CALL register/stack semantics differ")
    return {"original_instruction_executed":True,"x64_import_return_rax":1234,
            "guest_stack_balanced":True,"synthetic_stub_only":True}


SMOKE_C = r'''#include <stdint.h>
#include "mx_import_registry.h"
int lifted_import_callsite(const mx_import_runtime *,mx_win64_call *);
typedef struct { uint64_t now; unsigned int sleep_calls; } fake_clock;
static uint64_t mono(void *data){return ((fake_clock*)data)->now;}
static uint64_t real(void *data){(void)data;return 0;}
static void sleeping(void *data,uint64_t ns){(void)ns;((fake_clock*)data)->sleep_calls++;}
static int no_guest_write(void *data,uint64_t ptr,const uint8_t *bytes,uint32_t n){
 (void)data;(void)ptr;(void)bytes;(void)n;return 0;
}
int smoke(void){
 fake_clock f={UINT64_C(1234000000),0};
 mx_clock_source clock={&f,mono,real,sleeping};
 mx_import_runtime rt={&clock,no_guest_write,&f};
 mx_win64_call guest={0};
 guest.rsp=UINT64_C(0x70000ffe0);
 if(lifted_import_callsite(&rt,&guest)!=1)return 1;
 if(guest.rax!=1234)return 2;
 if(guest.rsp!=UINT64_C(0x70000ffe0))return 3;
 if(f.sleep_calls)return 4;
 if(mx_dispatch_supported_win64_import(&rt,"steam_api64.dll","SteamAPI_Init",&guest)!=0)return 5;
 if(guest.rax!=1234)return 6;
 return 0;
}
#ifdef HOST_SMOKE
int main(void){return smoke();}
#endif
'''


def prove(executable,output):
    root=Path(__file__).resolve().parents[1]/"arm64-lab"
    pe=PE(executable)
    inventory=pe.inventory()
    if inventory["sha256"]!=EXE_SHA:
        raise ValueError("Unexpected executable revision")
    iat={rva:(dll,name) for rva,dll,name in import_slots(pe)}
    blob=pe.read_rva(CALL_RVA,6)
    lifted,meta=lift_import_call_site(blob,CALL_RVA,iat)
    if (meta["dll"].lower(),meta["symbol"])!=(EXPECTED_DLL,EXPECTED_SYMBOL):
        raise RuntimeError("Original RVA is not the expected GetTickCount imported CALL")
    reference=original_call_reference(blob,int(meta["iat_rva"],16))
    with tempfile.TemporaryDirectory(prefix="private-real-mxbikes-call-") as t:
        temp=Path(t)
        generated=temp/"original-callsite-generated.c"
        smoke=temp/"smoke.c"
        generated.write_text(lifted)
        smoke.write_text(SMOKE_C)
        sources=[str(root/"runtime"/name) for name in
                 ("mx_time_compat.c","mx_guest_imports.c","mx_import_registry.c")]
        inc=f"-I{root/'runtime'}"
        host=temp/"host_test"
        host_cmd=["cc","-std=c11","-O2","-DHOST_SMOKE",
                  "-Wall","-Wextra","-Werror",inc,str(generated),str(smoke),
                  *sources,"-o",str(host)]
        subprocess.run(host_cmd,check=True)
        subprocess.run([str(host)],check=True)
        arm=temp/"real_import_arm64.elf"
        arm_cmd=["clang","--target=aarch64-unknown-linux-gnu","-fuse-ld=lld",
                 "-nostdlib","-static","-ffreestanding","-fno-stack-protector",
                 "-fno-builtin","-O2","-std=c11",inc,
                 "-Wl,-e,smoke","-Wl,--build-id=none","-Wl,-z,max-page-size=4096",
                 str(generated),str(smoke),*sources,"-o",str(arm)]
        result=subprocess.run(arm_cmd,text=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
        if result.returncode:
            raise RuntimeError("ARM64 compile error: "+result.stderr[-2500:])
        arm_report=execute_arm64_elf(arm)
    report={
      "original_exe_sha256":EXE_SHA,
      "original_instruction_rva":hex(CALL_RVA),
      "original_instruction_count":1,
      "resolved_import":EXPECTED_DLL+"!"+EXPECTED_SYMBOL,
      "verified_real_guest_x64_instruction":reference,
      "host_generated_code_test":"pass",
      "arm64_aot_smoke":arm_report,
      "native_arm64_registry_invoked":True,
      "original_entire_function_translated":False,
      "original_game_booted":False,
      "steam_initialized":False,
      "limitations":[
          "Only a single original six-byte CALL imported instruction was translated, not its surrounding function.",
          "The x64 reference used a synthetic import RET; native ARM64 uses deterministic portable clock service.",
          "Guest Win64 caller stack state is supplied externally; real PE import loader, function ABI and control-flow reconstruction remain unsolved.",
          "ARM64 ELF under Unicorn is not signed iOS Mach-O code."
      ],
    }
    output.mkdir(parents=True,exist_ok=True)
    (output/"original-import-arm64.json").write_text(json.dumps(report,indent=2)+"\n")
    summary="\n".join([
      "# Original MX Bikes import CALL -> AArch64 execution proof","",
      "- Original six-byte x64 imported CALL RVA: "+hex(CALL_RVA),
      "- Target: KERNEL32.dll!GetTickCount (verified from original IAT)",
      "- Original instruction executed in Unicorn x64 with synthetic API RET: PASS",
      "- Generated function called real native import registry and timing implementation: PASS",
      "- Native host compiled execution: PASS",
      "- Original instruction's imported-call effects executed on Unicorn ARM64: PASS",
      "- Return RAX: 1234; guest RSP preserved; Steam success was **not** fabricated",
      "",
      "**Exactly one original import-call instruction translated. Not full game function, engine startup, or iOS app.**",""
    ])
    (output/"original-import-arm64.md").write_text(summary)
    print(summary)


def main():
    if len(sys.argv)!=3:
        raise SystemExit("usage: python mxbikes_real_import_call_proof.py ORIGINAL_EXE REPORT_DIR")
    prove(Path(sys.argv[1]),Path(sys.argv[2]))


if __name__=="__main__":
    main()
