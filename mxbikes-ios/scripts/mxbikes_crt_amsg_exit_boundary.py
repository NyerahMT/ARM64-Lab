#!/usr/bin/env python3
"""Pin the original _amsg_exit CALL+JMP IAT handoff as terminal.

The original callsite and imported jump are SHA-checked and decoded privately.
Native host and executed ARM64 test the existing strict CRT terminal boundary.
Neither run executes Windows MSVCR90 or claims a real guest-process abort.
No original bytes or generated executable are uploaded.
"""
from pathlib import Path
import hashlib
import json
import subprocess
import sys
import tempfile

from capstone import Cs, CS_ARCH_X86, CS_MODE_64
from capstone.x86 import X86_OP_IMM, X86_OP_MEM

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "arm64-lab"))
from tools.pe_probe import PE
from tools.import_aot_smoke import execute_arm64_elf
from mxbikes_first_callee_emu import import_slots
from mxbikes_crt_exception_callback_differential import BASE, SHA

CALLSITE = 0x2ab08d
THUNK = 0x2ab72c

HARNESS = r"""
#include <stdint.h>
#include "mx_crt_init_imports.h"
#define CALLSITE UINT64_C(__CALLSITE__)
#define RETURN_PC (CALLSITE+5U)
#define STACK UINT64_C(0x700000000)
#define SP (STACK+0x100U)
static uint8_t stack[512];
static uint32_t callback_count=0;
static int hook(void*ctx,uint32_t kind,uint64_t arg,
                uint64_t aux,uint32_t*result){
  (void)ctx;(void)kind;(void)arg;(void)aux;(void)result;
  callback_count++;
  return 1;
}
int smoke(void) {
  for(uint32_t i=0;i<sizeof(stack);i++)stack[i]=(uint8_t)(i^0x5aU);
  mx_cfg_region region={STACK,stack,sizeof(stack)};
  mx_cfg_memory mem={&region,1};
  mx_crt_state guest={0};
  guest.rip=CALLSITE;guest.rsp=SP;guest.rcx=8U;
  guest.rax=UINT64_C(0x123456789abcdef0);
  guest.rbx=UINT64_C(0x987654321);
  guest.zf=1U;
  if(mx_crt_invoke_init_thunk(&guest,&mem,MX_CRT_AMSG_EXIT,
       CALLSITE,RETURN_PC,0U,hook,0)!=MX_CRT_IMPORT_BOUNDARY)
     return 1;
  if(guest.rip!=CALLSITE||guest.rsp!=SP||guest.rax!=UINT64_C(0x123456789abcdef0)||
     guest.rcx!=8U||guest.rbx!=UINT64_C(0x987654321)||!guest.zf||
     guest.imports||guest.pending_import||guest.resume_pc||
     guest.import_trace||guest.fault||callback_count)
     return 2;
  /* No injected RET, stack push, continuation or service callback. */
  for(uint32_t i=0;i<sizeof(stack);i++)
    if(stack[i]!=(uint8_t)(i^0x5aU))return 3;
  /* An invalid return address cannot be treated as the verified call. */
  if(mx_crt_invoke_init_thunk(&guest,&mem,MX_CRT_AMSG_EXIT,
      CALLSITE,RETURN_PC+1U,0U,hook,0)!=MX_CRT_INVALID)return 4;
  return 0;
}
#ifdef HOST
int main(void){return smoke();}
#endif
"""

def run(exe: Path, report: Path) -> None:
    pe=PE(exe)
    if hashlib.sha256(pe.b).hexdigest()!=SHA:
        raise RuntimeError("Original executable SHA mismatch")
    decoder=Cs(CS_ARCH_X86,CS_MODE_64)
    decoder.detail=True
    call=list(decoder.disasm(pe.read_rva(CALLSITE,5),CALLSITE))
    if (len(call)!=1 or call[0].mnemonic!="call" or
        call[0].size!=5 or len(call[0].operands)!=1 or
        call[0].operands[0].type!=X86_OP_IMM or
        call[0].operands[0].imm!=THUNK):
        raise RuntimeError("Original fatal CRT CALL instruction changed")
    jump=list(decoder.disasm(pe.read_rva(THUNK,6),THUNK))
    if (len(jump)!=1 or jump[0].mnemonic!="jmp" or
        jump[0].size!=6 or len(jump[0].operands)!=1):
        raise RuntimeError("Original imported fatal jump changed")
    op=jump[0].operands[0]
    if (op.type!=X86_OP_MEM or jump[0].reg_name(op.mem.base)!="rip"
            or op.mem.index):
        raise RuntimeError("Original fatal thunk is not RIP-relative IAT")
    slot=jump[0].address+jump[0].size+op.mem.disp
    matches=[(dll.lower(),name) for rva,dll,name in import_slots(pe)
             if rva==slot]
    if matches!=[("msvcr90.dll","_amsg_exit")]:
        raise RuntimeError("Original fatal IAT target identity changed")
    with tempfile.TemporaryDirectory(prefix="private-original-fatal-crt-") as td:
        root=Path(td)
        source=root/"terminal.c"
        source.write_text(HARNESS.replace("__CALLSITE__",str(BASE+CALLSITE)))
        flags=["-std=c11","-O2","-Wall","-Wextra","-Werror",
               "-I"+str(ROOT/"arm64-lab"/"runtime")]
        host=root/"host"
        subprocess.run(["cc",*flags,"-DHOST",str(source),"-o",str(host)],
                       check=True)
        subprocess.run([str(host)],check=True)
        arm=root/"arm64.elf"
        subprocess.run(["clang","--target=aarch64-unknown-linux-gnu",
                        "-fuse-ld=lld","-nostdlib","-static",
                        "-ffreestanding","-fno-builtin","-fno-stack-protector",
                        *flags,"-Wl,-e,smoke","-Wl,-z,max-page-size=4096",
                        "-Wl,--build-id=none",str(source),"-o",str(arm)],check=True)
        outcome=execute_arm64_elf(arm,instruction_budget=100000,
                                  timeout_us=4000000)
        if outcome["arm64_smoke_exit"]!=0:
            raise RuntimeError("Terminal import native ARM64 fixture failed")
    report.mkdir(parents=True,exist_ok=True)
    summary={
        "authentic_callsite_rva":hex(CALLSITE),
        "authentic_import_thunk_rva":hex(THUNK),
        "verified_import":"msvcr90.dll::_amsg_exit",
        "original_call_and_jump_identity_pinned":True,
        "host_and_executed_arm64_terminal_boundary_passed":True,
        "guest_call_continuation_allowed":False,
        "original_msvcr90_code_executed":False,
        "real_process_termination_implemented":False,
        "native_engine_booted":False,
    }
    (report/"crt-original-amsg-exit-boundary.json").write_text(
        json.dumps(summary,indent=2)+"\n")
    markdown="\n".join([
        "# Authentic original fatal CRT import: terminal boundary","",
        "- SHA-pinned x64 CALL at "+hex(CALLSITE)+
          " and RIP-relative IAT JMP at "+hex(THUNK),
        "- Verified imported symbol: **msvcr90.dll::_amsg_exit**",
        "- Native host and executed ARM64: **terminal boundary contract passed**",
        "- No synthetic guest RET, no callback invocation, no resume PC,",
        "  no stack/register changes or fabricated success return","",
        "**This verifies a known fatal handoff boundary, NOT actual Windows",
        "MSVCR90 execution, host process termination, full CRT or game boot.**",""
    ])
    (report/"crt-original-amsg-exit-boundary.md").write_text(markdown)
    print(markdown)

if __name__=="__main__":
    if len(sys.argv)!=3:
        raise SystemExit("usage: script.py /private/owned-exe report-dir")
    run(Path(sys.argv[1]),Path(sys.argv[2]))
