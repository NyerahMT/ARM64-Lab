"""Verify strict original-shape empty CRT helper on host and AArch64.

This assembles independent synthetic source; private original-game bytes and
C derivatives never enter this public repository.
"""
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

from tools.crt_empty_table_lift import (
    lift_empty_crt_table, UnsupportedEmptyCRTTable,
)
from tools.import_aot_smoke import execute_arm64_elf

ROOT = Path(__file__).resolve().parents[1]
START = 0x1000
IMAGE = 0x140000000

ASM = r"""
.intel_syntax noprefix
.section .text
.globl helper
helper:
  mov QWORD PTR [rsp+8],rbx
  push rdi
  sub rsp,0x20
  lea rbx,[rip+table_start]
  lea rdi,[rip+table_end]
  jmp check
walk:
  mov rax,QWORD PTR [rbx]
  test rax,rax
  je advance
  call rax
advance:
  add rbx,8
check:
  cmp rbx,rdi
  jb walk
  mov rbx,QWORD PTR [rsp+0x30]
  add rsp,0x20
  pop rdi
  ret
.globl helper_end
helper_end:
.org 0x100
table_start:
TABLE_CONTENT
table_end:
"""

DRIVER = r"""
#include <stdint.h>
#include "mx_crt_cluster_guest.h"
#define BASE UINT64_C(0x700000000)
#define SP (BASE+0x100)
#define PC UINT64_C(0x140001000)
#define RETURN UINT64_C(0x500001000)
static uint8_t bytes[1024];
int native_empty_crt_table(mx_crt_cluster_state*,mx_cfg_memory*);
int smoke(void){
  mx_cfg_region region={BASE,bytes,sizeof(bytes)};
  mx_cfg_memory memory={&region,1};
  uint64_t target=RETURN;
  if(!mx_cfg_transfer(&memory,SP,&target,8,1))return 1;
  mx_crt_cluster_state state={0};
  state.rip=PC;state.rsp=SP;
  state.rax=UINT64_C(0x123456789);
  state.rbx=UINT64_C(0xaaaa);
  state.rdi=UINT64_C(0xbbbb);
  state.zf=0;state.sf=1;state.cf=1;
  if(native_empty_crt_table(&state,&memory)!=MX_CRT_CLUSTER_RETURNED)
    return 2;
  uint64_t home=0,saved_rdi=0;
  if(!mx_cfg_transfer(&memory,SP+8,&home,8,0) ||
     !mx_cfg_transfer(&memory,SP-8,&saved_rdi,8,0)||
     home!=0xaaaaU || saved_rdi!=0xbbbbU)return 3;
  if(state.rax!=UINT64_C(0x123456789)||
     state.rbx!=0xaaaaU||state.rdi!=0xbbbbU||
     !state.zf||state.sf||state.cf||
     state.rip!=RETURN||state.rsp!=SP+8U||
     state.instructions!=12U)return 4;
  state=(mx_crt_cluster_state){0};
  state.rip=PC;state.rsp=BASE+4U;state.rax=5U;
  if(native_empty_crt_table(&state,&memory)!=MX_CRT_CLUSTER_INVALID||
     state.rax!=5U)return 5;
  state=(mx_crt_cluster_state){0};
  state.rip=PC;state.rsp=BASE+1020U;state.rax=5U;
  if(native_empty_crt_table(&state,&memory)!=MX_CRT_CLUSTER_MEMORY_FAULT||
     state.rax!=5U)return 6;
  state=(mx_crt_cluster_state){0};
  state.rip=PC+1U;state.rsp=SP;
  if(native_empty_crt_table(&state,&memory)!=MX_CRT_CLUSTER_INVALID)
    return 7;
  return 0;
}
#ifdef HOST
int main(void){return smoke();}
#endif
"""


def assemble(tmp: Path, entry: str = "") -> bytes:
    asm = tmp / "source.S"
    obj = tmp / "source.o"
    raw = tmp / "source.bin"
    asm.write_text(ASM.replace("TABLE_CONTENT", entry))
    subprocess.run(["as","--64",str(asm),"-o",str(obj)],check=True)
    subprocess.run(["objcopy","-O","binary","-j",".text",
                    str(obj),str(raw)],check=True)
    symbols={}
    for line in subprocess.check_output(["nm", "-a", str(obj)],
                                        text=True).splitlines():
        words=line.split()
        if len(words)==3:
            try: symbols[words[2]]=int(words[0],16)
            except ValueError: pass
    self_code=raw.read_bytes()[symbols["helper"]:symbols["helper_end"]]
    return self_code


class EmptyCRTTableTests(unittest.TestCase):
    def test_fails_closed_for_nonempty_or_mutated_bytecode(self):
        if not all(shutil.which(x) for x in ("as","objcopy","nm")):
            self.skipTest("Native assembler missing")
        with tempfile.TemporaryDirectory() as td:
            root=Path(td)
            empty=assemble(root)
            source,meta=lift_empty_crt_table(empty,START,IMAGE)
            self.assertIn("MX_CRT_CLUSTER_RETURNED",source)
            self.assertEqual(meta["decoded_instructions"],17)
            self.assertTrue(meta["original_callback_range_is_empty"])
            nonempty=assemble(root,".quad 0\n")
            with self.assertRaises(UnsupportedEmptyCRTTable):
                lift_empty_crt_table(nonempty,START,IMAGE)
            for code in (b"",empty[:-1],empty+b"\x90",empty.replace(b"\xc3",b"\x90")):
                with self.subTest(code=code.hex()[:16]):
                    with self.assertRaises(UnsupportedEmptyCRTTable):
                        lift_empty_crt_table(code,START,IMAGE)

    def test_guest_state_on_host_and_executed_arm64(self):
        required=("as","objcopy","nm","cc","clang")
        if not all(shutil.which(x) for x in required):
            self.skipTest("Native assembler/ARM64 compiler missing")
        with tempfile.TemporaryDirectory() as td:
            root=Path(td)
            code=assemble(root)
            src,meta=lift_empty_crt_table(code,START,IMAGE)
            self.assertEqual(meta["indirect_calls_executed"],0)
            generated=root/"helper.c"
            generated.write_text(src)
            driver=root/"driver.c"
            driver.write_text(DRIVER)
            flags=["-O2","-std=c11","-Wall","-Wextra","-Werror",
                   "-I"+str(ROOT/"runtime")]
            exe=root/"host"
            subprocess.run(["cc",*flags,"-DHOST",str(generated),
                            str(driver),"-o",str(exe)],check=True)
            subprocess.run([str(exe)],check=True)
            elf=root/"arm64.elf"
            subprocess.run(["clang","--target=aarch64-unknown-linux-gnu",
                            "-fuse-ld=lld","-nostdlib","-static",
                            "-ffreestanding","-fno-builtin","-fno-stack-protector",
                            *flags,"-Wl,-e,smoke","-Wl,-z,max-page-size=4096",
                            "-Wl,--build-id=none",str(generated),str(driver),
                            "-o",str(elf)],check=True)
            outcome=execute_arm64_elf(elf,instruction_budget=200000,
                                      timeout_us=4000000)
            self.assertEqual(outcome["arm64_smoke_exit"],0)


if __name__=="__main__":
    unittest.main()
