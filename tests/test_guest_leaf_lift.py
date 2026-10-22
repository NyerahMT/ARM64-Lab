"""Synthetic x64 leaf validation on native host and executed AArch64."""
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

from tools.guest_leaf_lift import lift_guest_leaf_to_c, UnsupportedGuestLeaf
from tools.import_aot_smoke import execute_arm64_elf

ROOT=Path(__file__).resolve().parents[1]
HARNESS=r"""
#include <stdint.h>
#include "mx_crt_cluster_guest.h"
#define STACK UINT64_C(0x700000000)
#define SP (STACK+0x100)
#define RET UINT64_C(0x500000100)
int native_leaf_zero_a(mx_crt_cluster_state*,mx_cfg_memory*);
int native_leaf_zero_b(mx_crt_cluster_state*,mx_cfg_memory*);
int native_leaf_mov(mx_crt_cluster_state*,mx_cfg_memory*);
static uint8_t stack[1024];
int smoke(void) {
  mx_cfg_region region={STACK,stack,sizeof(stack)};
  mx_cfg_memory memory={&region,1};
  uint64_t ret=RET;
  if(!mx_cfg_transfer(&memory,SP,&ret,8,1))return 1;
  mx_crt_cluster_state x={0};
  x.rip=0x140001000;x.rsp=SP;x.rax=17U;x.zf=0;x.sf=1;x.cf=1;
  if(native_leaf_zero_a(&x,&memory)!=MX_CRT_CLUSTER_RETURNED ||
     x.rax!=0U || x.zf!=1U || x.sf!=0U || x.cf!=0U ||
     x.rip!=RET || x.rsp!=SP+8U || x.instructions!=2U)
    return 2;
  x=(mx_crt_cluster_state){0};
  x.rip=0x140001100;x.rsp=SP;x.rax=19U;x.zf=0;x.sf=1;x.cf=1;
  if(native_leaf_zero_b(&x,&memory)!=MX_CRT_CLUSTER_RETURNED ||
     x.rax!=0U || x.zf!=1U || x.sf!=0U || x.cf!=0U ||
     x.rip!=RET || x.rsp!=SP+8U)return 3;
  x=(mx_crt_cluster_state){0};
  x.rip=0x140001200;x.rsp=SP;x.rax=17U;x.zf=0;x.sf=1;x.cf=1;
  if(native_leaf_mov(&x,&memory)!=MX_CRT_CLUSTER_RETURNED ||
     x.rax!=UINT64_C(0xdeadbeef) ||
     x.zf!=0U || x.sf!=1U || x.cf!=1U ||
     x.rip!=RET || x.rsp!=SP+8U)return 4;
  x=(mx_crt_cluster_state){0};
  x.rip=0x140001000;x.rsp=STACK+1020U;x.rax=91U;
  if(native_leaf_zero_a(&x,&memory)!=MX_CRT_CLUSTER_MEMORY_FAULT ||
     x.rax!=91U || x.rsp!=STACK+1020U || x.rip!=0x140001000)
     return 5;
  x=(mx_crt_cluster_state){0};
  x.rip=0x140001001;x.rsp=SP;x.rax=91U;
  if(native_leaf_zero_a(&x,&memory)!=MX_CRT_CLUSTER_INVALID ||
     x.rax!=91U)return 6;
  x=(mx_crt_cluster_state){0};
  x.rip=0x140001000;x.rsp=SP;x.rax=91U;x.instructions=191U;
  if(native_leaf_zero_a(&x,&memory)!=MX_CRT_CLUSTER_INVALID ||
     x.instructions!=191U || x.rax!=91U)return 7;
  return 0;
}
#ifdef HOST
int main(void){return smoke();}
#endif
"""

class GuestLeafLiftTests(unittest.TestCase):
    def test_bad_boundaries_fail_closed(self):
        for blob in (b"", b"\x31\xc0", b"\x31\xc0\xc3\x90",
                     b"\x31\xd0\xc3", b"\xc3",
                     b"\xb8\x01\x02\xc3"):
            with self.subTest(code=blob.hex()):
                with self.assertRaises(UnsupportedGuestLeaf):
                    lift_guest_leaf_to_c(blob,0x140001000)
        for name in ("x-y","0invalid","foo;bar"):
            with self.assertRaises(UnsupportedGuestLeaf):
                lift_guest_leaf_to_c(b"\x31\xc0\xc3",0x140001000,name)
        for address in (0, -1, 1 << 64, True):
            with self.assertRaises(UnsupportedGuestLeaf):
                lift_guest_leaf_to_c(b"\x31\xc0\xc3",address)

    def test_native_host_and_executed_aarch64(self):
        required=("cc","clang")
        if any(not shutil.which(x) for x in required):
            self.skipTest("Cross-compiler unavailable")
        cases=[
            (bytes.fromhex("31c0c3"),0x140001000,"native_leaf_zero_a"),
            (bytes.fromhex("33c0c3"),0x140001100,"native_leaf_zero_b"),
            (bytes.fromhex("b8efbeaddec3"),0x140001200,"native_leaf_mov"),
        ]
        with tempfile.TemporaryDirectory() as td:
            tmp=Path(td)
            generated=tmp/"native-leaves.c"
            generated.write_text("\n".join(
                lift_guest_leaf_to_c(code,va,name)
                for code,va,name in cases))
            driver=tmp/"driver.c"
            driver.write_text(HARNESS)
            flags=["-O2","-std=c11","-Wall","-Wextra","-Werror",
                   "-I"+str(ROOT/"runtime")]
            host=tmp/"host"
            subprocess.run(["cc",*flags,"-DHOST",str(generated),str(driver),
                            "-o",str(host)],check=True)
            subprocess.run([str(host)],check=True)
            elf=tmp/"arm64.elf"
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
