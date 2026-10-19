"""Synthetic regression tests for the bounded second-CRT pre-import prologue."""
from pathlib import Path
import subprocess
import tempfile
import unittest
from capstone import Cs,CS_ARCH_X86,CS_MODE_64
from tools.crt_cfg_lift import UnsupportedCRT
from tools.crt_entry_prefix_lift import lift_crt_entry_prefix

ROOT=Path(__file__).resolve().parents[1]
CODE=bytes.fromhex("4889742410574883ec408364241800488d4c2428ff1520000000")
START=0x4000
BOUNDARY=0x4014
IAT_SLOT=0x403a
IAT={IAT_SLOT:("kernel32.dll","GetStartupInfoA")}

class PrefixTests(unittest.TestCase):
    def test_supported_prologue_native_execution(self):
        text,meta=lift_crt_entry_prefix(CODE,START,IAT)
        self.assertEqual(meta["original_prefix_instruction_count"],5)
        self.assertEqual(meta["stop_before_import_rva"],hex(BOUNDARY))
        self.assertFalse(meta["api_executed"])
        smoke=r"""
#include <stdint.h>
#include "mx_crt_vm.h"
int lifted_crt_entry_prefix(mx_crt_state *,mx_cfg_memory *);
int main(void) {
    uint8_t stack[256]={0};
    mx_cfg_region reg={UINT64_C(0x500000),stack,sizeof(stack)};
    mx_cfg_memory mem={&reg,1};
    mx_crt_state s={0};
    s.rsp=UINT64_C(0x500088);
    s.rip=UINT64_C(0x140004000);
    s.rax=99;s.rsi=UINT64_C(0x1122334455667788);
    s.rdi=UINT64_C(0x8877665544332211);
    uint32_t filled=UINT32_C(0xffffffff);
    if(!mx_cfg_transfer(&mem,UINT64_C(0x500057),&filled,4,1))return 1;
    if(lifted_crt_entry_prefix(&s,&mem)!=MX_CRT_IMPORT_BOUNDARY)return 2;
    if(s.rsp!=UINT64_C(0x500040) || s.rip!=UINT64_C(0x140004014))return 3;
    if(s.rcx!=UINT64_C(0x500068) || s.rax!=99 || s.visited!=31U ||
       s.instructions!=5U || s.pending_import!=0U || !s.zf)return 4;
    uint64_t saved=0,pushed=0;
    uint32_t zero=1;
    if(!mx_cfg_transfer(&mem,UINT64_C(0x500098),&saved,8,0) ||
       !mx_cfg_transfer(&mem,UINT64_C(0x500080),&pushed,8,0) ||
       !mx_cfg_transfer(&mem,UINT64_C(0x500058),&zero,4,0))return 5;
    if(saved!=s.rsi || pushed!=s.rdi || zero!=0)return 6;
    if(lifted_crt_entry_prefix(&s,&mem)!=MX_CRT_INVALID)return 7;
    return 0;
}
"""
        with tempfile.TemporaryDirectory() as td:
            root=Path(td)
            (root/"lifted.c").write_text(text)
            (root/"check.c").write_text(smoke)
            exe=root/"prefix"
            r=subprocess.run(["cc","-std=c11","-O2","-Wall","-Wextra","-Werror",
                              "-I",str(ROOT/"runtime"),str(root/"lifted.c"),
                              str(root/"check.c"),"-o",str(exe)],
                             capture_output=True,text=True)
            self.assertEqual(r.returncode,0,r.stderr)
            out=subprocess.run([str(exe)],capture_output=True,text=True)
            self.assertEqual(out.returncode,0,
                             f"synthetic prologue native exit={out.returncode} {out.stderr}")

    def test_unrecognized_api_rejected(self):
        with self.assertRaisesRegex(UnsupportedCRT,"Unsupported imported"):
            lift_crt_entry_prefix(CODE,START,
                                  {IAT_SLOT:("steam_api64.dll","SteamAPI_Init")})

    def test_unmapped_import_rejected(self):
        with self.assertRaisesRegex(UnsupportedCRT,"Unsupported imported"):
            lift_crt_entry_prefix(CODE,START,{})

    def test_code_boundary_rejected(self):
        with self.assertRaises(UnsupportedCRT):
            lift_crt_entry_prefix(CODE[:-1],START,IAT)

    def test_unsupported_instruction_form_rejected(self):
        modified=bytearray(CODE)
        modified[4]=0
        with self.assertRaises(UnsupportedCRT):
            lift_crt_entry_prefix(bytes(modified),START,IAT)

if __name__=="__main__":
    unittest.main()
