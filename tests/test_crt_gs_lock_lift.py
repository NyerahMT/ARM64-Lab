"""Synthetic x64 GS/TEB and single-thread CMPXCHG native block tests."""
from pathlib import Path
import subprocess
import tempfile
import unittest
from tools.crt_cfg_lift import UnsupportedCRT
from tools.crt_gs_lock_lift import lift_crt_gs_lock_prefix

# Synthetic fixture differs from original game offsets, globals, branches.
SRC=bytes.fromhex("9065488b042538000000488b781031f631c0f0480fb13d450000007402")
START=0x4000

class GSLockTests(unittest.TestCase):
    def test_both_cmpxchg_outcomes_on_native_host(self):
        source,meta=lift_crt_gs_lock_prefix(SRC,START)
        self.assertEqual(meta["original_instructions_executed"],6)
        self.assertEqual(meta["stop_before_branch_rva"],"0x401b")
        self.assertFalse(meta["fully_models_lock_atomicity"])
        smoke=r"""
#include <stdint.h>
#include "mx_crt_primitives.h"
int lifted_crt_gs_lock_prefix(mx_crt_state*,mx_cfg_memory*,uint64_t,int);
int main(void) {
    uint8_t teb[128]={0},shared[8]={0};
    mx_cfg_region regions[2]={{UINT64_C(0x500000),teb,sizeof(teb)},
                              {UINT64_C(0x140004060),shared,sizeof(shared)}};
    mx_cfg_memory m={regions,2};
    uint64_t ptr=UINT64_C(0x500000);
    uint64_t thread=UINT64_C(0xaabbccdd11223344);
    if(!mx_cfg_transfer(&m,UINT64_C(0x500038),&ptr,8,1) ||
       !mx_cfg_transfer(&m,UINT64_C(0x500010),&thread,8,1))return 1;
    for(unsigned n=0;n<2;n++) {
        uint64_t initial=(n==0 ? 0 : 99);
        if(!mx_cfg_transfer(&m,UINT64_C(0x140004060),&initial,8,1))return 2;
        mx_crt_state s={0};
        s.rip=UINT64_C(0x140004000);
        s.rax=777;s.rsi=555;s.rdi=444;s.rsp=UINT64_C(0x600008);
        if(lifted_crt_gs_lock_prefix(&s,&m,UINT64_C(0x500000),1)!=MX_CRT_BRANCH_BOUNDARY)return 3;
        if(s.visited!=63U || s.instructions!=6U || s.rip!=UINT64_C(0x14000401b))return 4;
        if(s.rsi!=0 || s.rdi!=thread || s.rsp!=UINT64_C(0x600008) || s.fault)return 5;
        uint64_t final=0;
        if(!mx_cfg_transfer(&m,UINT64_C(0x140004060),&final,8,0))return 6;
        if(n==0 && (final!=thread || s.rax!=0 || !s.zf))return 7;
        if(n==1 && (final!=99 || s.rax!=99 || s.zf))return 8;
    }
    return 0;
}
"""
        rootrepo=Path(__file__).resolve().parents[1]
        with tempfile.TemporaryDirectory() as td:
            p=Path(td)
            (p/"lifted.c").write_text(source)
            (p/"test.c").write_text(smoke)
            binary=p/"check"
            cmd=["cc","-std=c11","-O2","-Wall","-Wextra","-Werror",
                 "-I",str(rootrepo/"runtime"),str(p/"lifted.c"),
                 str(p/"test.c"),"-o",str(binary)]
            c=subprocess.run(cmd,capture_output=True,text=True)
            self.assertEqual(c.returncode,0,c.stderr)
            result=subprocess.run([str(binary)],capture_output=True,text=True)
            self.assertEqual(result.returncode,0,
                             f"CMPXCHG guest test exited {result.returncode}: {result.stderr}")

    def test_reject_bad_instruction(self):
        altered=bytearray(SRC)
        altered[0]=0xcc
        with self.assertRaises(UnsupportedCRT):
            lift_crt_gs_lock_prefix(bytes(altered),START)

    def test_reject_missing_branch(self):
        with self.assertRaises(UnsupportedCRT):
            lift_crt_gs_lock_prefix(SRC[:-2],START)

if __name__=="__main__":
    unittest.main()
