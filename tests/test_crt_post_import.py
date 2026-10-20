"""Synthetic post-MSVCR90 branch and guest-memory tests."""
from pathlib import Path
import subprocess
import tempfile
import unittest
from tools.crt_post_import import after_initterm_e, after_initterm
from tools.crt_cfg_lift import UnsupportedCRT

# Purpose-built x64 only, not commercial bytes.
STATUS=bytes.fromhex("85c07410b8ff000000e913000000")
STATE=bytes.fromhex("c705260000000200000085f6750931c048870529000000")

class CRTContinuationTests(unittest.TestCase):
    def test_branch_shapes_and_rejection(self):
        source,info=after_initterm_e(STATUS,0x4000)
        self.assertEqual(info["return_success_rva"],"0x4014")
        self.assertEqual(info["return_error_rva"],"0x4021")
        self.assertIn("s->rax=255",source)
        code,meta=after_initterm(STATE,0x4100)
        self.assertEqual(meta["state_global_va"],hex(0x140004130))
        self.assertEqual(meta["lock_owner_va"],hex(0x140004140))
        with self.assertRaises(UnsupportedCRT):
            after_initterm_e(STATUS[:-1],0x4000)
        with self.assertRaises(UnsupportedCRT):
            after_initterm(STATE[:-1],0x4100)

    def test_native_success_error_recursive_release(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td)
            (root/"a.c").write_text(after_initterm_e(STATUS,0x4000)[0])
            (root/"b.c").write_text(after_initterm(STATE,0x4100)[0])
            (root/"check.c").write_text(r"""
#include <stdint.h>
#include "mx_crt_primitives.h"
int crt_after_initterm_e(mx_crt_state*);
int crt_after_initterm(mx_crt_state*,mx_cfg_memory*,int);
int main(void){
  uint8_t guest[128]={0};
  mx_cfg_region r={UINT64_C(0x140004100),guest,128};
  mx_cfg_memory m={&r,1};
  for(unsigned i=0;i<3;i++){
    mx_crt_state s={0};s.rip=UINT64_C(0x140004000);
    s.rax=i==0?0U:(i==1?1U:UINT64_C(0xffffffff));
    if(crt_after_initterm_e(&s)!=MX_CRT_BRANCH_BOUNDARY)return 10+i;
    if(i==0&&(s.rip!=UINT64_C(0x140004014)||s.rax||!s.zf))return 20;
    if(i!=0&&(s.rip!=UINT64_C(0x140004021)||s.rax!=255U||s.zf))return 21;
    uint32_t state=1U,after=0U;
    uint64_t owner=UINT64_C(0x1122334455667788),read=0;
    if(!mx_cfg_transfer(&m,UINT64_C(0x140004130),&state,4,1)||
       !mx_cfg_transfer(&m,UINT64_C(0x140004140),&owner,8,1))return 30;
    s=(mx_crt_state){0};s.rip=UINT64_C(0x140004100);
    s.rax=77U;s.rsi=i==1?1U:0U;
    if(crt_after_initterm(&s,&m,1)!=MX_CRT_BRANCH_BOUNDARY)return 40;
    if(!mx_cfg_transfer(&m,UINT64_C(0x140004130),&after,4,0)||
       !mx_cfg_transfer(&m,UINT64_C(0x140004140),&read,8,0))return 50;
    if(after!=2U||s.rip!=UINT64_C(0x140004117))return 60;
    if(i==1&&(read!=owner||s.rax!=77U||s.zf))return 70;
    if(i!=1&&(read!=0||s.rax!=owner||!s.zf))return 71;
  }
  return 0;
}
""")
            inc=Path(__file__).resolve().parents[1]/"runtime"
            exe=root/"check"
            cmd=["cc","-std=c11","-O2","-Wall","-Wextra","-Werror",
                 "-I"+str(inc),str(root/"a.c"),str(root/"b.c"),
                 str(root/"check.c"),"-o",str(exe)]
            compiled=subprocess.run(cmd,capture_output=True,text=True)
            self.assertEqual(compiled.returncode,0,compiled.stderr)
            ran=subprocess.run([str(exe)],capture_output=True,text=True)
            self.assertEqual(ran.returncode,0,f"exit={ran.returncode} {ran.stderr}")
