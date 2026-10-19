"""Synthetic-only unit coverage for resumable CRT CFG translation."""
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

from tools.crt_cfg_lift import translate_crt_cfg, UnsupportedCRT

ROOT=Path(__file__).resolve().parents[1]

class CRTCFGTests(unittest.TestCase):
    def test_branch_and_continuation_code_compiles(self):
        # sub rsp,40; cmp rax,rbx; je skip; not rax; add rsp,40; ret
        source=bytes.fromhex("4883ec284839d8740348f7d04883c428c3")
        c, meta=translate_crt_cfg(source,0x1000,{})
        self.assertEqual(meta["decoded_instructions"],6)
        self.assertEqual(meta["blocks"],3)
        self.assertEqual(meta["direct_edges"],3)
        self.assertIn("goto I_100c;",c)
        self.assertIn("int lifted_crt_run(",c)
        self._compile(c)

    def test_import_pauses_and_resumes(self):
        # sub rsp,40; call qword ptr [rip+0x46]; add rsp,40; ret
        source=bytes.fromhex("4883ec28ff15460000004883c428c3")
        c,meta=translate_crt_cfg(source,0x2000,
                                  {0x2050:("kernel32.dll","GetTickCount")})
        self.assertEqual(meta["decoded_instructions"],4)
        self.assertEqual(meta["imports"][0]["iat_symbol"],"GetTickCount")
        self.assertIn("MX_CRT_PAUSED_IMPORT",c)
        self.assertIn("goto I_200a",c)
        self._compile(c)

    def test_synthetic_branches_execute_on_host(self):
        body=bytes.fromhex("4883ec284839d8740348f7d04883c428c3")
        source,_=translate_crt_cfg(body,0x1000,{})
        sample=r"""
#include <stdint.h>
#include "mx_crt_vm.h"
int lifted_crt_run(mx_crt_state *,mx_cfg_memory *);
int main(void) {
    uint8_t stack[128]={0};
    mx_cfg_region r={UINT64_C(0x500000),stack,sizeof(stack)};
    mx_cfg_memory mem={&r,1};
    for(unsigned i=0;i<2;i++) {
        mx_crt_state s={0};
        s.rip=UINT64_C(0x140001000);s.rsp=UINT64_C(0x500048);
        s.rax=(i==0 ? 7U : 0U);s.rbx=(i==0 ? 7U : 1U);
        uint64_t ret=UINT64_C(0x12345678);
        if(!mx_cfg_transfer(&mem,s.rsp,&ret,8,1))return 10;
        if(lifted_crt_run(&s,&mem)!=MX_CRT_RETURNED)return 11;
        if(s.rip!=ret || s.rsp!=UINT64_C(0x500050))return 12;
        if(s.rax!=(i==0 ? 7U : UINT64_MAX))return 13;
    }
    return 0;
}
"""
        self._execute(source,sample)

    def test_synthetic_win64_import_resume_executes(self):
        body=bytes.fromhex("4883ec28ff15460000004883c428c3")
        code,_=translate_crt_cfg(body,0x2000,
                                 {0x2050:("kernel32.dll","GetTickCount")})
        smoke=r"""
#include <stdint.h>
#include "mx_crt_vm.h"
int lifted_crt_run(mx_crt_state *,mx_cfg_memory *);
int lifted_crt_resume_import(mx_crt_state *,const mx_import_runtime *);
static uint64_t monotonic(void *p){return *(uint64_t*)p;}
int main(void) {
    uint8_t stack[128]={0};
    mx_cfg_region region={UINT64_C(0x500000),stack,sizeof(stack)};
    mx_cfg_memory memory={&region,1};
    uint64_t ret=UINT64_C(0x12345678);
    uint64_t time_ns=UINT64_C(42000000);
    mx_clock_source clock={&time_ns,monotonic,0,0};
    mx_import_runtime rt={&clock,0,0,0,0,0};
    mx_crt_state s={0};
    s.rip=UINT64_C(0x140002000);s.rsp=UINT64_C(0x500048);
    if(!mx_cfg_transfer(&memory,s.rsp,&ret,8,1))return 10;
    if(lifted_crt_run(&s,&memory)!=MX_CRT_PAUSED_IMPORT)return 11;
    if(s.pending_import!=1U || s.rsp!=UINT64_C(0x500020))return 12;
    uint64_t callee_return=0;
    if(!mx_cfg_transfer(&memory,UINT64_C(0x500018),&callee_return,8,0))return 13;
    if(callee_return!=UINT64_C(0x14000200a))return 14;
    if(lifted_crt_resume_import(&s,&rt)!=1)return 15;
    if(lifted_crt_run(&s,&memory)!=MX_CRT_RETURNED)return 16;
    if(s.rax!=42U || s.import_trace!=1U || s.imports!=1U)return 17;
    if(s.rip!=ret || s.rsp!=UINT64_C(0x500050))return 18;
    return 0;
}
"""
        self._execute(code,smoke)

    def _execute(self,source,smoke):
        with tempfile.TemporaryDirectory() as tmp:
            p=Path(tmp)
            (p/"lifted.c").write_text(source)
            (p/"smoke.c").write_text(smoke)
            runtime=ROOT/"runtime"
            exe=p/"host"
            cmd=["cc","-std=c11","-O2","-Wall","-Wextra","-Werror",
                 "-I",str(runtime),str(p/"lifted.c"),str(p/"smoke.c"),
                 *map(str,[runtime/n for n in
                     ("mx_time_compat.c","mx_guest_imports.c","mx_import_registry.c")]),
                 "-o",str(exe)]
            subprocess.run(cmd,check=True,capture_output=True,text=True)
            subprocess.run([str(exe)],check=True,capture_output=True,text=True)

    def test_unrecognized_import_rejected(self):
        source=bytes.fromhex("4883ec28ff15460000004883c428c3")
        with self.assertRaisesRegex(UnsupportedCRT,"Unverified"):
            translate_crt_cfg(source,0x2000,{})
        with self.assertRaisesRegex(UnsupportedCRT,"Unsupported runtime import"):
            translate_crt_cfg(source,0x2000,
                              {0x2050:("steam_api64.dll","SteamAPI_Init")})

    def test_unsupported_instruction_rejected(self):
        with self.assertRaisesRegex(UnsupportedCRT,"Unsupported original opcode"):
            translate_crt_cfg(bytes.fromhex("9090c3"),0x3000,{})

    def _compile(self,source):
        with tempfile.TemporaryDirectory() as temp:
            p=Path(temp)
            (p/"lifted.c").write_text(source)
            subprocess.run(["cc","-std=c11","-O2","-Wall","-Wextra","-Werror",
                            "-I",str(ROOT/"runtime"),"-c",
                            str(p/"lifted.c"),"-o",str(p/"lifted.o")],check=True,
                           capture_output=True,text=True)

if __name__=="__main__":
    unittest.main()
