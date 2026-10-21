"""Regression: guest CRT command-line handoff reaches, but never executes, main."""
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
SOURCE=r"""
#include <stdint.h>
#include "mx_crt_main_handoff.h"
#define BASE UINT64_C(0x140000000)
#define GATE (BASE+UINT64_C(0xe4adc8))
#define IAT (BASE+UINT64_C(0x3214d0))
#define POST (BASE+UINT64_C(0x2ab108))
#define MAIN (BASE+UINT64_C(0x2ab186))
#define DATA UINT64_C(0x600010000)
#define STACK UINT64_C(0x70000fe00)
#define RSP (STACK+UINT64_C(0x60))
static uint8_t gate[8],iat[8],data[1024],stack[512];
static int wr(mx_cfg_memory*m,uint64_t addr,void*value,uint32_t size){
    return mx_cfg_transfer(m,addr,value,size,1);
}
int smoke(void){
    mx_cfg_region regions[]={{GATE,gate,8U},{IAT,iat,8U},
                             {DATA,data,1024U},{STACK,stack,512U}};
    mx_cfg_memory memory={regions,4};
    const uint64_t ptr=DATA+0x100U,text=DATA+0x180U;
    uint32_t mode=4U,flag=1U;
    uint16_t show=72U;
    uint8_t nul=0U;
    if(!wr(&memory,IAT,(void*)&ptr,8U)||
       !wr(&memory,ptr,(void*)&text,8U)||
       !wr(&memory,text,&nul,1U)||
       !wr(&memory,RSP+0x20U,&mode,4U)||
       !wr(&memory,RSP+0x6cU,&flag,4U)||
       !wr(&memory,RSP+0x70U,&show,2U))return 1;
    mx_crt_state s={0};s.rip=POST;s.rsp=RSP;
    mx_crt_main_handoff h={0};
    h.continuation_pc=POST;h.main_call_pc=MAIN;
    h.executable_base=BASE;h.command_line_iat_va=IAT;
    h.onexit_state_va=GATE;
    if(mx_crt_advance_to_main_call(&s,&memory,&h)!=MX_CRT_BRANCH_BOUNDARY ||
       !h.reached_main_call||s.rip!=MAIN||s.rsp!=RSP ||
       s.rdi!=text||s.rsi!=4U||s.rcx!=BASE||s.rax!=72U ||
       h.rdx!=0||h.r8!=text||h.r9!=72U||s.zf!=1U)return 2;
    uint64_t written=0;
    if(!mx_cfg_transfer(&memory,RSP+0x28U,&written,8U,0) ||
       written!=text)return 3;
    /* No branch may silently bypass either unsupported Windows exit
     * registration or unimplemented nonempty command-line handling. */
    uint64_t busy=1;
    if(!wr(&memory,GATE,&busy,8U))return 4;
    s.rip=POST;
    if(mx_crt_advance_to_main_call(&s,&memory,&h)!=MX_CRT_IMPORT_BOUNDARY||
       s.rip!=POST)return 5;
    busy=0;
    uint8_t nonempty=0x41U;
    if(!wr(&memory,GATE,&busy,8U)||
       !wr(&memory,text,&nonempty,1U))return 6;
    s.rip=POST;
    if(mx_crt_advance_to_main_call(&s,&memory,&h)!=MX_CRT_IMPORT_BOUNDARY||
       s.rip!=POST)return 7;
    if(!wr(&memory,text,&nul,1U))return 8;
    flag=0U;
    if(!wr(&memory,RSP+0x6cU,&flag,4U))return 9;
    s.rip=POST;
    if(mx_crt_advance_to_main_call(&s,&memory,&h)!=MX_CRT_BRANCH_BOUNDARY||
       h.r9!=10U||s.rax!=72U)return 10;
    return 0;
}
#ifdef HOST
int main(void){return smoke();}
#endif
"""

class CRTMainHandoffTests(unittest.TestCase):
    def test_boundaries_on_host_and_executed_aarch64(self):
        if not shutil.which("cc") or not shutil.which("clang"):
            self.skipTest("C compilers unavailable")
        with tempfile.TemporaryDirectory() as td:
            tmp=Path(td)
            src=tmp/"handoff.c"
            src.write_text(SOURCE)
            flags=["-O2","-std=c11","-Wall","-Wextra","-Werror",
                   "-I",str(ROOT/"runtime")]
            host=tmp/"host"
            subprocess.run(["cc",*flags,"-DHOST",str(src),"-o",str(host)],check=True)
            subprocess.run([str(host)],check=True)
            arm=tmp/"handoff.elf"
            subprocess.run(["clang","--target=aarch64-unknown-linux-gnu",
                            "-fuse-ld=lld","-nostdlib","-static",
                            "-ffreestanding","-fno-builtin",
                            "-fno-stack-protector",*flags,"-Wl,-e,smoke",
                            "-Wl,-z,max-page-size=4096","-Wl,--build-id=none",
                            str(src),"-o",str(arm)],check=True)
            from tools.import_aot_smoke import execute_arm64_elf
            result=execute_arm64_elf(arm,instruction_budget=200000,
                                      timeout_us=3000000)
            self.assertEqual(result["arm64_smoke_exit"],0)

if __name__=="__main__":
    unittest.main()
