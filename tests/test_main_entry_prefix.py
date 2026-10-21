"""Host and executed AArch64 checks for an authentic Win64 main first block."""
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

ROOT=Path(__file__).resolve().parents[1]
SOURCE=r"""
#include <stdint.h>
#include "mx_main_entry_prefix.h"
#define BASE UINT64_C(0x140000000)
#define STACK UINT64_C(0x70000f000)
#define SP (STACK+0x800U)
#define COOKIE (BASE+0x3928a0U)
#define ARG0 (BASE+0xe8b228U)
#define ARG1 (BASE+0xe8ad00U)
#define SHOW (BASE+0xe8b230U)
static uint8_t stack[4096],cookie[8],arg0[8],arg1[8],show[4];
static int wr(mx_cfg_memory*m,uint64_t addr,void*v,uint32_t n){
    return mx_cfg_transfer(m,addr,v,n,1);
}
static int rd(mx_cfg_memory*m,uint64_t addr,void*v,uint32_t n){
    return mx_cfg_transfer(m,addr,v,n,0);
}
int smoke(void){
    mx_cfg_region regions[]={
        {STACK,stack,sizeof(stack)},
        {COOKIE,cookie,sizeof(cookie)},
        {ARG0,arg0,sizeof(arg0)},
        {ARG1,arg1,sizeof(arg1)},
        {SHOW,show,sizeof(show)}
    };
    mx_cfg_memory m={regions,5};
    mx_main_prefix_layout layout={
      BASE+0x136710U,BASE+0x136741U,COOKIE,
      ARG0,ARG1,SHOW,0x288U,0x250U};
    for(uint32_t i=0;i<12U;i++){
        uint64_t c=UINT64_C(0x1234567887654321)+i*33U;
        if(!wr(&m,COOKIE,&c,8U))return 1;
        mx_main_prefix_state s={0};
        s.rip=layout.entry;
        s.rsp=SP;
        s.rax=UINT64_C(0xaabbcc);
        s.rcx=BASE+i*13U;
        s.rdx=UINT64_C(0x32345)+i*3U;
        s.r8=UINT64_C(0x600010180)+i;
        s.r9=UINT64_C(0xab00000000)+i;
        uint64_t expected_rsp=SP-0x288U;
        uint64_t expected_rax=c^expected_rsp;
        if(mx_main_execute_prefix(&s,&m,&layout)!=MX_MAIN_PREFIX_CALL_BOUNDARY ||
           s.rax!=expected_rax || s.rsp!=expected_rsp ||
           s.rip!=layout.call_site || s.rcx!=UINT64_C(0x600010180)+i ||
           s.rdx!=UINT64_C(0x32345)+i || s.r8!=UINT64_C(0x600010180)+i ||
           s.instructions!=8U || s.zf!=(expected_rax==0U))return 2;
        uint64_t memory_cookie=0,arg_a=0,arg_b=0;
        uint32_t winshow=0;
        if(!rd(&m,expected_rsp+0x250U,&memory_cookie,8U) ||
           !rd(&m,ARG0,&arg_a,8U) ||
           !rd(&m,ARG1,&arg_b,8U) ||
           !rd(&m,SHOW,&winshow,4U) ||
           memory_cookie!=expected_rax ||
           arg_a!=BASE+i*13U ||
           arg_b!=UINT64_C(0x32345)+i*3U ||
           winshow!=i)return 3;
        if(mx_main_execute_prefix(&s,&m,&layout)!=MX_MAIN_PREFIX_INVALID)
            return 4;
    }
    mx_main_prefix_state invalid={0};
    invalid.rip=layout.entry;invalid.rsp=SP;
    mx_main_prefix_layout bad=layout;
    bad.show_global=BASE+0xdead0000U;
    uint64_t untouched=0;
    if(mx_main_execute_prefix(&invalid,&m,&bad)!=MX_MAIN_PREFIX_INVALID ||
       invalid.instructions!=0U || invalid.rsp!=SP ||
       !rd(&m,ARG0,&untouched,8U) || untouched!=BASE+11U*13U)
        return 5;
    return 0;
}
#ifdef HOST
int main(void){return smoke();}
#endif
"""
class MainEntryPrefixTests(unittest.TestCase):
    def test_host_and_executed_aarch64(self):
        if not shutil.which("cc") or not shutil.which("clang"):
            self.skipTest("host/AArch64 C compiler unavailable")
        with tempfile.TemporaryDirectory() as td:
            root=Path(td)
            src=root/"main_prefix.c"
            src.write_text(SOURCE)
            flags=["-O2","-std=c11","-Wall","-Wextra","-Werror",
                   "-I",str(ROOT/"runtime")]
            exe=root/"host"
            subprocess.run(["cc",*flags,"-DHOST",str(src),"-o",str(exe)],check=True)
            subprocess.run([str(exe)],check=True)
            arm=root/"arm64.elf"
            subprocess.run(["clang","--target=aarch64-unknown-linux-gnu",
                 "-fuse-ld=lld","-nostdlib","-static","-ffreestanding",
                 "-fno-builtin","-fno-stack-protector",
                 *flags,"-Wl,-e,smoke","-Wl,-z,max-page-size=4096",
                 "-Wl,--build-id=none",str(src),"-o",str(arm)],check=True)
            from tools.import_aot_smoke import execute_arm64_elf
            result=execute_arm64_elf(arm,instruction_budget=350000,
                                     timeout_us=4000000)
            self.assertEqual(result["arm64_smoke_exit"],0)

if __name__=="__main__":
    unittest.main()
