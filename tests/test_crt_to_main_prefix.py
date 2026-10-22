"""Synthetic shared-memory CRT direct-CALL -> game-main prefix on host/AArch64."""
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

from tools.import_aot_smoke import execute_arm64_elf

ROOT=Path(__file__).resolve().parents[1]
SOURCE=r"""
#include <stdint.h>
#include "mx_crt_to_main_prefix.h"
#define BASE UINT64_C(0x140000000)
#define CRT_CALL (BASE+0x2ab186U)
#define MAIN (BASE+0x136710U)
#define CALL_BOUNDARY (BASE+0x136741U)
#define STACK UINT64_C(0x700000000)
#define CRT_SP (STACK+0x1000U)
#define COOKIE (BASE+0x3928a0U)
#define ARG0 (BASE+0xe4b228U)
#define ARG1 (BASE+0xe4b200U)
#define SHOW (BASE+0xe4b230U)
static uint8_t stack[8192],cookie_bytes[8],arg0_bytes[8],arg1_bytes[8],show_bytes[4];
int smoke(void) {
    mx_cfg_region regions[]={
        {STACK,stack,sizeof(stack)},
        {COOKIE,cookie_bytes,sizeof(cookie_bytes)},
        {ARG0,arg0_bytes,sizeof(arg0_bytes)},
        {ARG1,arg1_bytes,sizeof(arg1_bytes)},
        {SHOW,show_bytes,sizeof(show_bytes)}
    };
    mx_cfg_memory guest={regions,5};
    uint64_t cookie=UINT64_C(0x123456789abcdeff);
    uint64_t original=UINT64_C(0xfedcba9876543210);
    if(!mx_cfg_transfer(&guest,COOKIE,&cookie,8U,1) ||
       !mx_cfg_transfer(&guest,CRT_SP-8U,&original,8U,1))
       return 1;
    mx_crt_state crt={0};
    crt.rip=CRT_CALL;
    crt.rsp=CRT_SP;
    crt.rax=0x77U;
    crt.rcx=BASE;
    crt.zf=1U;
    mx_crt_main_handoff hand={0};
    hand.reached_main_call=1U;
    hand.commands_consumed=1U;
    hand.executable_base=BASE;
    hand.main_call_pc=CRT_CALL;
    hand.rdx=0U;
    hand.r8=UINT64_C(0x600000180);
    hand.r9=10U;
    mx_crt_to_main_layout layout={0};
    layout.crt_direct_call_pc=CRT_CALL;
    layout.crt_return_pc=CRT_CALL+5U;
    layout.prefix=(mx_main_prefix_layout){
        MAIN,CALL_BOUNDARY,COOKIE,ARG0,ARG1,SHOW,0x288U,0x250U
    };
    mx_main_prefix_state main_state={0};
    if(mx_crt_enter_main_prefix(&crt,&hand,&guest,&layout,&main_state)!=
       MX_MAIN_PREFIX_CALL_BOUNDARY)return 2;
    uint64_t pushed=0,guard=0,argument=0,other=1U,show64=0;
    uint32_t show32=0;
    const uint64_t entry_rsp=CRT_SP-8U;
    const uint64_t frame_rsp=entry_rsp-0x288U;
    if(!mx_cfg_transfer(&guest,entry_rsp,&pushed,8U,0) ||
       !mx_cfg_transfer(&guest,frame_rsp+0x250U,&guard,8U,0) ||
       !mx_cfg_transfer(&guest,ARG0,&argument,8U,0) ||
       !mx_cfg_transfer(&guest,ARG1,&other,8U,0) ||
       !mx_cfg_transfer(&guest,SHOW,&show32,4U,0))return 3;
    if(pushed!=CRT_CALL+5U||guard!=(cookie^frame_rsp)||
       argument!=BASE||other!=0U||show32!=10U||
       main_state.rsp!=frame_rsp||main_state.rip!=CALL_BOUNDARY||
       main_state.rax!=guard||main_state.rcx!=hand.r8||
       main_state.rdx!=0U||main_state.r9!=10U||
       main_state.zf!=0U||main_state.sf!=0U||main_state.cf!=0U||
       main_state.instructions!=8U)return 4;
    /* The original CRT state and separate guest heap must survive intact. */
    if(crt.rsp!=CRT_SP||crt.rip!=CRT_CALL||crt.zf!=1U)return 5;
    /* No preexisting synthetic result may authorize invalid callsite,
       misaligned CALL, or missing command-line ABI. */
    mx_crt_state invalid=crt;
    invalid.rsp=CRT_SP+8U;
    if(mx_crt_enter_main_prefix(&invalid,&hand,&guest,&layout,&main_state)!=
       MX_MAIN_PREFIX_INVALID)return 6;
    hand.r8=0U;
    if(mx_crt_enter_main_prefix(&crt,&hand,&guest,&layout,&main_state)!=
       MX_MAIN_PREFIX_INVALID)return 7;
    hand.r8=UINT64_C(0x600000180);
    layout.crt_return_pc=CRT_CALL+4U;
    if(mx_crt_enter_main_prefix(&crt,&hand,&guest,&layout,&main_state)!=
       MX_MAIN_PREFIX_INVALID)return 8;
    layout.crt_return_pc=CRT_CALL+5U;
    mx_cfg_region lost[4]={regions[0],regions[1],regions[2],regions[3]};
    mx_cfg_memory unmapped={lost,4};
    uint64_t old=0;
    if(!mx_cfg_transfer(&unmapped,CRT_SP-8U,&old,8U,0))return 9;
    if(mx_crt_enter_main_prefix(&crt,&hand,&unmapped,&layout,&main_state)!=
       MX_MAIN_PREFIX_INVALID)return 10;
    if(!mx_cfg_transfer(&unmapped,CRT_SP-8U,&pushed,8U,0) ||
       pushed!=old)return 11;
    (void)show64;
    return 0;
}
#ifdef HOST
int main(void){return smoke();}
#endif
"""

class CRTToMainPrefixTests(unittest.TestCase):
    def test_one_guest_process_on_host_and_arm64(self):
        if not shutil.which("cc") or not shutil.which("clang"):
            self.skipTest("Native and AArch64 C compilers unavailable")
        with tempfile.TemporaryDirectory() as td:
            root=Path(td)
            src=root/"test.c"
            src.write_text(SOURCE)
            flags=["-std=c11","-O2","-Wall","-Wextra","-Werror",
                   "-I"+str(ROOT/"runtime")]
            host=root/"host"
            subprocess.run(["cc",*flags,"-DHOST",str(src),"-o",str(host)],
                           check=True)
            subprocess.run([str(host)],check=True)
            arm=root/"arm64.elf"
            subprocess.run([
                "clang","--target=aarch64-unknown-linux-gnu",
                "-fuse-ld=lld","-nostdlib","-static","-ffreestanding",
                "-fno-builtin","-fno-stack-protector",*flags,
                "-Wl,-e,smoke","-Wl,-z,max-page-size=4096",
                "-Wl,--build-id=none",str(src),"-o",str(arm)
            ],check=True)
            outcome=execute_arm64_elf(
                arm,instruction_budget=140000,timeout_us=4000000)
            self.assertEqual(outcome["arm64_smoke_exit"],0)

if __name__=="__main__":
    unittest.main()
