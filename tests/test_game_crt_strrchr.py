"""Bounded guest CRT strrchr: compile host and execute real AArch64 test ELF."""
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

from tools.import_aot_smoke import execute_arm64_elf

ROOT=Path(__file__).resolve().parents[1]
SOURCE=r"""
#include <stdint.h>
#include "mx_game_crt_strrchr.h"
#define SRC UINT64_C(0x600100000)
#define STACK UINT64_C(0x700100000)
#define CALL UINT64_C(0x140013e80)
#define THUNK UINT64_C(0x1402aaeaa)
#define NEXT (CALL+5U)
static uint8_t letters[256],stack_bytes[256];

static int check(uint32_t character,uint32_t limit,uint64_t want) {
    mx_cfg_region r[]={
        {SRC,letters,sizeof(letters)},
        {STACK,stack_bytes,sizeof(stack_bytes)}
    };
    mx_cfg_memory memory={r,2};
    mx_crt_cluster_state s={0};
    s.rip=CALL;s.rsp=STACK+128U;
    s.rax=UINT64_C(0xdeadbeef);
    s.rcx=SRC;s.rdx=character;
    s.r8=UINT64_C(0x445566);s.zf=1U;
    int result=mx_game_crt_strrchr_import_call(
        &s,&memory,CALL,THUNK,NEXT,limit);
    uint64_t return_address=0;
    if(!mx_cfg_transfer(&memory,s.rsp-8U,
                        &return_address,8U,0))return 1;
    if(result!=MX_GAME_STRRCHR_OK||s.rax!=want||
       s.rip!=NEXT||s.rsp!=STACK+128U||
       s.imports!=1U||s.instructions!=3U||
       s.rdx!=character||s.rcx!=SRC||s.r8!=0x445566U||
       s.zf!=1U||return_address!=NEXT)return 2;
    return 0;
}
int smoke(void){
    const uint8_t path[]={
        67,58,92,77,88,66,105,107,101,115,92,
        109,120,98,105,107,101,115,46,101,120,101,0
    };
    for(uint32_t i=0;i<sizeof(path);i++)letters[i]=path[i];
    /* Last occurrence rather than the first. Win64 int->unsigned char. */
    if(check('e',23U,SRC+21U))return 1;
    if(check('m',23U,SRC+11U))return 2;
    if(check('\\',23U,SRC+10U))return 3;
    if(check(0U,23U,SRC+22U))return 4;
    if(check('Q',23U,0U))return 5;
    if(check(0x10065U,23U,SRC+21U))return 6;
    /* Searching empty string for NUL returns the starting pointer. */
    letters[0]=0U;
    if(check(0U,1U,SRC))return 7;
    if(check('A',1U,0U))return 8;
    letters[0]=path[0];
    mx_cfg_region regions[]={
        {SRC,letters,sizeof(letters)},
        {STACK,stack_bytes,sizeof(stack_bytes)}
    };
    mx_cfg_memory memory={regions,2};
    mx_crt_cluster_state s={0};
    s.rip=CALL;s.rsp=STACK+128U;s.rcx=SRC;s.rdx='e';
    s.rax=UINT64_C(0xfeed1234);
    /* When no terminator is available under limit, fail without effects. */
    if(mx_game_crt_bounded_strrchr(&s,&memory,20U)!=
       MX_GAME_STRRCHR_UNSUPPORTED||s.rax!=0xfeed1234U)
        return 9;
    mx_crt_cluster_state prev=s;
    if(mx_game_crt_strrchr_import_call(
        &s,&memory,CALL,THUNK,NEXT,20U)!=
       MX_GAME_STRRCHR_UNSUPPORTED||s.rax!=prev.rax||
       s.rip!=prev.rip||s.rsp!=prev.rsp||
       s.instructions||s.imports)return 10;
    /* Require aligned Win64 caller stack; no fake return on failure. */
    s.rsp+=8U;
    if(mx_game_crt_strrchr_import_call(
        &s,&memory,CALL,THUNK,NEXT,23U)!=
       MX_GAME_STRRCHR_BAD_STATE||s.rax!=prev.rax)return 11;
    s.rsp-=8U;
    for(uint32_t i=250U;i<256U;i++)letters[i]='x';
    s.rcx=SRC+250U;
    if(mx_game_crt_bounded_strrchr(&s,&memory,23U)!=
       MX_GAME_STRRCHR_MEMORY||s.rax!=prev.rax)return 12;
    if(mx_game_crt_bounded_strrchr(&s,&memory,0U)!=
       MX_GAME_STRRCHR_UNSUPPORTED)return 13;
    if(mx_game_crt_bounded_strrchr(&s,&memory,4097U)!=
       MX_GAME_STRRCHR_UNSUPPORTED)return 14;
    return 0;
}
#ifdef HOST
int main(void){return smoke();}
#endif
"""

class GameCRTStrrchrTests(unittest.TestCase):
    def test_bounded_guest_string_and_call_frame_on_host_and_arm64(self):
        if not shutil.which("cc") or not shutil.which("clang"):
            self.skipTest("Native and cross compilers missing")
        with tempfile.TemporaryDirectory() as td:
            root=Path(td)
            source=root/"guest-strrchr.c"
            source.write_text(SOURCE)
            common=["-std=c11","-O2","-Wall","-Wextra","-Werror",
                    "-I"+str(ROOT/"runtime")]
            host=root/"host"
            subprocess.run(["cc",*common,"-DHOST",str(source),"-o",str(host)],
                           check=True)
            subprocess.run([str(host)],check=True)
            arm=root/"arm64.elf"
            subprocess.run([
                "clang","--target=aarch64-unknown-linux-gnu",
                "-fuse-ld=lld","-nostdlib","-static","-ffreestanding",
                "-fno-builtin","-fno-stack-protector",*common,
                "-Wl,-e,smoke","-Wl,-z,max-page-size=4096",
                "-Wl,--build-id=none",str(source),"-o",str(arm)],
                check=True)
            result=execute_arm64_elf(arm,instruction_budget=300000,
                                     timeout_us=5000000)
            self.assertEqual(result["arm64_smoke_exit"],0)


if __name__=="__main__":
    unittest.main()
