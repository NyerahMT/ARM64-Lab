"""Verify original filename helper ADD RSP,0x38; RET on host and ARM64."""
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from tools.import_aot_smoke import execute_arm64_elf

ROOT=Path(__file__).resolve().parents[1]
SOURCE=r"""
#include <stdint.h>
#include "mx_game_filename_helper_return.h"
#define BASE UINT64_C(0x140000000)
#define STACK UINT64_C(0x710300000)
#define EPILOGUE (BASE+UINT64_C(0x15b862))
#define RETURN (BASE+UINT64_C(0x136769))
#define LOCAL_SP (STACK+UINT64_C(0x800))
#define CALLER_SP (LOCAL_SP+UINT64_C(0x40))
static uint8_t stack_bytes[4096];
int smoke(void) {
    mx_cfg_region region={STACK,stack_bytes,sizeof(stack_bytes)};
    mx_cfg_memory mem={&region,1};
    uint64_t ret=RETURN;
    if(!mx_cfg_transfer(&mem,LOCAL_SP+0x38U,&ret,8U,1))
        return 1;
    const mx_game_filename_helper_return_layout layout={
        EPILOGUE,RETURN,CALLER_SP,0x38U
    };
    mx_crt_cluster_state s={0};
    s.rip=EPILOGUE;s.rsp=LOCAL_SP;s.rax=BASE+0x3968a0U;
    s.rcx=0x12345U;s.rdx=0x87654U;s.zf=1U;
    s.cf=1U;s.sf=1U;s.imports=2U;s.instructions=394U;
    if(mx_game_filename_helper_return(&s,&mem,&layout)!=
        MX_GAME_HELPER_EPILOGUE_RETURNED)return 2;
    if(s.rip!=RETURN||s.rsp!=CALLER_SP||s.rax!=BASE+0x3968a0U||
       s.rcx!=0x12345U||s.rdx!=0x87654U||s.zf!=0U||
       s.cf!=0U||s.sf!=0U||s.imports!=2U||s.instructions!=396U)
        return 3;
    ret=RETURN+1U;
    if(!mx_cfg_transfer(&mem,LOCAL_SP+0x38U,&ret,8U,1))
        return 4;
    mx_crt_cluster_state failure={0};
    failure.rip=EPILOGUE;failure.rsp=LOCAL_SP;failure.rax=UINT64_C(0x55);
    if(mx_game_filename_helper_return(&failure,&mem,&layout)!=
        MX_GAME_HELPER_EPILOGUE_BAD_RETURN||
       failure.rip!=EPILOGUE||failure.rsp!=LOCAL_SP||
       failure.rax!=UINT64_C(0x55)||failure.instructions)
        return 5;
    /* The caller stack frame must match an original ABI-tested layout. */
    const mx_game_filename_helper_return_layout wrong={
        EPILOGUE,RETURN,CALLER_SP+16U,0x38U
    };
    if(mx_game_filename_helper_return(&failure,&mem,&wrong)!=
        MX_GAME_HELPER_EPILOGUE_INVALID)
        return 6;
    mx_cfg_memory empty={0};
    if(mx_game_filename_helper_return(&failure,&empty,&layout)!=
        MX_GAME_HELPER_EPILOGUE_UNMAPPED)
        return 7;
    return 0;
}
#ifdef HOST
int main(void){return smoke();}
#endif
"""

class OriginalFilenameEpilogueTest(unittest.TestCase):
    def test_native_original_win64_helper_return_host_and_arm64(self):
        if not shutil.which("cc") or not shutil.which("clang"):
            self.skipTest("Compilers missing")
        with tempfile.TemporaryDirectory() as td:
            root=Path(td)
            c=root/"test.c"
            c.write_text(SOURCE)
            opts=["-std=c11","-O2","-Wall","-Wextra","-Werror",
                  "-I"+str(ROOT/"runtime")]
            host=root/"host"
            subprocess.run(["cc",*opts,"-DHOST",str(c),"-o",str(host)],check=True)
            subprocess.run([str(host)],check=True)
            elf=root/"arm64.elf"
            subprocess.run(["clang","--target=aarch64-unknown-linux-gnu",
                "-fuse-ld=lld","-nostdlib","-static","-ffreestanding",
                "-fno-builtin","-fno-stack-protector",*opts,
                "-Wl,-e,smoke","-Wl,-z,max-page-size=4096",
                "-Wl,--build-id=none",str(c),"-o",str(elf)],check=True)
            self.assertEqual(
                execute_arm64_elf(elf)["arm64_smoke_exit"],0)

if __name__=="__main__":
    unittest.main()
