"""Original filename-helper with-separator exit: host and executed ARM64."""
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from tools.import_aot_smoke import execute_arm64_elf

ROOT=Path(__file__).resolve().parents[1]
SOURCE=r"""
#include <stdint.h>
#include "mx_game_filename_separator_finish.h"
#define GUEST UINT64_C(0x1403968a0)
#define STACK UINT64_C(0x710200000)
#define START UINT64_C(0x14015b809)
#define END UINT64_C(0x14015b862)
static uint8_t data[260],stack_bytes[128];
int smoke(void){
    const uint8_t path[]={
        67,58,92,77,88,66,105,107,101,115,92,
        109,120,98,105,107,101,115,46,101,120,101,0
    };
    for(uint32_t i=0;i<sizeof(path);i++)data[i]=path[i];
    mx_cfg_region regions[]={
        {GUEST,data,sizeof(data)},
        {STACK,stack_bytes,sizeof(stack_bytes)}
    };
    mx_cfg_memory mem={regions,2};
    const mx_game_filename_finish_layout layout={START,GUEST,END,260U};
    const uint64_t rsp=STACK+64U,sep=GUEST+10U;
    if(!mx_cfg_transfer(&mem,rsp+0x20U,(void*)&sep,8U,1))return 1;
    mx_crt_cluster_state state={0};
    state.rip=START;state.rsp=rsp;state.zf=0U;state.cf=0U;
    state.rax=0x44U;state.rdx=0x55U;
    if(mx_game_filename_finish_separator(&state,&mem,&layout)!=
       MX_GAME_FILENAME_FINISH_REACHED)return 2;
    if(state.rip!=END||state.rax!=GUEST||state.rsp!=rsp||
       state.zf!=0U||state.cf!=0U||state.rdx!=0x55U||
       state.instructions!=4U||state.imports||
       data[10]!='\\'||data[11]!=0U||data[12]!='x')
       return 3;
    uint64_t saved=0;
    if(!mx_cfg_transfer(&mem,rsp+0x20U,&saved,8U,0)||saved!=sep)
       return 4;
    /* Refuse a separator outside the owned filename buffer. */
    state=(mx_crt_cluster_state){0};
    state.rip=START;state.rsp=rsp;
    uint64_t wrong=GUEST+260U;
    if(!mx_cfg_transfer(&mem,rsp+0x20U,&wrong,8U,1))return 5;
    if(mx_game_filename_finish_separator(&state,&mem,&layout)!=
       MX_GAME_FILENAME_FINISH_INVALID||data[11]!=0U||state.instructions)
       return 6;
    /* Invalid layout cannot fabricate the original jump or memory write. */
    mx_game_filename_finish_layout broken=layout;
    broken.filename_capacity=0U;
    if(mx_game_filename_finish_separator(&state,&mem,&broken)!=
       MX_GAME_FILENAME_FINISH_INVALID)return 7;
    return 0;
}
#ifdef HOST
int main(void){return smoke();}
#endif
"""

class OriginalFilenameFinishTests(unittest.TestCase):
    def test_guest_original_separator_exit_host_and_arm64(self):
        if not shutil.which("cc") or not shutil.which("clang"):
            self.skipTest("C toolchains unavailable")
        with tempfile.TemporaryDirectory() as td:
            root=Path(td)
            c=root/"test.c"
            c.write_text(SOURCE)
            opts=["-std=c11","-O2","-Wall","-Wextra","-Werror",
                  "-I"+str(ROOT/"runtime")]
            host=root/"host"
            subprocess.run(["cc",*opts,"-DHOST",str(c),"-o",str(host)],check=True)
            subprocess.run([str(host)],check=True)
            arm=root/"arm64.elf"
            subprocess.run(["clang","--target=aarch64-unknown-linux-gnu",
                "-fuse-ld=lld","-nostdlib","-static","-ffreestanding",
                "-fno-builtin","-fno-stack-protector",*opts,
                "-Wl,-e,smoke","-Wl,-z,max-page-size=4096",
                "-Wl,--build-id=none",str(c),"-o",str(arm)],check=True)
            self.assertEqual(execute_arm64_elf(arm)["arm64_smoke_exit"],0)

if __name__=="__main__":
    unittest.main()
