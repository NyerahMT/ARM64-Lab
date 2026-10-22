"""Execute full bounded original filename loop composition on host and ARM64."""
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

from tools.import_aot_smoke import execute_arm64_elf

ROOT=Path(__file__).resolve().parents[1]
SOURCE=r"""
#include <stdint.h>
#include "mx_game_filename_scan.h"
#define BASE UINT64_C(0x140000000)
#define SRC UINT64_C(0x600100000)
#define STACK UINT64_C(0x710200000)
#define FOUND (BASE+UINT64_C(0x15b7f5))
#define LOOP (BASE+UINT64_C(0x15b7c1))
#define ZERO (BASE+UINT64_C(0x15b801))
#define NORMAL (BASE+UINT64_C(0x15b7db))
#define SLASH (BASE+UINT64_C(0x15b7e8))
#define WITH_SEP (BASE+UINT64_C(0x15b809))
#define NO_SEP (BASE+UINT64_C(0x15b81b))
static uint8_t bytes[260],stack[256];
static const mx_game_filename_scan_layout layout={
    {LOOP,ZERO,NORMAL},
    {NORMAL,ZERO,FOUND,SLASH,NO_SEP,WITH_SEP},
    {SLASH,FOUND,LOOP},
    FOUND,LOOP,WITH_SEP,NO_SEP,260U
};
static int seed(mx_cfg_memory*memory,const uint8_t *input,
                uint32_t len, uint64_t pointer, uint64_t last){
    if(len>sizeof(bytes))return 0;
    for(uint32_t i=0;i<sizeof(bytes);i++)bytes[i]=0xffU;
    for(uint32_t i=0;i<len;i++)bytes[i]=input[i];
    const uint64_t rsp=STACK+128U;
    return mx_cfg_transfer(memory,rsp+0x28U,&pointer,8U,1) &&
           mx_cfg_transfer(memory,rsp+0x20U,&last,8U,1);
}
int smoke(void){
    mx_cfg_region areas[]={
        {SRC,bytes,sizeof(bytes)},
        {STACK,stack,sizeof(stack)}
    };
    mx_cfg_memory memory={areas,2};
    const uint8_t path[]={
      67,58,92,77,88,66,105,107,101,115,92,
      109,120,98,105,107,101,115,46,101,120,101,0
    };
    mx_crt_cluster_state state={0};
    mx_game_filename_scan_result result={0};
    if(!seed(&memory,path,sizeof(path),SRC+2U,0U))return 1;
    state.rip=FOUND;state.rsp=STACK+128U;state.rax=0x5cU;
    state.zf=1U;state.cf=0U;state.sf=0U;
    if(mx_game_filename_scan_to_nul(&state,&memory,
        &layout,&result)!=MX_GAME_FILENAME_SCAN_REACHED)return 2;
    if(state.rip!=WITH_SEP||state.rax!=0U||
       state.instructions!=314U||state.imports!=0U||
       state.zf!=0U||state.cf!=0U||state.sf!=0U||
       result.loop_iterations!=20U||result.separator_records!=2U||
       result.ordinary_characters!=18U||
       result.terminator!=SRC+22U||
       result.last_separator!=SRC+10U||
       !result.ended_with_separator)return 3;
    uint64_t last=0,cur=0;
    if(!mx_cfg_transfer(&memory,state.rsp+0x20U,&last,8U,0)||
       !mx_cfg_transfer(&memory,state.rsp+0x28U,&cur,8U,0)||
       last!=SRC+10U||cur!=SRC+22U)return 4;

    const uint8_t bare[]={'a','b','c',0};
    if(!seed(&memory,bare,sizeof(bare),SRC,0U))return 5;
    state=(mx_crt_cluster_state){0};
    state.rip=LOOP;state.rsp=STACK+128U;
    if(mx_game_filename_scan_to_nul(&state,&memory,
        &layout,&result)!=MX_GAME_FILENAME_SCAN_REACHED)return 6;
    if(state.rip!=NO_SEP||result.ended_with_separator||
       result.last_separator||result.loop_iterations!=3U||
       result.separator_records||result.terminator!=SRC+3U)
       return 7;

    const uint8_t slash[]={'A','/','B',0};
    if(!seed(&memory,slash,sizeof(slash),SRC,0U))return 8;
    state=(mx_crt_cluster_state){0};
    state.rip=LOOP;state.rsp=STACK+128U;
    if(mx_game_filename_scan_to_nul(&state,&memory,
        &layout,&result)!=MX_GAME_FILENAME_SCAN_REACHED)return 9;
    if(state.rip!=WITH_SEP||result.last_separator!=SRC+1U||
       result.separator_records!=1U||result.loop_iterations!=3U)return 10;

    /* No NUL under the iteration cap may invent a return branch. */
    const uint8_t noend[]={'a','b','c','d','e','f'};
    if(!seed(&memory,noend,sizeof(noend),SRC,0U))return 11;
    mx_game_filename_scan_layout limited=layout;
    limited.max_bytes=2U;
    state=(mx_crt_cluster_state){0};
    state.rip=LOOP;state.rsp=STACK+128U;
    if(mx_game_filename_scan_to_nul(&state,&memory,
        &limited,&result)!=MX_GAME_FILENAME_SCAN_LIMIT)return 12;
    if(state.rip==WITH_SEP||state.rip==NO_SEP)return 13;

    /* Missing second byte must fail closed without claiming a final state. */
    state=(mx_crt_cluster_state){0};
    state.rip=LOOP;state.rsp=STACK+128U;
    uint64_t just_last=SRC+259U,empty=0U;
    if(!mx_cfg_transfer(&memory,state.rsp+0x28U,&just_last,8U,1)||
       !mx_cfg_transfer(&memory,state.rsp+0x20U,&empty,8U,1))return 14;
    if(mx_game_filename_scan_to_nul(&state,&memory,
        &layout,&result)!=MX_GAME_FILENAME_SCAN_MEMORY)return 15;
    if(state.rip==WITH_SEP||state.rip==NO_SEP)return 16;
    return 0;
}
#ifdef HOST
int main(void){return smoke();}
#endif
"""

class FilenameScanTests(unittest.TestCase):
    def test_original_filename_loop_runs_bounded_on_native_host_and_aarch64(self):
        if not shutil.which("cc") or not shutil.which("clang"):
            self.skipTest("Host/AArch64 C compiler missing")
        with tempfile.TemporaryDirectory() as td:
            root=Path(td)
            source=root/"test.c"
            source.write_text(SOURCE)
            common=["-std=c11","-O2","-Wall","-Wextra","-Werror",
                    "-I"+str(ROOT/"runtime")]
            host=root/"host"
            subprocess.run(["cc",*common,"-DHOST",str(source),"-o",str(host)],check=True)
            subprocess.run([str(host)],check=True)
            arm=root/"arm64.elf"
            subprocess.run(["clang","--target=aarch64-unknown-linux-gnu",
                "-fuse-ld=lld","-nostdlib","-static","-ffreestanding",
                "-fno-builtin","-fno-stack-protector",*common,
                "-Wl,-e,smoke","-Wl,-z,max-page-size=4096",
                "-Wl,--build-id=none",str(source),"-o",str(arm)],check=True)
            out=execute_arm64_elf(arm,instruction_budget=350000,timeout_us=5000000)
            self.assertEqual(out["arm64_smoke_exit"],0)

if __name__=="__main__":
    unittest.main()
