"""Host and executed AArch64 tests of bounded CRT callback table walking."""
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

ROOT=Path(__file__).resolve().parents[1]
SOURCE=r"""
#include <stdint.h>
#include "mx_crt_initializer_walk.h"
#define BASE UINT64_C(0x140032000)
#define OK UINT64_C(0x140010000)
#define ERROR UINT64_C(0x140020000)
#define UNSUPPORTED UINT64_C(0x140030000)
#define FAULT UINT64_C(0x140040000)
static uint64_t ptrs[8];
static uint64_t observed[8];
static uint32_t index_observed[8];
static uint32_t dispatched;
static int dispatch(void *ctx,uint64_t addr,uint32_t index,uint8_t is_e,
                    uint32_t *result){
    (void)ctx;
    if(!result||!addr||dispatched>=8U)return -1;
    observed[dispatched]=addr;
    index_observed[dispatched]=index;
    dispatched++;
    if(addr==UNSUPPORTED)return 0;
    if(addr==FAULT)return -1;
    if(addr==OK){*result=0;return 1;}
    if(addr==ERROR){*result=is_e?42U:UINT32_MAX;return 1;}
    return 0;
}
int smoke(void){
    mx_cfg_region range={BASE,(uint8_t*)ptrs,sizeof(ptrs)};
    mx_cfg_memory guest={&range,1};
    mx_crt_init_walk out={0};
    int r;
    for(uint32_t i=0;i<8;i++)ptrs[i]=0;
    /* _initterm_e short circuits at first nonzero int callback. */
    ptrs[1]=OK;ptrs[2]=ERROR;ptrs[3]=FAULT;
    dispatched=0;
    r=mx_crt_walk_initializers(&guest,BASE,BASE+32U,1,dispatch,0,&out);
    if(r!=MX_CRT_INIT_TABLE_EARLY_ERROR||out.slots_examined!=3U||
       out.skipped_nulls!=1U||out.callbacks_invoked!=2U||
       out.callback_error_status!=42U||
       out.failed_slot_address!=BASE+16U||
       out.failed_function_address!=ERROR||
       dispatched!=2U||observed[0]!=OK||observed[1]!=ERROR||
       index_observed[0]!=1U||index_observed[1]!=2U)return 1;
    /* _initterm is void: it must visit both OK and ERROR callbacks. */
    dispatched=0;
    r=mx_crt_walk_initializers(&guest,BASE,BASE+24U,0,dispatch,0,&out);
    if(r!=MX_CRT_INIT_TABLE_COMPLETE||out.slots_examined!=3U||
       out.callbacks_invoked!=2U||dispatched!=2U||
       out.callback_error_status!=0U)return 2;
    /* Unsupported at third non-null is not silently skipped. */
    ptrs[3]=UNSUPPORTED;dispatched=0;
    r=mx_crt_walk_initializers(&guest,BASE,BASE+32U,0,dispatch,0,&out);
    if(r!=MX_CRT_INIT_TABLE_UNSUPPORTED||out.slots_examined!=4U||
       out.callbacks_invoked!=2U||out.failed_slot_address!=BASE+24U||
       out.failed_function_address!=UNSUPPORTED)return 3;
    /* A callback error is separate from an unsupported callback. */
    ptrs[3]=FAULT;dispatched=0;
    r=mx_crt_walk_initializers(&guest,BASE,BASE+32U,0,dispatch,0,&out);
    if(r!=MX_CRT_INIT_TABLE_CALLBACK_FAULT||
       out.failed_function_address!=FAULT)return 4;
    /* Unmapped slot is memory fault, not a callback execution failure. */
    for(uint32_t i=0;i<8;i++)ptrs[i]=0;
    r=mx_crt_walk_initializers(&guest,BASE,BASE+80U,0,dispatch,0,&out);
    if(r!=MX_CRT_INIT_TABLE_MEMORY_FAULT||
       out.failed_slot_address!=BASE+64U)return 6;
    /* Empty range and all-null tables are both successful. */
    dispatched=0;
    r=mx_crt_walk_initializers(&guest,BASE,BASE,1,dispatch,0,&out);
    if(r!=MX_CRT_INIT_TABLE_COMPLETE||out.slots_examined||dispatched)return 7;
    r=mx_crt_walk_initializers(&guest,BASE,BASE+64U,0,dispatch,0,&out);
    if(r!=MX_CRT_INIT_TABLE_COMPLETE||out.skipped_nulls!=8U||
       out.callbacks_invoked!=0U||dispatched)return 8;
    if(mx_crt_walk_initializers(&guest,BASE+1U,BASE+8U,0,dispatch,0,&out)!=
       MX_CRT_INIT_TABLE_INVALID)return 9;
    if(mx_crt_walk_initializers(&guest,BASE,BASE+520U,0,dispatch,0,&out)!=
       MX_CRT_INIT_TABLE_INVALID)return 10;
    if(mx_crt_walk_initializers(&guest,BASE+16U,BASE,0,dispatch,0,&out)!=
       MX_CRT_INIT_TABLE_INVALID)return 11;
    if(mx_crt_walk_initializers(&guest,BASE,BASE+16U,2,dispatch,0,&out)!=
       MX_CRT_INIT_TABLE_INVALID)return 12;
    if(mx_crt_walk_initializers(&guest,BASE,BASE+16U,1,0,0,&out)!=
       MX_CRT_INIT_TABLE_INVALID)return 13;
    return 0;
}
#ifdef HOST
int main(void){return smoke();}
#endif
"""

class CRTInitWalkTests(unittest.TestCase):
    def test_original_abi_style_synthetic_tables_host_and_arm64(self):
        if not shutil.which("cc") or not shutil.which("clang"):
            self.skipTest("host/ARM64 compiler unavailable")
        with tempfile.TemporaryDirectory() as td:
            work=Path(td)
            path=work/"crt-init-walk.c"
            path.write_text(SOURCE)
            flags=["-O2","-std=c11","-Wall","-Wextra","-Werror",
                   "-I"+str(ROOT/"runtime")]
            host=work/"host"
            subprocess.run(["cc",*flags,"-DHOST",str(path),"-o",str(host)],check=True)
            subprocess.run([str(host)],check=True)
            elf=work/"init-walk-arm64.elf"
            subprocess.run([
                "clang","--target=aarch64-unknown-linux-gnu",
                "-fuse-ld=lld","-nostdlib","-static","-ffreestanding",
                "-fno-builtin","-fno-stack-protector",*flags,
                "-Wl,-e,smoke","-Wl,-z,max-page-size=4096",
                "-Wl,--build-id=none",str(path),"-o",str(elf)
            ],check=True)
            from tools.import_aot_smoke import execute_arm64_elf
            result=execute_arm64_elf(elf,instruction_budget=280000,
                                     timeout_us=4500000)
            self.assertEqual(result["arm64_smoke_exit"],0)

if __name__=="__main__":
    unittest.main()
