"""Executable native/ARM64 verification for bounded CRT process services."""
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

ROOT=Path(__file__).resolve().parents[1]
SOURCE=r"""
#include <stdint.h>
#include "mx_crt_process_services.h"
#define BASE UINT64_C(0x140000000)
static uint8_t guest_bytes[512];
int smoke(void){
    mx_cfg_region reg={BASE,guest_bytes,sizeof(guest_bytes)};
    mx_cfg_memory guest={&reg,1};
    mx_crt_process p={0};
    uint64_t v=UINT64_C(0xabadcafe);
    if(mx_crt_process_bind_args(&p,&guest,3U,BASE+0x100U,
                                BASE+0x180U)!=1)return 1;
    if(mx_crt_process_getmainargs(&p,BASE+0x20U,BASE+0x30U,
                                  BASE+0x40U,0U,&v)!=1||v!=0U)return 2;
    uint32_t count=0;
    uint64_t argv=0,env=0;
    if(!mx_cfg_transfer(&guest,BASE+0x20U,&count,4U,0) ||
       !mx_cfg_transfer(&guest,BASE+0x30U,&argv,8U,0) ||
       !mx_cfg_transfer(&guest,BASE+0x40U,&env,8U,0) ||
       count!=3U||argv!=BASE+0x100U||env!=BASE+0x180U)return 3;
    v=UINT64_C(0xabadcafe);
    if(mx_crt_process_getmainargs(&p,BASE+0x20U,BASE+0x22U,
                                  BASE+0x40U,0U,&v)!=-1 ||
       v!=UINT64_C(0xabadcafe))return 4;
    if(mx_crt_process_getmainargs(&p,BASE+0x20U,BASE+0x30U,
                                  BASE+0x500U,0U,&v)!=-1 ||
       v!=UINT64_C(0xabadcafe))return 5;
    if(mx_crt_process_getmainargs(&p,BASE+0x20U,BASE+0x30U,
                                  BASE+0x40U,1U,&v)!=-1 ||
       v!=UINT64_C(0xabadcafe))return 6;
    if(!mx_cfg_transfer(&guest,BASE+0x20U,&count,4U,0) ||
       !mx_cfg_transfer(&guest,BASE+0x30U,&argv,8U,0) ||
       !mx_cfg_transfer(&guest,BASE+0x40U,&env,8U,0) ||
       count!=3U||argv!=BASE+0x100U||env!=BASE+0x180U)return 7;
    if(mx_crt_process_set_app_type(&p,2U)!=1 ||
       !p.app_type_set ||p.app_type!=2U ||
       mx_crt_process_set_app_type(&p,3U)!=-1 ||
       p.app_type!=2U)return 8;
    if(mx_crt_process_set_matherr(&p,BASE+0x220U)!=1 ||
       p.math_handler!=BASE+0x220U)return 9;
    if(mx_crt_process_configthreadlocale(&p,0U,&v)!=1 ||
       v!=2U ||p.thread_locale!=2U)return 10;
    if(mx_crt_process_configthreadlocale(&p,1U,&v)!=1 ||
       v!=2U||p.thread_locale!=1U)return 11;
    if(mx_crt_process_configthreadlocale(&p,2U,&v)!=1 ||
       v!=1U||p.thread_locale!=2U)return 12;
    v=UINT64_C(0xabcdef);
    if(mx_crt_process_configthreadlocale(&p,7U,&v)!=-1 ||
       v!=UINT64_C(0xabcdef)||p.thread_locale!=2U)return 13;
    mx_crt_process invalid={0};
    if(mx_crt_process_getmainargs(&invalid,BASE+0x20U,
                                  BASE+0x30U,BASE+0x40U,0U,&v)!=-1 ||
       mx_crt_process_bind_args(&invalid,&guest,0U,BASE+0x100U,
                                BASE+0x180U)!=-1)return 14;
    return 0;
}
#ifdef HOST
int main(void){return smoke();}
#endif
"""

class CRTProcessServiceTests(unittest.TestCase):
    def test_original_guest_memory_marshalling_on_host_and_arm64(self):
        if not shutil.which("cc") or not shutil.which("clang"):
            self.skipTest("C compilers unavailable")
        with tempfile.TemporaryDirectory() as td:
            root=Path(td)
            src=root/"process-services.c"
            src.write_text(SOURCE)
            flags=["-O2","-std=c11","-Wall","-Wextra","-Werror",
                   "-I"+str(ROOT/"runtime")]
            host=root/"host"
            subprocess.run(["cc",*flags,"-DHOST",str(src),"-o",str(host)],check=True)
            subprocess.run([str(host)],check=True)
            arm=root/"arm64.elf"
            subprocess.run(["clang","--target=aarch64-unknown-linux-gnu",
                            "-fuse-ld=lld","-nostdlib","-static",
                            "-ffreestanding","-fno-builtin","-fno-stack-protector",
                            *flags,"-Wl,-e,smoke","-Wl,-z,max-page-size=4096",
                            "-Wl,--build-id=none",str(src),"-o",str(arm)],check=True)
            from tools.import_aot_smoke import execute_arm64_elf
            res=execute_arm64_elf(arm,instruction_budget=300000,
                                  timeout_us=4000000)
            self.assertEqual(res["arm64_smoke_exit"],0)

if __name__=="__main__":
    unittest.main()
