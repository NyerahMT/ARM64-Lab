"""Host and real AArch64 execution of exact original Steam branch caller semantics.

Only caller instructions are translated. The context object, virtual method,
return value and ownership are synthetic test inputs; not a game startup.
"""
import sys
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/"arm64-lab"))
from tools.import_aot_smoke import execute_arm64_elf

C_SOURCE=r"""
#include <stdint.h>
#include "mxbikes_steam_original_branch_native.h"
static uint8_t ctx[128],apps[64],table[128];
int smoke(void){
 mx_crt_cluster_state s={0};
 s.rip=MXB_STEAM_POST_RESTART;
 s.rax=0U;
 if(!mxb_original_steam_branch_after_return(&s) ||
    s.rip!=MXB_STEAM_INIT_CALL||!s.zf||s.cf)return 1;
 s.rip=MXB_STEAM_POST_RESTART;s.rax=1U;
 if(!mxb_original_steam_branch_after_return(&s) ||
    s.rip!=MXB_STEAM_FAILURE_BRANCH||s.zf)return 2;
 s.rip=MXB_STEAM_POST_INIT;s.rax=0U;
 if(!mxb_original_steam_branch_after_return(&s) ||
    s.rip!=MXB_STEAM_FAILURE_BRANCH||!s.zf)return 3;
 s.rip=MXB_STEAM_POST_INIT;s.rax=1U;
 if(!mxb_original_steam_branch_after_return(&s) ||
    s.rip!=MXB_STEAM_CONTEXT_PREP||s.zf)return 4;

 mx_cfg_region regions[3]={
   {UINT64_C(0x73001000),ctx,sizeof(ctx)},
   {UINT64_C(0x73002000),apps,sizeof(apps)},
   {UINT64_C(0x73003000),table,sizeof(table)}
 };
 mx_cfg_memory mem={regions,3U};
 uint64_t obj=regions[1].base,vt=regions[2].base;
 uint64_t method=UINT64_C(0x760000300);
 if(!mx_cfg_transfer(&mem,regions[0].base+0x30U,&obj,8U,1)||
    !mx_cfg_transfer(&mem,obj,&vt,8U,1)||
    !mx_cfg_transfer(&mem,vt+0x30U,&method,8U,1))return 5;
 s.rip=MXB_STEAM_CONTEXT_RETURN;
 s.rax=regions[0].base;
 s.rsp=UINT64_C(0x73004050);
 mxb_original_apps_call call={0};
 if(!mxb_original_steam_apps_method_preflight(&s,&mem,&call)||
    s.rip!=MXB_STEAM_VIRTUAL_CALL||
    s.rcx!=obj||s.rdx!=MXB_STEAM_APP_ID||s.rax!=vt||
    call.interface_object!=obj||call.interface_vtable!=vt||
    call.method_address!=method||
    call.return_pc!=MXB_STEAM_VIRTUAL_RETURN)return 6;
 s.rip=MXB_STEAM_VIRTUAL_RETURN;
 s.rax=1U; s.rcx=UINT64_C(0xffffffff);
 if(!mxb_original_steam_apps_result(&s)||
    s.rip!=MXB_STEAM_RESULT_CONTINUATION||
    s.rax!=0U||s.rcx!=0U||s.zf)return 7;
 s.rip=MXB_STEAM_VIRTUAL_RETURN;
 s.rax=0U;
 if(!mxb_original_steam_apps_result(&s)||
    s.rip!=MXB_STEAM_RESULT_CONTINUATION||
    s.rax!=1U||s.rcx!=1U||!s.zf)return 8;
 s.rip=MXB_STEAM_VIRTUAL_CALL;s.rax=1U;
 if(mxb_original_steam_apps_result(&s))return 9;
 s.rip=MXB_STEAM_CONTEXT_RETURN;s.rax=regions[0].base;
 s.rsp++;
 if(mxb_original_steam_apps_method_preflight(&s,&mem,&call))return 10;
 return 0;
}
#ifdef HOST
int main(void){return smoke();}
#endif
"""
class SteamOriginalNativeBranchTests(unittest.TestCase):
    def test_real_arm64_and_host_x64_steam_caller_semantics(self):
        with tempfile.TemporaryDirectory(prefix="mxb-native-steam-caller-") as folder:
            p=Path(folder)
            source=p/"steam_caller.c"
            source.write_text(C_SOURCE)
            includes=["-I"+str(ROOT/"scripts"),
                      "-I"+str(ROOT/"arm64-lab"/"runtime")]
            flags=["-O2","-std=c11","-Wall","-Wextra","-Werror"]
            host=p/"host"
            subprocess.run(["cc",*flags,*includes,str(source),"-DHOST",
                            "-o",str(host)],check=True,capture_output=True,text=True)
            subprocess.run([str(host)],check=True,capture_output=True,text=True)
            arm=p/"steam_caller_arm64.elf"
            subprocess.run([
                "clang","--target=aarch64-unknown-linux-gnu",
                "-fuse-ld=lld","-nostdlib","-static","-ffreestanding",
                "-fno-builtin","-fno-stack-protector",*flags,*includes,
                "-Wl,-e,smoke","-Wl,-z,max-page-size=4096",
                "-Wl,--build-id=none",str(source),"-o",str(arm)
            ],check=True,capture_output=True,text=True)
            result=execute_arm64_elf(arm,instruction_budget=150000,
                                     timeout_us=3000000)
            self.assertTrue(result["return_to_sentinel"])
if __name__=="__main__":
    unittest.main()
