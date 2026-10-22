"""Host and executed AArch64 original game-main directory import adapter."""
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from tools.import_aot_smoke import execute_arm64_elf

ROOT=Path(__file__).resolve().parents[1]
SOURCE=r"""
#include <stdint.h>
#include "mx_game_virtual_current_directory.h"
#define BASE UINT64_C(0x140000000)
#define GLOBAL (BASE+UINT64_C(0x3968a0))
#define STACK UINT64_C(0x710300000)
#define MAIN (BASE+UINT64_C(0x136769))
#define CALL (BASE+UINT64_C(0x13676c))
#define AFTER (BASE+UINT64_C(0x136772))
#define NEXT (BASE+UINT64_C(0x13677f))
#define ARG (BASE+UINT64_C(0xe4adf0))
#define TEXT (BASE+UINT64_C(0xe4ae20))
static uint8_t path[260],stack_bytes[512],dword[8];
static int allow(void*opaque,const uint8_t*name,uint32_t n){
    int *result=(int*)opaque;
    const uint8_t expected[]={'C',':','\\','M','X','B','i','k','e','s','\\'};
    if(n!=sizeof(expected))return -1;
    for(uint32_t i=0;i<n;i++)if(name[i]!=expected[i])return -1;
    return *result;
}
static int verify(uint32_t expected_success){
    mx_cfg_region regions[]={
        {GLOBAL,path,sizeof(path)},{STACK,stack_bytes,sizeof(stack_bytes)},
        {ARG,dword,sizeof(dword)}
    };
    mx_cfg_memory memory={regions,3};
    mx_crt_cluster_state s={0};
    s.rip=MAIN;s.rsp=STACK+256U;s.rax=GLOBAL;
    s.cf=1U;s.sf=1U;s.zf=1U;
    mx_game_cwd_context ctx={0};
    int approved=(int)expected_success;
    ctx.validate=allow;ctx.opaque=&approved;
    if(mx_game_setcwd_prepare(&s,MAIN,CALL)!=MX_GAME_CWD_OK||
       s.rip!=CALL||s.rcx!=GLOBAL||s.instructions!=1U||
       s.zf!=1U||s.sf!=1U||s.cf!=1U)return 1;
    if(mx_game_setcwd_import_call(&s,&memory,&ctx,CALL,AFTER,260U)!=
       MX_GAME_CWD_OK)return 2;
    uint64_t return_word=0;
    if(!mx_cfg_transfer(&memory,s.rsp-8U,&return_word,8U,0)||
       return_word!=AFTER||s.rip!=AFTER||s.rsp!=STACK+256U||
       s.rax!=expected_success||s.instructions!=3U||
       s.imports!=1U||ctx.calls!=1U||
       ctx.length!=(expected_success?11U:0U)||
       (expected_success&&ctx.virtual_path[10]!='\\')||
       s.zf!=1U||s.sf!=1U||s.cf!=1U)return 3;
    uint32_t arg=0x1234abcdU;
    if(!mx_cfg_transfer(&memory,ARG,&arg,4U,1))return 4;
    if(mx_game_main_after_cwd_prepare(&s,&memory,
        AFTER,ARG,TEXT,NEXT)!=MX_GAME_CWD_OK||
        s.rip!=NEXT||s.rcx!=0x1234abcdU||s.rdx!=TEXT||
        s.instructions!=5U||s.rax!=expected_success||
        s.zf!=1U||s.cf!=1U||s.sf!=1U)return 5;
    return 0;
}
int smoke(void){
    const uint8_t data[]={'C',':','\\','M','X','B','i','k','e','s','\\',0};
    for(uint32_t i=0;i<sizeof(data);i++)path[i]=data[i];
    if(verify(1U))return 10;
    if(verify(0U))return 11;
    mx_cfg_region regions[]={
        {GLOBAL,path,sizeof(path)},{STACK,stack_bytes,sizeof(stack_bytes)}
    };
    mx_cfg_memory memory={regions,2};
    mx_crt_cluster_state s={0};
    s.rip=CALL;s.rsp=STACK+256U;s.rcx=GLOBAL;s.rax=1234U;
    mx_game_cwd_context ctx={0};
    if(mx_game_setcwd_import_call(&s,&memory,&ctx,CALL,AFTER,260U)!=
       MX_GAME_CWD_UNSUPPORTED||
       s.rax!=1234U||s.rip!=CALL||s.imports)return 12;
    s.rcx=GLOBAL+252U;ctx.validate=allow;
    int approved=1;ctx.opaque=&approved;
    for(uint32_t i=252U;i<260U;i++)path[i]='x';
    if(mx_game_setcwd_import_call(&s,&memory,&ctx,CALL,AFTER,260U)!=
       MX_GAME_CWD_INVALID||s.rip!=CALL)return 13;
    s.rcx=GLOBAL;
    const uint8_t before=path[0];path[0]='Q';
    if(mx_game_setcwd_import_call(&s,&memory,&ctx,CALL,AFTER,260U)!=
       MX_GAME_CWD_UNSUPPORTED||
       path[0]!='Q'||ctx.calls)return 14;
    path[0]=before;
    mx_cfg_memory empty={0};
    if(mx_game_setcwd_import_call(&s,&empty,&ctx,CALL,AFTER,260U)!=
       MX_GAME_CWD_UNMAPPED||s.rip!=CALL)return 15;
    return 0;
}
#ifdef HOST
int main(void){return smoke();}
#endif
"""
class GuestDirectoryTests(unittest.TestCase):
    def test_win64_virtual_directory_adapter_on_host_and_arm64(self):
        if not shutil.which("cc") or not shutil.which("clang"):
            self.skipTest("Compilers unavailable")
        with tempfile.TemporaryDirectory() as td:
            root=Path(td)
            c=root/"test.c"
            c.write_text(SOURCE)
            common=["-std=c11","-O2","-Wall","-Wextra","-Werror","-I"+str(ROOT/"runtime")]
            host=root/"host"
            subprocess.run(["cc",*common,"-DHOST",str(c),"-o",str(host)],check=True)
            subprocess.run([str(host)],check=True)
            elf=root/"aarch64.elf"
            subprocess.run(["clang","--target=aarch64-unknown-linux-gnu",
                "-fuse-ld=lld","-nostdlib","-static","-ffreestanding",
                "-fno-builtin","-fno-stack-protector",*common,
                "-Wl,-e,smoke","-Wl,-z,max-page-size=4096",
                "-Wl,--build-id=none",str(c),"-o",str(elf)],check=True)
            result=execute_arm64_elf(elf,instruction_budget=200000,timeout_us=5000000)
            self.assertEqual(result["arm64_smoke_exit"],0)
if __name__=="__main__":
    unittest.main()
