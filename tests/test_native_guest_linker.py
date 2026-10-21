"""Host and executed ARM64 tests of the automatic original-VA guest linker."""
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
SOURCE=r"""
#include <stdint.h>
#include "mx_native_guest_linker.h"
#define BASE UINT64_C(0x140000000)
#define MAIN (BASE+UINT64_C(0x136710))
#define CALLEE (BASE+UINT64_C(0x136120))
#define LEAF (BASE+UINT64_C(0x155000))
#define UNKNOWN (BASE+UINT64_C(0x808080))
#define STACK UINT64_C(0x710000000)
#define SP (STACK+0x180U)
#define SENTINEL UINT64_C(0x1400abcde)
#define GLOBAL UINT64_C(0x140300000)
static uint8_t stack_bytes[1024],glob_bytes[8];
static int guest_return(mx_crt_cluster_state*s,mx_cfg_memory*m){
    uint64_t ret=0U;
    if(!mx_cfg_transfer(m,s->rsp,&ret,8U,0))return MX_NATIVE_LINK_STACK;
    s->rip=ret;
    s->rsp+=8U;
    return MX_NATIVE_LINK_OK;
}
static int leaf(mx_crt_cluster_state*s,mx_cfg_memory*m,void*ctx){
    (void)ctx;
    if(s->rip!=LEAF||(s->rsp&15U)!=8U)return MX_NATIVE_LINK_INVALID;
    uint64_t g=0U;
    if(!mx_cfg_transfer(m,GLOBAL,&g,8U,0))return MX_NATIVE_LINK_STACK;
    g+=7U;
    if(!mx_cfg_transfer(m,GLOBAL,&g,8U,1))return MX_NATIVE_LINK_STACK;
    s->rax+=g;
    return guest_return(s,m);
}
static int callee(mx_crt_cluster_state*s,mx_cfg_memory*m,void*ctx){
    mx_native_link_registry*r=(mx_native_link_registry*)ctx;
    if(s->rip!=CALLEE ||(s->rsp&15U)!=8U)return MX_NATIVE_LINK_INVALID;
    /* Win64 function prologue reserves shadow space before nested CALL. */
    uint64_t old_rsp=s->rsp;
    s->rsp-=0x28U;
    s->rip=CALLEE+0x12U;
    /* Resolve by guest virtual address; no direct native function pointers. */
    int result=mx_native_link_call(r,s,m,LEAF,CALLEE+0x17U);
    if(result!=MX_NATIVE_LINK_OK)return result;
    if(s->rsp!=old_rsp-0x28U || s->rip!=CALLEE+0x17U)
        return MX_NATIVE_LINK_BAD_RETURN;
    s->rsp=old_rsp;
    return guest_return(s,m);
}
static int broken(mx_crt_cluster_state*s,mx_cfg_memory*m,void*ctx){
    (void)m;(void)ctx;
    s->rip=BASE+0xaaaaU;
    return MX_NATIVE_LINK_OK;
}
static int force_recursion(mx_crt_cluster_state*s,mx_cfg_memory*m,void*ctx){
    mx_native_link_registry*r=(mx_native_link_registry*)ctx;
    uint64_t oldrsp=s->rsp;
    s->rsp-=0x28U;
    s->rip=BASE+0x201U;
    int out=mx_native_link_call(r,s,m,BASE+0x200U,BASE+0x206U);
    s->rsp=oldrsp;
    return out;
}
int smoke(void){
    mx_cfg_region regions[]={
        {STACK,stack_bytes,sizeof(stack_bytes)},
        {GLOBAL,glob_bytes,sizeof(glob_bytes)}
    };
    mx_cfg_memory mem={regions,2U};
    uint64_t initial=11U;
    if(!mx_cfg_transfer(&mem,GLOBAL,&initial,8U,1))return 1;
    mx_native_link_entry entries[]={
        {BASE+0x200U,force_recursion,0},
        {CALLEE,callee,0},
        {LEAF,leaf,0},
        {BASE+0x900000U,broken,0}
    };
    mx_native_link_registry router={0};
    router.entries=entries;
    router.count=4U;
    router.max_depth=4U;
    if(mx_native_link_validate(&router)!=MX_NATIVE_LINK_OK)return 2;
    entries[0].context=&router;
    entries[1].context=&router;
    if(mx_native_link_seal(&router)!=MX_NATIVE_LINK_OK ||
       !router.table_sealed)return 2;
    mx_crt_cluster_state s={0};
    s.rip=MAIN+0x31U;
    s.rsp=SP;
    s.rax=2U;
    int result=mx_native_link_call(&router,&s,&mem,CALLEE,MAIN+0x36U);
    if(result!=MX_NATIVE_LINK_OK)return 31;
    if(s.rip!=MAIN+0x36U)return 32;
    if(s.rsp!=SP)return 33;
    if(s.rax!=20U)return 34;
    if(router.calls_completed!=2U)return 35;
    if(router.active_depth!=0U)return 36;
    if(router.last_completed_target!=CALLEE)return 37;
    uint64_t global=0U;
    if(!mx_cfg_transfer(&mem,GLOBAL,&global,8U,0)||global!=18U)return 4;
    const uint64_t old_rsp=s.rsp,old_rip=s.rip;
    if(mx_native_link_call(&router,&s,&mem,UNKNOWN,MAIN+0x37U)!=
       MX_NATIVE_LINK_UNRESOLVED ||s.rsp!=old_rsp||s.rip!=old_rip||
       router.last_unresolved_target!=UNKNOWN ||router.unresolved_calls!=1U)
        return 5;
    if(mx_native_link_call(&router,&s,&mem,BASE+0x900000U,MAIN+0x39U)!=
       MX_NATIVE_LINK_BAD_RETURN)return 6;
    /* Fail-closed on duplicate registrations, even if call target exists. */
    mx_native_link_entry duplicate[]={
        {CALLEE,callee,&router},{CALLEE,callee,&router}
    };
    mx_native_link_registry duplicates={0};
    duplicates.entries=duplicate;duplicates.count=2U;duplicates.max_depth=3U;
    if(mx_native_link_validate(&duplicates)!=MX_NATIVE_LINK_BAD_TABLE)
        return 7;
    /* Restore parent state after the intentionally broken callback. */
    s.rsp=SP;s.rip=MAIN+0x40U;s.fault=0;
    router.max_depth=3U;
    if(mx_native_link_call(&router,&s,&mem,BASE+0x200U,MAIN+0x45U)!=
       MX_NATIVE_LINK_RECURSION ||router.active_depth!=0U)
        return 8;
    /* Dynamic guest target resolves to same table, or hard-fails unknown. */
    s.rsp=SP;s.rip=MAIN+0x46U;s.fault=0;s.rax=0U;
    uint64_t target=LEAF;
    if(!mx_cfg_transfer(&mem,GLOBAL,&target,8U,1))return 9;
    if(!mx_cfg_transfer(&mem,GLOBAL,&target,8U,0))return 10;
    if(mx_native_link_call(&router,&s,&mem,target,MAIN+0x4bU)!=
       MX_NATIVE_LINK_OK ||s.rip!=MAIN+0x4bU ||s.rsp!=SP)
        return 11;
    /* Tail-call reuses the caller's return slot; no CALL push. */
    s.rsp=SP-8U;s.rip=MAIN+0x4cU;s.fault=0;
    uint64_t returning=SENTINEL;
    if(!mx_cfg_transfer(&mem,s.rsp,&returning,8U,1))return 12;
    if(mx_native_link_tail_jump(&router,&s,&mem,LEAF)!=MX_NATIVE_LINK_OK ||
       s.rip!=SENTINEL||s.rsp!=SP)return 13;
    return 0;
}
#ifdef HOST
int main(void){return smoke();}
#endif
"""

class NativeGuestLinkerTests(unittest.TestCase):
    def test_multifunction_original_va_dispatch_on_host_and_arm64(self):
        if not shutil.which("cc") or not shutil.which("clang"):
            self.skipTest("Missing host or ARM64 compiler")
        with tempfile.TemporaryDirectory() as td:
            root=Path(td)
            src=root/"linker.c"
            src.write_text(SOURCE)
            flags=["-std=c11","-O2","-Wall","-Wextra","-Werror",
                   "-I",str(ROOT/"runtime")]
            host=root/"host"
            subprocess.run(["cc",*flags,"-DHOST",str(src),"-o",str(host)],
                           capture_output=True,text=True,check=True)
            subprocess.run([str(host)],check=True)
            arm=root/"native-link.elf"
            subprocess.run(["clang","--target=aarch64-unknown-linux-gnu",
                "-fuse-ld=lld","-nostdlib","-static","-ffreestanding",
                "-fno-builtin","-fno-stack-protector",*flags,
                "-Wl,-e,smoke","-Wl,-z,max-page-size=4096",
                "-Wl,--build-id=none",str(src),"-o",str(arm)],
                capture_output=True,text=True,check=True)
            from tools.import_aot_smoke import execute_arm64_elf
            result=execute_arm64_elf(arm,instruction_budget=750000,
                                     timeout_us=7000000)
            self.assertEqual(result["arm64_smoke_exit"],0)

if __name__=="__main__":
    unittest.main()
