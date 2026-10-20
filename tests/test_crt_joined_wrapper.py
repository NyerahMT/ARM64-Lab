"""Executed host and AArch64 tests for nested Win64 wrapper/callee ABI.

Purely synthetic child: independently validates the stack bridge and that
volatile register, guest global and nested-return-slot effects survive.
Actual original child is tested separately in PRIVATE x64/AArch64 CI.
"""
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

ROOT=Path(__file__).resolve().parents[1]
SOURCE=r"""
#include <stdint.h>
#include "mx_crt_joined_wrapper.h"
#define WIN UINT64_C(0x7000fa00)
#define SP UINT64_C(0x7000fb08)
#define WRAPPER UINT64_C(0x140002000)
#define CHILD UINT64_C(0x140003000)
#define EXIT UINT64_C(0x500000100)
#define GLOBAL UINT64_C(0x140020000)
static uint8_t stack_data[512];
static uint8_t globals[16];
static unsigned called, imported;

static int fake_import(void *ctx,mx_crt_service_id id,
                       mx_crt_cluster_state *s,
                       mx_cfg_memory *m,uint64_t callee_sp) {
    (void)ctx;(void)m;
    if(id!=MX_CRT_SERVICE_LOCK ||
       callee_sp!=SP-0x60U || s->rcx!=8U)return 0;
    imported++;
    return 1;
}
static int real_guest_side_effects(
        mx_crt_cluster_state *s,mx_cfg_memory*m,
        mx_crt_cluster_import_fn callback,void*ctx) {
    called++;
    if(s->rip!=CHILD || s->rsp!=SP-0x30U ||
       s->rcx!=UINT64_C(0x12345678))return MX_CRT_CLUSTER_INVALID;
    const uint64_t ret=mx_crt_cluster_read(s,m,s->rsp,8);
    if(s->fault || ret!=WRAPPER+9U)return MX_CRT_CLUSTER_MEMORY_FAULT;
    s->rcx=8U;
    s->rsp-=0x30U;
    if(!callback(ctx,MX_CRT_SERVICE_LOCK,s,m,s->rsp))
        return MX_CRT_CLUSTER_IMPORT_UNSUPPORTED;
    s->rsp+=0x30U;
    s->r8=UINT64_C(0x7766554433221100);
    s->rdx=UINT64_C(0x1122334455667788);
    s->rcx=UINT64_C(0xabcd);
    const uint64_t global_value=UINT64_C(0xfeedcafebeef1256);
    if(!mx_crt_cluster_write(s,m,GLOBAL,8,global_value))
        return MX_CRT_CLUSTER_MEMORY_FAULT;
    const uint64_t shadow=UINT64_C(0x1020304050607080);
    if(!mx_crt_cluster_write(s,m,s->rsp-0x28U,8,shadow))
        return MX_CRT_CLUSTER_MEMORY_FAULT;
    s->rax=(ctx!=0)?1U:0U;
    s->rip=ret;s->rsp+=8U;
    return MX_CRT_CLUSTER_RETURNED;
}
static int fail_child(mx_crt_cluster_state *s,mx_cfg_memory*m,
                      mx_crt_cluster_import_fn callback,void*ctx){
    (void)s;(void)m;(void)callback;(void)ctx;
    called++;
    return MX_CRT_CLUSTER_IMPORT_UNSUPPORTED;
}
static int copy64(mx_cfg_memory*m,uint64_t addr,uint64_t v){
    return mx_cfg_transfer(m,addr,&v,8,1);
}
int smoke(void) {
    mx_cfg_region ranges[2]={{WIN,stack_data,512},{GLOBAL,globals,16}};
    mx_cfg_memory mem={ranges,2};
    for(unsigned i=0;i<2;i++){
        for(unsigned j=0;j<512;j++)stack_data[j]=0;
        for(unsigned j=0;j<16;j++)globals[j]=0;
        mx_crt_cluster_state s={0};
        s.rip=WRAPPER;s.rsp=SP;s.rcx=UINT64_C(0x12345678);
        s.r8=UINT64_C(0x55);s.rdx=UINT64_C(0x66);
        s.rdi=UINT64_C(0x7788);s.rbx=UINT64_C(0x9922);
        s.zf=1;
        if(!copy64(&mem,SP,EXIT))return 1;
        called=0;imported=0;
        void*arg=i ? 0 : (void*)&s;
        int result=mx_crt_joined_wrapper8(&s,&mem,WRAPPER,CHILD,
                      real_guest_side_effects,fake_import,arg);
        if(result!=MX_CRT_CLUSTER_RETURNED || called!=1 || imported!=1)
            return 10+i;
        uint64_t saved=0, global_value=0,shadow=0;
        if(!mx_cfg_transfer(&mem,SP-0x30U,&saved,8,0) ||
           !mx_cfg_transfer(&mem,GLOBAL,&global_value,8,0) ||
           !mx_cfg_transfer(&mem,SP-0x58U,&shadow,8,0))
            return 20+i;
        if(saved!=WRAPPER+9U ||
           global_value!=UINT64_C(0xfeedcafebeef1256) ||
           shadow!=UINT64_C(0x1020304050607080))
            return 30+i;
        if(s.rax!=(i?UINT64_C(0xffffffff):0U) ||
           s.rip!=EXIT || s.rsp!=SP+8U || s.zf!=0 ||
           s.rcx!=UINT64_C(0xabcd) ||
           s.rdx!=UINT64_C(0x1122334455667788) ||
           s.r8!=UINT64_C(0x7766554433221100) ||
           s.rbx!=UINT64_C(0x9922) ||
           s.rdi!=UINT64_C(0x7788) ||
           s.instructions!=8U)
            return 40+i;
    }
    mx_crt_cluster_state s={0};
    s.rip=WRAPPER;s.rsp=SP;s.rcx=UINT64_C(0x12345678);
    if(!copy64(&mem,SP,EXIT))return 51;
    called=0;
    if(mx_crt_joined_wrapper8(&s,&mem,WRAPPER,CHILD,
            fail_child,fake_import,0)!=MX_CRT_CLUSTER_IMPORT_UNSUPPORTED ||
       called!=1)
        return 52;
    if(mx_crt_joined_wrapper8(&s,&mem,WRAPPER,CHILD,
            real_guest_side_effects,0,0)!=MX_CRT_CLUSTER_INVALID)
        return 53;
    s.rsp=0;
    if(mx_crt_joined_wrapper8(&s,&mem,WRAPPER,CHILD,
            real_guest_side_effects,fake_import,0)!=MX_CRT_CLUSTER_INVALID)
        return 54;
    return 0;
}
#ifdef HOST
int main(void){return smoke();}
#endif
"""

class JoinedWrapperTests(unittest.TestCase):
    def test_synthetic_native_host_and_executed_aarch64(self):
        if not shutil.which("cc") or not shutil.which("clang"):
            self.skipTest("host C and AArch64 compilers unavailable")
        with tempfile.TemporaryDirectory() as td:
            work=Path(td)
            source=work/"joined.c"
            source.write_text(SOURCE)
            flags=["-O2","-std=c11","-Wall","-Wextra","-Werror",
                   "-I"+str(ROOT/"runtime")]
            host=work/"host"
            subprocess.run(["cc",*flags,"-DHOST",str(source),
                            "-o",str(host)],check=True)
            subprocess.run([str(host)],check=True)
            elf=work/"joined-arm64.elf"
            subprocess.run([
                "clang","--target=aarch64-unknown-linux-gnu",
                "-fuse-ld=lld","-nostdlib","-static","-ffreestanding",
                "-fno-stack-protector","-fno-builtin",*flags,
                "-Wl,-e,smoke","-Wl,-z,max-page-size=4096",
                "-Wl,--build-id=none",str(source),"-o",str(elf)
            ],check=True)
            from tools.import_aot_smoke import execute_arm64_elf
            report=execute_arm64_elf(elf,instruction_budget=220000,
                                     timeout_us=4000000)
            self.assertEqual(report["arm64_smoke_exit"],0)

if __name__=="__main__":
    unittest.main()
