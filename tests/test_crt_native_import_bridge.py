"""Stateful Win64 CRT import composition in generated host C and executed ARM64.

Uses entirely synthetic x64 assembly, not proprietary game bytes. The real
private differential suite must separately validate authentic entry paths.
"""
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

from tools.crt_import_cluster_lift import lift_crt_import_cluster
from tools.import_aot_smoke import execute_arm64_elf

ROOT=Path(__file__).resolve().parents[1]
BASE=0x140000000
START=0x1000
ASM=r"""
.intel_syntax noprefix
.section .text
.globl synthetic_entry
synthetic_entry:
  push rbx
  sub rsp,0x30
  lea rcx,QWORD PTR [rip+argc_out]
  lea rdx,QWORD PTR [rip+argv_out]
  lea r8,QWORD PTR [rip+env_out]
  xor r9d,r9d
  lea r11,QWORD PTR [rip+startup_info]
  mov QWORD PTR [rsp+0x20],r11
  call QWORD PTR [rip+arg_slot]
  mov rbx,rax
  mov ecx,2
  call QWORD PTR [rip+app_slot]
  mov ecx,1
  call QWORD PTR [rip+locale_slot]
  mov ecx,8
  call QWORD PTR [rip+lock_slot]
  mov ecx,8
  call QWORD PTR [rip+unlock_slot]
  lea rcx,QWORD PTR [rip+callback_function]
  call QWORD PTR [rip+onexit_slot]
  add rsp,0x30
  pop rbx
  ret
.globl synthetic_end
synthetic_end:
.org 0x400
arg_slot: .quad 0
app_slot: .quad 0
locale_slot: .quad 0
lock_slot: .quad 0
unlock_slot: .quad 0
onexit_slot: .quad 0
.org 0x500
argc_out: .long 0
.align 8
argv_out: .quad 0
env_out: .quad 0
startup_info: .long 0
.align 8
callback_function: .quad 0
.org 0x600
argv_vector: .quad 0
env_vector: .quad 0
"""
SYMBOLS={
    "arg_slot":"__getmainargs",
    "app_slot":"__set_app_type",
    "locale_slot":"_configthreadlocale",
    "lock_slot":"_lock",
    "unlock_slot":"_unlock",
    "onexit_slot":"_onexit",
}

def assemble(work):
    asm=work/"synthetic.S"
    asm.write_text(ASM)
    obj=work/"synthetic.o"
    out=work/"synthetic.bin"
    subprocess.run(["as","--64",str(asm),"-o",str(obj)],check=True)
    subprocess.run(["objcopy","-O","binary","-j",".text",str(obj),str(out)],check=True)
    raw=out.read_bytes()
    names={}
    for line in subprocess.check_output(["nm","-a",str(obj)],text=True).splitlines():
        cells=line.split()
        if len(cells)==3:
            try: names[cells[2]]=int(cells[0],16)
            except ValueError: pass
    assert names["synthetic_entry"]==0
    iat={START+names[key]:("msvcr90.dll",sym) for key,sym in SYMBOLS.items()}
    return raw[:names["synthetic_end"]],iat,names

HARNESS=r"""
#include <stdint.h>
#include "mx_crt_native_import_bridge.h"
#define BASE_G UINT64_C(0x140001000)
#define STACK UINT64_C(0x700000000)
#define SP (STACK+0xf08U)
#define STOP UINT64_C(0x500000100)
#define G(name) (BASE_G+UINT64_C(name))
#define ARGC G(ARGC_LOCATION)
#define ARGV G(ARGV_LOCATION)
#define ENV G(ENV_LOCATION)
#define STARTUP G(STARTUP_LOCATION)
#define CALLBACK G(CALLBACK_LOCATION)
#define ARGVEC G(ARGVEC_LOCATION)
#define ENVVEC G(ENVVEC_LOCATION)
static uint8_t image[2048], stack[4096];
int smoke(void){
    mx_cfg_region regions[2]={
        {BASE_G,image,sizeof(image)},
        {STACK,stack,sizeof(stack)}
    };
    mx_cfg_memory mem={regions,2};
    mx_crt_process process={0};
    mx_crt_services services={0};
    if(mx_crt_services_init(&services,UINT64_C(0x123456789abcdef1))!=1)
        return 1;
    if(mx_crt_process_bind_args(&process,&mem,3U,ARGVEC,ENVVEC)!=1)
        return 2;
    mx_crt_service_adapter native={&services,&mem,111U,0U,0U};
    mx_crt_native_import_bridge bridge={&mem,&process,&native,0U,0};
    uint64_t return_pc=STOP;
    if(!mx_cfg_transfer(&mem,SP,&return_pc,8U,1))return 3;
    mx_crt_cluster_state s={0};
    s.rip=BASE_G;
    s.rsp=SP;
    s.rbx=UINT64_C(0xaabbccddeeff0099);
    s.rax=UINT64_C(0x11112222);
    if(lifted_crt_import_cluster(&s,&mem,mx_crt_native_import_callback,
                                 &bridge)!=MX_CRT_CLUSTER_RETURNED)return 4;
    uint32_t argc=0U;
    uint64_t argv=0U,env=0U;
    if(!mx_cfg_transfer(&mem,ARGC,&argc,4U,0) ||
       !mx_cfg_transfer(&mem,ARGV,&argv,8U,0) ||
       !mx_cfg_transfer(&mem,ENV,&env,8U,0) ||
       argc!=3U||argv!=ARGVEC||env!=ENVVEC)return 5;
    if(bridge.calls_handled!=6U||
       bridge.last_service!=MX_CRT_SERVICE_ONEXIT ||
       !process.app_type_set||process.app_type!=2U||
       process.thread_locale!=1U||services.lock_depth[8]!=0U||
       services.onexit_count!=1U||services.onexit[0]!=CALLBACK ||
       s.rax!=CALLBACK || s.rsp!=SP+8U ||s.rip!=STOP ||
       s.rbx!=UINT64_C(0xaabbccddeeff0099))return 6;
    /* Disallow a nonzero startupinfo.newmode; don't commit argc/argv. */
    uint32_t newmode=1U, zero=0U;
    uint64_t blank=0U;
    if(!mx_cfg_transfer(&mem,STARTUP,&newmode,4U,1)||
       !mx_cfg_transfer(&mem,ARGC,&zero,4U,1)||
       !mx_cfg_transfer(&mem,ARGV,&blank,8U,1)||
       !mx_cfg_transfer(&mem,ENV,&blank,8U,1)||
       !mx_cfg_transfer(&mem,SP,&return_pc,8U,1))return 7;
    bridge.calls_handled=0U;
    mx_crt_cluster_state fail={0};
    fail.rip=BASE_G;fail.rsp=SP;fail.rax=UINT64_C(0xfedcba9876543210);
    if(lifted_crt_import_cluster(&fail,&mem,mx_crt_native_import_callback,
                                 &bridge)!=MX_CRT_CLUSTER_IMPORT_UNSUPPORTED||
       fail.rax!=UINT64_C(0xfedcba9876543210)||
       bridge.calls_handled!=0U)return 8;
    if(!mx_cfg_transfer(&mem,ARGC,&argc,4U,0)||
       !mx_cfg_transfer(&mem,ARGV,&argv,8U,0)||
       !mx_cfg_transfer(&mem,ENV,&env,8U,0)||
       argc!=0U||argv!=0U||env!=0U)return 9;
    /* Missing process context and unknown external services fail closed. */
    if(!mx_cfg_transfer(&mem,STARTUP,&zero,4U,1)||
       !mx_cfg_transfer(&mem,SP,&return_pc,8U,1))return 10;
    bridge.process=0;
    mx_crt_cluster_state absent={0};
    absent.rip=BASE_G;absent.rsp=SP;absent.rax=77U;
    if(lifted_crt_import_cluster(&absent,&mem,mx_crt_native_import_callback,
                                 &bridge)!=MX_CRT_CLUSTER_IMPORT_UNSUPPORTED||
       absent.rax!=77U||bridge.calls_handled!=0U)return 11;
    mx_crt_cluster_state direct={0};
    direct.rip=BASE_G;direct.rsp=SP-8U;direct.rax=123U;
    if(!mx_cfg_transfer(&mem,direct.rsp-8U,&return_pc,8U,1))return 12;
    if(mx_crt_native_import_callback(&bridge,MX_CRT_SERVICE_UNSUPPORTED,
            &direct,&mem,direct.rsp-8U)!=0||direct.rax!=123U||
       bridge.calls_handled!=0U)return 13;
    return 0;
}
#ifdef HOST
int main(void){return smoke();}
#endif
"""

class StatefulNativeImportsTests(unittest.TestCase):
    def test_generated_crt_calls_share_process_on_host_and_arm64(self):
        required=("as","nm","objcopy","cc","clang")
        if any(shutil.which(tool) is None for tool in required):
            self.skipTest("Host assembler and ARM64 cross-compiler unavailable")
        with tempfile.TemporaryDirectory() as td:
            work=Path(td)
            code,iat,names=assemble(work)
            generated,metadata=lift_crt_import_cluster(code,START,iat,{},BASE)
            self.assertEqual(metadata["import_calls"],6)
            self.assertEqual(set(metadata["unique_import_services"]),
                             set(SYMBOLS.values()))
            src=work/"lifted.c"
            src.write_text(generated)
            harness=HARNESS
            for name,macro in (
                ("argc_out","ARGC_LOCATION"),("argv_out","ARGV_LOCATION"),
                ("env_out","ENV_LOCATION"),("startup_info","STARTUP_LOCATION"),
                ("callback_function","CALLBACK_LOCATION"),
                ("argv_vector","ARGVEC_LOCATION"),("env_vector","ENVVEC_LOCATION")):
                harness=harness.replace(macro,str(names[name]))
            driver=work/"driver.c"
            driver.write_text(harness)
            flags=["-std=c11","-O2","-Wall","-Wextra","-Werror",
                   "-I"+str(ROOT/"runtime")]
            native=work/"native"
            subprocess.run(["cc",*flags,"-DHOST",str(src),str(driver),
                            "-o",str(native)],check=True)
            subprocess.run([str(native)],check=True)
            arm=work/"arm64.elf"
            subprocess.run([
                "clang","--target=aarch64-unknown-linux-gnu",
                "-fuse-ld=lld","-nostdlib","-static","-ffreestanding",
                "-fno-stack-protector","-fno-builtin",*flags,
                "-Wl,-e,smoke","-Wl,-z,max-page-size=4096",
                "-Wl,--build-id=none",str(src),str(driver),"-o",str(arm)
            ],check=True)
            result=execute_arm64_elf(arm,instruction_budget=800000,
                                     timeout_us=6000000)
            self.assertEqual(result["arm64_smoke_exit"],0)

if __name__=="__main__":
    unittest.main()
