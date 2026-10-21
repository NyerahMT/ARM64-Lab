"""Native and executed ARM64 checks for CRT table handoff semantics."""
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

ROOT=Path(__file__).resolve().parents[1]
SOURCE=r"""
#include <stdint.h>
#include "mx_crt_startup_bridge.h"
#define EBEGIN UINT64_C(0x1400321a88)
#define IBEGIN UINT64_C(0x1400321a60)
#define STACK UINT64_C(0x70000f000)
#define SP (STACK+0x200U)
#define APP UINT64_C(0x1402ab234)
#define EXCEPT UINT64_C(0x1402ab714)
#define ARG UINT64_C(0x1402aafc4)
#define SECOND UINT64_C(0x140320770)
#define TAIL UINT64_C(0x140320790)
static uint64_t ewords[3]={0U,APP,EXCEPT};
static uint64_t iwords[4]={0U,ARG,SECOND,TAIL};
static uint8_t stack_data[1024];
typedef struct {
  uint32_t fail_e, calls, visited[5];
} test_context;
static int verified_callback(void*opaque,uint64_t address,
                             uint32_t index,uint8_t checked,
                             uint32_t *out){
  test_context *t=(test_context*)opaque;
  uint64_t want=0;
  if(checked)want=index==1U?APP:index==2U?EXCEPT:0U;
  else want=index==1U?ARG:index==2U?SECOND:index==3U?TAIL:0U;
  if(!want||want!=address||!out||t->calls>=5U)return 0;
  t->visited[t->calls++]=(uint32_t)(checked?index:index+2U);
  *out=checked&&index==1U?t->fail_e:0U;
  return 1;
}
int smoke(void){
  mx_cfg_region regions[3]={
    {EBEGIN,(uint8_t*)ewords,sizeof(ewords)},
    {IBEGIN,(uint8_t*)iwords,sizeof(iwords)},
    {STACK,stack_data,sizeof(stack_data)}
  };
  mx_cfg_memory guest={regions,3};
  test_context callback={0};
  mx_crt_startup_bridge bridge={0};
  bridge.memory=&guest;
  bridge.callback=verified_callback;
  bridge.callback_context=&callback;
  bridge.checked_begin=EBEGIN;bridge.checked_end=EBEGIN+24U;
  bridge.plain_begin=IBEGIN;bridge.plain_end=IBEGIN+32U;
  mx_crt_state crt={0};
  crt.rsp=SP;crt.rip=UINT64_C(0x1402ab0b6);crt.rcx=EBEGIN;
  crt.rax=UINT64_C(0xaabbccdd);
  if(mx_crt_invoke_init_thunk(&crt,&guest,MX_CRT_INITTERM_E,
           crt.rip,crt.rip+5U,EBEGIN+24U,
           mx_crt_startup_bridge_call,&bridge)!=MX_CRT_BRANCH_BOUNDARY)
     return 1;
  if(bridge.stage!=1U||bridge.checked_calls!=1U||
     bridge.checked_callbacks!=2U||bridge.plain_callbacks!=0U||
     callback.calls!=2U||callback.visited[0]!=1U||
     callback.visited[1]!=2U||crt.rax!=0U)return 2;
  crt.rip=UINT64_C(0x1402ab0ec);crt.rcx=IBEGIN;
  crt.rax=UINT64_C(0x123456789abcdef0);
  if(mx_crt_invoke_init_thunk(&crt,&guest,MX_CRT_INITTERM,
           crt.rip,crt.rip+5U,IBEGIN+32U,
           mx_crt_startup_bridge_call,&bridge)!=MX_CRT_BRANCH_BOUNDARY)
    return 3;
  if(bridge.stage!=2U||bridge.plain_calls!=1U||
     bridge.plain_callbacks!=3U||callback.calls!=5U||
     callback.visited[2]!=3U||callback.visited[3]!=4U||
     callback.visited[4]!=5U||
     crt.rax!=UINT64_C(0x123456789abcdef0))return 4;
  /* Wrong table, repeated stage and absent callback fail closed. */
  crt.rip=UINT64_C(0x1402ab0b6);crt.rcx=EBEGIN;
  if(mx_crt_invoke_init_thunk(&crt,&guest,MX_CRT_INITTERM_E,
           crt.rip,crt.rip+5U,EBEGIN+24U,
           mx_crt_startup_bridge_call,&bridge)!=MX_CRT_INVALID)
     return 5;
  callback=(test_context){0};bridge.stage=0U;
  callback.fail_e=37U;crt.rip=UINT64_C(0x1402ab0b6);
  if(mx_crt_invoke_init_thunk(&crt,&guest,MX_CRT_INITTERM_E,
           crt.rip,crt.rip+5U,EBEGIN+24U,
           mx_crt_startup_bridge_call,&bridge)!=MX_CRT_BRANCH_BOUNDARY)
    return 6;
  if(crt.rax!=37U||bridge.stage!=3U||callback.calls!=1U||
     bridge.last.failed_function_address!=APP)return 7;
  crt.rip=UINT64_C(0x1402ab0ec);crt.rcx=IBEGIN;
  if(mx_crt_invoke_init_thunk(&crt,&guest,MX_CRT_INITTERM,
           crt.rip,crt.rip+5U,IBEGIN+32U,
           mx_crt_startup_bridge_call,&bridge)!=MX_CRT_INVALID)return 8;
  callback=(test_context){0};bridge.stage=0U;
  ewords[1]=UINT64_C(0xbadbeef);
  crt.rip=UINT64_C(0x1402ab0b6);crt.rcx=EBEGIN;
  if(mx_crt_invoke_init_thunk(&crt,&guest,MX_CRT_INITTERM_E,
           crt.rip,crt.rip+5U,EBEGIN+24U,
           mx_crt_startup_bridge_call,&bridge)!=MX_CRT_INVALID||
     bridge.last.failed_function_address!=UINT64_C(0xbadbeef))
    return 9;
  ewords[1]=APP;
  /* Incorrect Win64 argument range is not accepted. */
  if(mx_crt_startup_bridge_call(&bridge,MX_CRT_INITTERM_E,
           EBEGIN,EBEGIN+32U,&callback.fail_e)!=0)return 10;
  return 0;
}
#ifdef HOST
int main(void){return smoke();}
#endif
"""

class StartupBridgeTests(unittest.TestCase):
    def test_import_to_callback_tables_on_host_and_arm64(self):
        if not shutil.which("cc") or not shutil.which("clang"):
            self.skipTest("host/ARM64 compiler unavailable")
        with tempfile.TemporaryDirectory() as td:
            root=Path(td)
            file=root/"startup_bridge.c"
            file.write_text(SOURCE)
            flags=["-O2","-std=c11","-Wall","-Wextra","-Werror",
                   "-I",str(ROOT/"runtime")]
            exe=root/"host"
            subprocess.run(["cc",*flags,"-DHOST",str(file),"-o",str(exe)],check=True)
            subprocess.run([str(exe)],check=True)
            arm=root/"arm64.elf"
            subprocess.run(["clang","--target=aarch64-unknown-linux-gnu",
                 "-fuse-ld=lld","-nostdlib","-static","-ffreestanding",
                 "-fno-builtin","-fno-stack-protector",
                 *flags,"-Wl,-e,smoke","-Wl,-z,max-page-size=4096",
                 "-Wl,--build-id=none",str(file),"-o",str(arm)],check=True)
            from tools.import_aot_smoke import execute_arm64_elf
            result=execute_arm64_elf(arm,instruction_budget=250000,
                                       timeout_us=4000000)
            self.assertEqual(result["arm64_smoke_exit"],0)

if __name__=="__main__":
    unittest.main()
