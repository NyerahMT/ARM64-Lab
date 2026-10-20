"""Synthetic Windows exception-filter callback shape: native and AArch64 compile.

Real original-game decoding, x64 execution and differential fixtures belong
in the private repo and are intentionally not embedded in public test data.
"""
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

ROOT=Path(__file__).resolve().parents[1]
SRC=r"""
#include <stdint.h>
#include <string.h>
#include "mx_crt_exception_callback.h"
#define BASE UINT64_C(0x700001000)
#define PC UINT64_C(0x140002000)
#define FILTER UINT64_C(0x140003000)
static uint8_t stack[256];
static unsigned calls;
static int hook(void *ctx,uint64_t addr,uint64_t *prev) {
  unsigned *n=(unsigned*)ctx; (*n)++; calls++;
  if(addr!=FILTER)return 0;
  *prev=UINT64_C(0xAABBCCDD);
  return 1;
}
static int smoke(void) {
  mx_cfg_region region={BASE,stack,sizeof(stack)};
  mx_cfg_memory memory={&region,1};
  const uint64_t sp=BASE+0x88U;
  const uint64_t ret=UINT64_C(0x500000100);
  for(unsigned i=0;i<4;i++) {
    for(unsigned j=0;j<sizeof(stack);j++){stack[j]=0;}\n    calls=0;
    mx_crt_state s={0};
    s.rip=PC;s.rsp=sp;s.rax=0xcccc;s.rcx=0xdddd;s.zf=1;
    if(!mx_cfg_transfer(&memory,sp,(void*)&ret,8,1))return 1;
    unsigned invoked=0;
    int result=mx_crt_exception_callback6(&s,&memory,PC,FILTER,hook,&invoked);
    if(result!=MX_CRT_RETURNED||s.rip!=ret||s.rsp!=sp+8 ||
       s.rax!=0||s.rcx!=FILTER||s.zf!=0||s.imports!=1||
       s.instructions!=6||s.visited!=63||invoked!=1||calls!=1)return 2;
    uint64_t nested=0;
    if(!mx_cfg_transfer(&memory,sp-0x30,&nested,8,0)||nested!=PC+17)return 3;
  }
  /* Invalid alignments and missing guest memory cannot invoke host APIs. */
  mx_crt_state s={0}; s.rip=PC;s.rsp=sp-1;
  unsigned invoked=0;
  if(mx_crt_exception_callback6(&s,&memory,PC,FILTER,hook,&invoked)
       !=MX_CRT_INVALID||invoked)return 4;
  s.rsp=BASE+0x1008;
  if(mx_crt_exception_callback6(&s,&memory,PC,FILTER,hook,&invoked)
       !=MX_CRT_MEMORY_FAULT||invoked)return 5;
  s.rsp=sp;s.rip=PC+1;
  if(mx_crt_exception_callback6(&s,&memory,PC,FILTER,hook,&invoked)
       !=MX_CRT_INVALID||invoked)return 6;
  return 0;
}
#ifdef HOST
int main(void){return smoke();}
#else
int smoke_arm64(void){return smoke();}
#endif
"""

class TestCRTExceptionCallback(unittest.TestCase):
    def test_native_and_arm64_object(self):
        cc=shutil.which("cc")
        clang=shutil.which("clang")
        if not cc or not clang:
            self.skipTest("C toolchains unavailable")
        with tempfile.TemporaryDirectory() as temp:
            p=Path(temp)
            source=p/"smoke.c";source.write_text(SRC)
            common=["-std=c11","-O2","-Wall","-Wextra","-Werror",
                    "-I",str(ROOT/"runtime")]
            subprocess.run([cc,*common,"-DHOST",str(source),"-o",str(p/"smoke")],check=True)
            subprocess.run([str(p/"smoke")],check=True)
            subprocess.run([clang,"--target=aarch64-unknown-linux-gnu",
                            "-ffreestanding","-fno-builtin","-fno-stack-protector",
                            *common,"-c",str(source),"-o",str(p/"smoke.o")],check=True)
            self.assertTrue((p/"smoke.o").stat().st_size>0)

if __name__=="__main__":
    unittest.main()
