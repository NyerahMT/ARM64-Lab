"""Synthetic eight-instruction CRT shared-helper tests (no game bytes)."""
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

ROOT=Path(__file__).resolve().parents[1]
SRC=r"""
#include <stdint.h>
#include "mx_crt_shared_helper.h"
#define BASE UINT64_C(0x700001000)
#define PC UINT64_C(0x140002000)
static uint8_t guest[256];
static int cb(void *p,uint64_t arg,uint64_t *value) {
  uint64_t *f=(uint64_t*)p;
  if(arg!=f[0])return 0;
  *value=f[1];return 1;
}
int smoke(void){
  mx_cfg_region range={BASE,guest,sizeof(guest)};
  mx_cfg_memory m={&range,1};
  for(unsigned j=0;j<16;j++){
    for(unsigned x=0;x<sizeof(guest);x++){guest[x]=0;}
    const uint64_t sp=BASE+0x88U,ret=UINT64_C(0x500000100);
    if(!mx_cfg_transfer(&m,sp,(void*)&ret,8,1))return 1;
    mx_crt_state s={0};s.rip=PC;s.rsp=sp;
    s.rcx=UINT64_C(0x1400000a0)+j;
    s.rax=UINT64_C(0xffffeeee00000000)+j;s.zf=j&1;
    uint64_t values[2]={s.rcx,j%2 ? 0 : (UINT64_C(0x77770000)+j)};
    if(mx_crt_shared_helper8(&s,&m,PC,cb,values)!=MX_CRT_RETURNED)
       return 10+j;
    if(s.rax!=(j%2 ? UINT64_C(0xffffffff):0)||
       s.rsp!=sp+8||s.rip!=ret||s.zf!=0||
       s.instructions!=8||s.visited!=255||s.imports!=0)
       return 30+j;
    uint64_t slot=0;
    if(!mx_cfg_transfer(&m,sp-0x30,&slot,8,0)||slot!=PC+9)
       return 50+j;
  }
  mx_crt_state s={0};s.rip=PC;s.rsp=BASE+0x88U;
  uint64_t values[2]={0,0};
  if(mx_crt_shared_helper8(&s,&m,PC,0,values)!=MX_CRT_INVALID)
    return 70;
  s.rsp=BASE+0x1088U;
  if(mx_crt_shared_helper8(&s,&m,PC,cb,values)!=MX_CRT_MEMORY_FAULT)
    return 71;
  return 0;
}
#ifdef HOST
int main(void){return smoke();}
#endif
"""
class SharedHelperSmoke(unittest.TestCase):
    def test_host_and_arm64_cross_compile(self):
        cc=shutil.which("cc")
        clang=shutil.which("clang")
        if not cc or not clang:self.skipTest("C compilers unavailable")
        with tempfile.TemporaryDirectory() as t:
            p=Path(t)
            src=p/"smoke.c";src.write_text(SRC)
            flags=["-std=c11","-O2","-Wall","-Wextra","-Werror","-I",str(ROOT/"runtime")]
            subprocess.run([cc,*flags,"-DHOST",str(src),"-o",str(p/"smoke")],check=True)
            subprocess.run([str(p/"smoke")],check=True)
            subprocess.run([clang,"--target=aarch64-unknown-linux-gnu",
                            "-ffreestanding","-fno-builtin","-fno-stack-protector",
                            *flags,"-c",str(src),"-o",str(p/"smoke.o")],check=True)
            self.assertGreater((p/"smoke.o").stat().st_size,0)

if __name__=="__main__":
    unittest.main()
