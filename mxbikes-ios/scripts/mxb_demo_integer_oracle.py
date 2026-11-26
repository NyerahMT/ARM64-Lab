"""Real native x64 CPU oracle for new scalar instruction semantics."""
import subprocess,sys,tempfile
from pathlib import Path
from mxb_demo_block_batch import PREAMBLE,generate

HARNESS=r'''
#include <stdio.h>
static uint64_t rng=0x87654321abcdef00ull;
static uint64_t next(void){rng^=rng<<13;rng^=rng>>7;rng^=rng<<17;return rng;}
int main(void){
 unsigned count=0;
 for(unsigned k=0;k<2048;++k){
  uint64_t a=next(),b=next(),flags,actual;
  unsigned n=k&63;
  mxb_cfg s={0};s.known=STATUS;
  actual=a;
  if(k&64){__asm__ volatile("rorq %%cl,%0;pushfq;popq %1":"+r"(actual),"=r"(flags):"c"((uint64_t)n):"cc");}
  else{__asm__ volatile("rolq %%cl,%0;pushfq;popq %1":"+r"(actual),"=r"(flags):"c"((uint64_t)n):"cc");}
  uint64_t v=mx_rotate(&s,64,!!(k&64),a,n);
  if(v!=actual||(n&&((s.flags^flags)&(CF|(n==1?OF:0))))||(!n&&s.known!=STATUS))return 1;
  ++count;
  s=(mxb_cfg){0};s.r[0]=a;
  uint32_t lo=(uint32_t)a,hi;
  __asm__ volatile("mull %3;pushfq;popq %2":"+a"(lo),"=d"(hi),"=r"(flags):"r"((uint32_t)b):"cc");
  mx_mul(&s,32,b);
  if(s.r[0]!=lo||s.r[2]!=hi||((s.flags^flags)&(CF|OF)))return 2;
  ++count;
  s=(mxb_cfg){0};s.r[0]=a;
  uint64_t l=a,h;
  __asm__ volatile("mulq %3;pushfq;popq %2":"+a"(l),"=d"(h),"=r"(flags):"r"(b):"cc");
  mx_mul(&s,64,b);
  if(s.r[0]!=l||s.r[2]!=h||((s.flags^flags)&(CF|OF)))return 3;
  ++count;
  int32_t divisor=(int32_t)(b%65535)-32767;if(!divisor)divisor=1;
  int64_t dividend=(int32_t)a;
  if(dividend==INT32_MIN&&divisor==-1)divisor=1;
  lo=(uint32_t)dividend;hi=(uint32_t)((uint64_t)dividend>>32);
  s=(mxb_cfg){0};s.r[0]=lo;s.r[2]=hi;
  __asm__ volatile("idivl %2":"+a"(lo),"+d"(hi):"r"(divisor):"cc");
  if(!mx_div(&s,32,1,(uint32_t)divisor)||s.r[0]!=lo||s.r[2]!=hi||s.known)return 4;
  ++count;
  uint64_t divisor64=(b|1),low=next(),high=next()%divisor64;
  s=(mxb_cfg){0};s.r[0]=low;s.r[2]=high;
  __asm__ volatile("divq %2":"+a"(low),"+d"(high):"r"(divisor64):"cc");
  if(!mx_div(&s,64,0,divisor64)||s.r[0]!=low||s.r[2]!=high)return 5;
  ++count;
  int64_t d64=(int64_t)(b%65535)-32767;if(!d64)d64=1;
  int64_t av=(int64_t)a;if(av==INT64_MIN&&d64==-1)d64=1;
  low=(uint64_t)av;high=av<0?UINT64_MAX:0;
  s=(mxb_cfg){0};s.r[0]=low;s.r[2]=high;
  __asm__ volatile("idivq %2":"+a"(low),"+d"(high):"r"(d64):"cc");
  if(!mx_div(&s,64,1,(uint64_t)d64)||s.r[0]!=low||s.r[2]!=high)return 6;
  ++count;
 }
 mxb_cfg s={0};s.r[0]=0x80000000;s.r[2]=0xffffffff;s.flags=0x123;s.known=STATUS;
 if(mx_div(&s,32,1,0xffffffff)||mx_div(&s,32,1,0)||s.r[0]!=0x80000000||s.r[2]!=0xffffffff||s.flags!=0x123)return 7;
 s.r[2]=1;s.r[0]=1;if(mx_div(&s,64,0,1))return 8;
 printf("INTEGER_CPU_COMPARISONS %u; fault checks 3\n",count);return 0;
}
'''
def run(root):
    root=Path(root);source=root/"integer-oracle.c";exe=root/"integer-oracle.exe"
    source.write_text(PREAMBLE+HARNESS)
    subprocess.run([sys.executable,"-m","ziglang","cc","-target","x86_64-windows-gnu","-O2",str(source),"-o",str(exe)],check=True,timeout=120)
    subprocess.run([str(exe)],check=True,timeout=30)
    rows={0:(b"\x48\xc1\xc1\x10","rol","rcx, 0x10"),4:(b"\x41\xf7\xe0","mul","r8d"),7:(b"\xf7\xf9","idiv","ecx"),9:(b"\xc3","ret","")}
    src,accepted,reject=generate(rows,set(rows))
    if len(accepted)!=4 or reject:raise RuntimeError("scalar generator fixture")
    source=root/"integer-arm.c";source.write_text(src)
    obj=root/"integer-arm.o"
    subprocess.run([sys.executable,"-m","ziglang","cc","-target","aarch64-linux-musl","-O2","-ffreestanding","-fno-builtin","-c",str(source),"-o",str(obj)],check=True,timeout=120)
    print("INTEGER_ARM64_OBJECT "+str(obj.stat().st_size),flush=True)
if __name__=="__main__":
    with tempfile.TemporaryDirectory(prefix="mxb-integer-oracle-") as p:run(p)
