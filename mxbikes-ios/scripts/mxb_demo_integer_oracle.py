"""Real native x64 CPU oracle for new scalar instruction semantics."""
import subprocess,sys,tempfile
from pathlib import Path
from mxb_demo_block_batch import PREAMBLE,generate

HARNESS=r'''
#include <stdio.h>
static uint64_t rng=0x87654321abcdef00ull;
static uint64_t next(void){rng^=rng<<13;rng^=rng>>7;rng^=rng<<17;return rng;}
static uint64_t cell;
static int allow_write;
static int test_rd(void*c,uint64_t p,unsigned n,uint64_t*out){if(p!=64||n!=8)return 0;*out=cell;return 1;}
static int test_wr(void*c,uint64_t p,unsigned n,uint64_t v){if(p!=64||n!=8||!allow_write)return 0;cell=v;return 1;}
static uint8_t cmps_left[32],cmps_right[32];
static int cmps_rd(void*c,uint64_t p,unsigned n,uint64_t*out){
 if(n!=1)return 0;
 if(p>=64&&p<96)*out=cmps_left[p-64];
 else if(p>=128&&p<160)*out=cmps_right[p-128];
 else return 0;
 return 1;
}
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
 mxb_cfg a={0};a.read=test_rd;a.write=test_wr;a.exclusive_guest=1;a.r[0]=9;cell=9;allow_write=1;
 if(mx_crt_cmpxchg64(&a,64,17)!=1||cell!=17||a.r[0]!=9||!(a.flags&ZF))return 9;
 if(mx_crt_cmpxchg64(&a,64,21)!=1||cell!=17||a.r[0]!=17||(a.flags&ZF))return 10;
 a.r[0]=4;allow_write=0;uint64_t f=a.flags;
 if(mx_crt_cmpxchg64(&a,64,21)!=-2||a.r[0]!=4||a.flags!=f||cell!=17)return 11;
 allow_write=1;a.exclusive_guest=0;
 if(mx_crt_xchg64(&a,64,0)!=-8||cell!=17||a.r[0]!=4)return 12;
 a.exclusive_guest=1;if(mx_crt_xchg64(&a,64,0)!=1||cell!=4||a.r[0]!=17||a.flags!=f)return 13;
 unsigned compares=0;
 for(unsigned k=0;k<2048;++k){
  for(unsigned i=0;i<32;++i){cmps_left[i]=(uint8_t)next();cmps_right[i]=cmps_left[i];}
  if(k&8)cmps_right[(unsigned)(next()%32)]^=1;
  unsigned reverse=k&1,equal=(k>>1)&1;
  uint64_t n=k%33,rc=n,f=0;
  unsigned index=reverse?31:0;
  const uint8_t *l=cmps_left+index,*r=cmps_right+index;
  if(reverse){
   if(equal){__asm__ volatile("std; repe cmpsb; pushfq; popq %3; cld":"+S"(l),"+D"(r),"+c"(rc),"=r"(f)::"cc","memory");}
   else{__asm__ volatile("std; repne cmpsb; pushfq; popq %3; cld":"+S"(l),"+D"(r),"+c"(rc),"=r"(f)::"cc","memory");}
  }else{
   if(equal){__asm__ volatile("cld; repe cmpsb; pushfq; popq %3":"+S"(l),"+D"(r),"+c"(rc),"=r"(f)::"cc","memory");}
   else{__asm__ volatile("cld; repne cmpsb; pushfq; popq %3":"+S"(l),"+D"(r),"+c"(rc),"=r"(f)::"cc","memory");}
  }
  mxb_cfg z={0};z.read=cmps_rd;z.r[1]=n;z.r[6]=64+index;z.r[7]=128+index;z.flags=reverse?MXB_DF:0;z.known=STATUS;
  if(mxb_compare_byte(&z,equal)!=1||z.r[1]!=rc||z.r[6]!=64+(uint64_t)((uintptr_t)l-(uintptr_t)cmps_left)||z.r[7]!=128+(uint64_t)((uintptr_t)r-(uintptr_t)cmps_right)||(n&&((z.flags^f)&STATUS))||(!n&&z.known!=STATUS))return 14;
  ++compares;
 }
 mxb_cfg z={0};z.read=cmps_rd;z.r[1]=2;z.r[6]=95;z.r[7]=159;cmps_left[31]=cmps_right[31]=0;
 if(mxb_compare_byte(&z,1)!=-2||z.r[1]!=1||z.r[6]!=96||z.r[7]!=160||!(z.flags&ZF))return 15;
 unsigned bitcases=0;
 for(unsigned k=0;k<2048;k++){
  uint64_t a=k%17?next():0,actual=123,flags;
  mxb_cfg x={0};x.r[3]=123;x.known=STATUS;
  __asm__ volatile("bsfq %2,%0;pushfq;popq %1":"+r"(actual),"=r"(flags):"r"(a):"cc");
  mx_bitscan(&x,3,64,0,a);
  if((a&&x.r[3]!=actual)||((x.flags^flags)&ZF)||x.known!=ZF)return 16;
  ++bitcases;
  actual=123;x=(mxb_cfg){0};x.r[3]=123;
  __asm__ volatile("bsrq %2,%0;pushfq;popq %1":"+r"(actual),"=r"(flags):"r"(a):"cc");
  mx_bitscan(&x,3,64,1,a);
  if((a&&x.r[3]!=actual)||((x.flags^flags)&ZF)||x.known!=ZF)return 17;
  ++bitcases;
  x=(mxb_cfg){0};
  __asm__ volatile("popcntq %2,%0;pushfq;popq %1":"=r"(actual),"=r"(flags):"r"(a):"cc");
  mx_bitscan(&x,3,64,2,a);
  if(x.r[3]!=actual||((x.flags^flags)&STATUS)||x.known!=STATUS)return 18;
  ++bitcases;
  for(unsigned op=0;op<4;op++){
   uint64_t b=next();actual=a;x=(mxb_cfg){0};x.r[3]=a;x.flags=ZF;x.known=STATUS;
   if(op==0){__asm__ volatile("btq %2,%0;pushfq;popq %1":"+r"(actual),"=r"(flags):"r"(b):"cc");}
   else if(op==1){__asm__ volatile("btsq %2,%0;pushfq;popq %1":"+r"(actual),"=r"(flags):"r"(b):"cc");}
   else if(op==2){__asm__ volatile("btrq %2,%0;pushfq;popq %1":"+r"(actual),"=r"(flags):"r"(b):"cc");}
   else{__asm__ volatile("btcq %2,%0;pushfq;popq %1":"+r"(actual),"=r"(flags):"r"(b):"cc");}
   mx_bitreg(&x,3,64,op,b);
   if(x.r[3]!=actual||((x.flags^flags)&CF)||!(x.flags&ZF)||x.known!=(CF|ZF))return 19;
   ++bitcases;
  }
 }
 unsigned families=0;
 for(unsigned k=0;k<2048;k++){
  uint64_t a=next(),b=next(),lo=a,hi,flags;
  mxb_cfg x={0};x.r[0]=a;
  __asm__ volatile("imulq %3;pushfq;popq %2":"+a"(lo),"=d"(hi),"=r"(flags):"r"(b):"cc");
  mx_mul_form(&x,64,b,1);
  if(x.r[0]!=lo||x.r[2]!=hi||((x.flags^flags)&(CF|OF)))return 20;
  ++families;
  uint32_t l=(uint32_t)a,h;
  x=(mxb_cfg){0};x.r[0]=a;x.r[2]=b;
  __asm__ volatile("imull %3;pushfq;popq %2":"+a"(l),"=d"(h),"=r"(flags):"r"((uint32_t)b):"cc");
  mx_mul_form(&x,32,b,1);
  if(x.r[0]!=l||x.r[2]!=h||((x.flags^flags)&(CF|OF)))return 21;
  ++families;
  uint64_t f0,f1,out0,out1;uint32_t csr=0x1f80;
  __asm__ volatile("movq %2,%%xmm0;cvtdq2pd %%xmm0,%%xmm0;movq %%xmm0,%0;psrldq $8,%%xmm0;movq %%xmm0,%1":"=&r"(f0),"=&r"(f1):"r"(a):"xmm0");
  if(!fp_fromint(&csr,32,64,a&UINT32_MAX,&out0)||!fp_fromint(&csr,32,64,a>>32,&out1)||out0!=f0||out1!=f1||csr!=0x1f80)return 22;
  ++families;
 }
 /* Guest memory bit-index addressing, including a negative register index. */
 mxb_cfg m={0};m.read=test_rd;m.write=test_wr;cell=UINT64_C(1)<<63;
 if(mx_bitmem(&m,72,64,0,UINT64_MAX,1)!=1||!(m.flags&CF))return 23;
 allow_write=1;
 if(mx_bitmem(&m,64,64,2,63,0)!=1||cell||!(m.flags&CF))return 24;
 allow_write=0;uint64_t before=m.flags;
 if(mx_bitmem(&m,64,64,1,1,0)!=-2||cell||m.flags!=before)return 25;
 printf("EXPANDED_SCALAR_SSE_CPU_COMPARISONS %u; memory bit checks 3\\n",families);
 printf("BIT_FAMILY_CPU_COMPARISONS %u\\n",bitcases);
 printf("INTEGER_CPU_COMPARISONS %u; fault checks 3; atomic contract checks 5; CMPS CPU comparisons %u; CMPS fault checks 1\n",count,compares);return 0;
}
'''
def run(root):
    root=Path(root);source=root/"integer-oracle.c";exe=root/"integer-oracle.exe"
    source.write_text(PREAMBLE+HARNESS)
    subprocess.run([sys.executable,"-m","ziglang","cc","-target","x86_64-windows-gnu","-O2",str(source),"-o",str(exe)],check=True,timeout=120)
    subprocess.run([str(exe)],check=True,timeout=30)
    rows={0:(b"\x48\xc1\xc1\x10","rol","rcx, 0x10"),4:(b"\x41\xf7\xe0","mul","r8d"),7:(b"\xf7\xf9","idiv","ecx"),9:(b"\xc3","ret","")}
    rows.update({10:(b"\x65\x48\x8b\x04\x25\x30\x00\x00\x00","mov","rax, qword ptr gs:[0x30]"),
                 19:(b"\xf0\x48\x0f\xb1\x3d\x24\x00\x00\x00","lock cmpxchg","qword ptr [rip + 0x24], rdi"),
                 28:(b"\x48\x87\x05\x80\x00\x00\x00","xchg","qword ptr [rip + 0x80], rax")})
    rows.update({35:(b"\xf3\xa6","repe cmpsb","byte ptr [rsi], byte ptr [rdi]"),
                 37:(b"\x65\x4c\x8b\x1c\x25\x10\x00\x00\x00","mov","r11, qword ptr gs:[0x10]")})
    rows.update({64:(bytes.fromhex("480fbc c1"),"bsf","rax, rcx"),
                 68:(bytes.fromhex("660fbd c1"),"bsr","ax, cx"),
                 72:(bytes.fromhex("f30fb8c1"),"popcnt","eax, ecx"),
                 76:(bytes.fromhex("480fa3c8"),"bt","rax, rcx"),
                 80:(bytes.fromhex("480fbae807"),"bts","rax, 7"),
                 85:(bytes.fromhex("0fb3c8"),"btr","eax, ecx"),
                 88:(bytes.fromhex("660fbb c8"),"btc","ax, cx"),
                 92:(bytes.fromhex("480fbc01"),"bsf","rax, qword ptr [rcx]")})
    rows.update({96:(bytes.fromhex("48f7e9"),"imul","rcx"),
                 100:(bytes.fromhex("480fa308"),"bt","qword ptr [rax], rcx"),
                 104:(bytes.fromhex("f30fe6c1"),"cvtdq2pd","xmm0, xmm1"),
                 108:(bytes.fromhex("f3ab"),"rep stosd","dword ptr [rdi], eax"),
                 112:(bytes.fromhex("f348a5"),"rep movsq","qword ptr [rdi], qword ptr [rsi]"),
                 116:(bytes.fromhex("c21000"),"ret","0x10")})
    rows[120]=(bytes.fromhex("660f2f01"),"comisd","xmm0, xmmword ptr [rcx]")
    rows.update({128:(bytes.fromhex("b5c0"),"mov","ch, 0xc0"),
                 132:(bytes.fromhex("00 30"),"add","byte ptr [rax], dh"),
                 136:(bytes.fromhex("00 dd"),"add","ch, bl"),
                 140:(bytes.fromhex("f00fb108"),"lock cmpxchg","dword ptr [rax], ecx"),
                 144:(bytes.fromhex("8718"),"xchg","dword ptr [rax], ebx"),
                 148:(bytes.fromhex("f00908"),"lock or","dword ptr [rax], ecx"),
                 152:(bytes.fromhex("d018"),"rcr","byte ptr [rax], 1"),
                 156:(bytes.fromhex("d1d1"),"rcl","ecx, 1"),
                 160:(bytes.fromhex("66a7"),"cmpsw","word ptr [rsi], word ptr [rdi]"),
                 164:(bytes.fromhex("ad"),"lodsd","eax, dword ptr [rsi]"),
                 168:(bytes.fromhex("a5"),"movsd","dword ptr [rdi], dword ptr [rsi]"),
                 172:(bytes.fromhex("e1fe"),"loope","0xac"),
                 176:(bytes.fromhex("9e"),"sahf",""),
                 180:(bytes.fromhex("fc"),"cld",""),
                 184:(bytes.fromhex("fd"),"std",""),
                 188:(bytes.fromhex("5c"),"pop","rsp"),
                 192:(bytes.fromhex("d7"),"xlatb",""),
                 196:(bytes.fromhex("9c"),"pushfq",""),
                 200:(bytes.fromhex("6318"),"movsxd","ebx, dword ptr [rax]")})
    src,accepted,reject=generate(rows,set(rows))
    if len(accepted)!=43 or reject:raise RuntimeError("scalar/CRT generator fixture")
    # Execute emitted memory operand with a callback accepting only eight
    # bytes. Incorrect 16-byte reads must fail this boundary fixture.
    compare=root/"compare-width.c";compare.write_text(src+r"""
int main(void);
static int rd64(void*c,uint64_t p,unsigned n,uint64_t*out){
 (void)c;if(p!=64||n!=8)return 0;*out=UINT64_C(0x3ff0000000000000);return 1;
}
int main(void){
 mxb_cfg s={0};s.read=rd64;s.rip=120;s.r[1]=64;s.mxcsr=0x1f80;
 s.xmm[0].lo=UINT64_C(0x3ff0000000000000);
 return mxb_block_step(&s)!=1||s.rip!=124||!(s.flags&ZF);
}
""")
    exe=root/"compare-width.exe"
    subprocess.run([sys.executable,"-m","ziglang","cc","-target","x86_64-windows-gnu","-O2",str(compare),"-o",str(exe)],check=True,timeout=120)
    subprocess.run([str(exe)],check=True,timeout=30)
    print("COMISD_M64_WIDTH_FIXTURE passed",flush=True)
    expanded=root/"expanded-memory.c";expanded.write_text(src+r"""
static uint8_t mem[256];static int writable=1;
static int rd(void*c,uint64_t a,unsigned n,uint64_t*out){
 (void)c;if(!n||n>8||a>sizeof(mem)-n)return 0;*out=0;for(unsigned i=0;i<n;i++)*out|=(uint64_t)mem[a+i]<<(8*i);return 1;
}
static int wr(void*c,uint64_t a,unsigned n,uint64_t v){
 (void)c;if(!writable||!n||n>8||a>sizeof(mem)-n)return 0;for(unsigned i=0;i<n;i++)mem[a+i]=(uint8_t)(v>>(8*i));return 1;
}
static int step(mxb_cfg*s,uint64_t pc){s->rip=pc;return mxb_block_step(s);}
int main(void){
 mxb_cfg s={0};s.read=rd;s.write=wr;s.exclusive_guest=1;s.known=STATUS;
 s.r[1]=0x1122334455667788ULL;if(step(&s,128)!=1||s.r[1]!=0x112233445566c088ULL)return 1;
 s.r[0]=64;s.r[2]=0x0200;mem[64]=254;if(step(&s,132)!=1||mem[64]||!(s.flags&CF)||!(s.flags&ZF))return 2;
 s.r[1]=0x7f00;s.r[3]=1;if(step(&s,136)!=1||s.r[1]!=0x8000||!(s.flags&OF))return 3;
 s.r[0]=64;s.r[1]=0x11223344;wr(0,64,4,64);
 if(step(&s,140)!=1||mem[64]!=0x44||!(s.flags&ZF))return 4;
 s.r[0]=64;if(step(&s,140)!=1||s.r[0]!=0x11223344||s.flags&ZF)return 5;
 s.r[0]=64;s.r[3]=0xffffffff000000aaULL;if(step(&s,144)!=1||s.r[3]!=0x11223344||mem[64]!=0xaa)return 6;
 s.r[1]=0x55;if(step(&s,148)!=1||mem[64]!=0xff)return 7;
 s.exclusive_guest=0;if(step(&s,148)!=-8||mem[64]!=0xff)return 8;s.exclusive_guest=1;
 s.flags=CF;s.known=STATUS;mem[64]=2;if(step(&s,152)!=1||mem[64]!=0x81||(s.flags&CF)||!(s.flags&OF))return 9;
 s.flags=CF;s.known=STATUS;s.r[1]=0x80000000;if(step(&s,156)!=1||s.r[1]!=1||!(s.flags&CF)||!(s.flags&OF))return 10;
 s.flags=0;s.r[6]=80;s.r[7]=90;wr(0,80,2,55);wr(0,90,2,55);
 if(step(&s,160)!=1||s.r[6]!=82||s.r[7]!=92||!(s.flags&ZF))return 11;
 wr(0,82,4,0xf1234567);if(step(&s,164)!=1||s.r[0]!=0xf1234567||s.r[6]!=86)return 12;
 wr(0,86,4,0x55667788);if(step(&s,168)!=1||mem[92]!=0x88||s.r[6]!=90||s.r[7]!=96)return 13;
 s.r[1]=2;s.flags=ZF;s.known=STATUS;if(step(&s,172)!=1||s.rip!=172||s.r[1]!=1)return 14;
 s.r[0]=0xd500;s.flags=OF;if(step(&s,176)!=1||(s.flags&(STATUS))!=(OF|CF|PF|AF|ZF|SF))return 15;
 if(step(&s,184)!=1||!(s.flags&1024)||step(&s,180)!=1||(s.flags&1024))return 16;
 s.r[4]=128;wr(0,128,8,200);if(step(&s,188)!=1||s.r[4]!=200)return 17;
 s.r[0]=3;s.r[3]=96;mem[99]=0x9a;if(step(&s,192)!=1||s.r[0]!=0x9a)return 18;
 s.flags=CF|OF;s.known=STATUS;s.r[4]=200;uint64_t v;
 if(step(&s,196)!=1||s.r[4]!=192||!rd(0,192,8,&v)||v!=(CF|OF|2))return 19;
 s.r[0]=64;wr(0,64,4,0x80000000);if(step(&s,200)!=1||s.r[3]!=0x80000000)return 20;
 writable=0;s.flags=CF;s.known=STATUS;mem[64]=2;if(step(&s,152)!=-2||s.flags!=CF||mem[64]!=2)return 21;
 return 0;
}
""")
    expanded_exe=root/"expanded-memory.exe"
    subprocess.run([sys.executable,"-m","ziglang","cc","-target","x86_64-windows-gnu","-O2",str(expanded),"-o",str(expanded_exe)],check=True,timeout=120)
    subprocess.run([str(expanded_exe)],check=True,timeout=30)
    print("EXPANDED_LEGACY_MEMORY_FIXTURE 21 checks passed",flush=True)
    source=root/"integer-arm.c";source.write_text(src)
    obj=root/"integer-arm.o"
    subprocess.run([sys.executable,"-m","ziglang","cc","-target","aarch64-linux-musl","-O2","-ffreestanding","-fno-builtin","-c",str(source),"-o",str(obj)],check=True,timeout=120)
    print("INTEGER_ARM64_OBJECT "+str(obj.stat().st_size),flush=True)
if __name__=="__main__":
    with tempfile.TemporaryDirectory(prefix="mxb-integer-oracle-") as p:run(p)
