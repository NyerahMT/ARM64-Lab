import ctypes as C
import platform,random,shutil,struct,subprocess,sys,tempfile,unittest
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'scripts'))
from mxb_demo_simd_batch import PREAMBLE,lift
from mxb_demo_cfg_batch import decode
Read=C.CFUNCTYPE(C.c_int,C.c_void_p,C.c_uint64,C.c_uint,C.POINTER(C.c_uint64))
Write=C.CFUNCTYPE(C.c_int,C.c_void_p,C.c_uint64,C.c_uint,C.c_uint64)
Write128=C.CFUNCTYPE(C.c_int,C.c_void_p,C.c_uint64,C.c_uint64,C.c_uint64)
class Xmm(C.Structure):_fields_=[('lo',C.c_uint64),('hi',C.c_uint64)]
class State(C.Structure):_fields_=[('r',C.c_uint64*16),('rip',C.c_uint64),('flags',C.c_uint64),('known',C.c_uint64),('ctx',C.c_void_p),('read',Read),('write',Write),('xmm',Xmm*16),('mxcsr',C.c_uint32),('write128',Write128)]
STATUS=0x8d5;STOP=0xdeadbeef
class Tests(unittest.TestCase):
    def setUp(self):
        if not shutil.which('clang') or not shutil.which('llvm-objdump'):self.skipTest('LLVM unavailable')
        t=tempfile.TemporaryDirectory();self.addCleanup(t.cleanup);self.p=Path(t.name);self.seq=0
        self.mem=bytearray(512);self.s=State();self.s.mxcsr=0x1f80;self.reset()
        @Read
        def rd(_,a,n,p):
            if not 0<=a<=a+n<=512:return 0
            p[0]=int.from_bytes(self.mem[a:a+n],'little');return 1
        @Write
        def wr(_,a,n,v):
            if not 0<=a<=a+n<=512:return 0
            self.mem[a:a+n]=v.to_bytes(8,'little')[:n];return 1
        @Write128
        def wr128(_,a,lo,hi):
            if not 0<=a<=a+16<=512:return 0
            self.mem[a:a+16]=struct.pack('<QQ',lo,hi);return 1
        self.s.read=rd;self.s.write=wr;self.s.write128=wr128
    def reset(self):
        self.s.rip=0;self.s.r[4]=400;self.s.flags=0;self.s.known=STATUS
        self.mem[400:408]=struct.pack('<Q',STOP)
    def compile(self,asm):
        self.seq+=1;src=self.p/f't{self.seq}.s';obj=src.with_suffix('.o');c=src.with_suffix('.c');so=src.with_suffix('.so')
        src.write_text('.text\n.intel_syntax noprefix\n.globl fixture\nfixture:\n'+asm+'\nret\n')
        subprocess.run(['clang','--target=x86_64-unknown-linux-gnu','-c',str(src),'-o',str(obj)],check=True)
        ins=decode(subprocess.check_output(['llvm-objdump','-d','--x86-asm-syntax=intel',str(obj)],text=True).splitlines())
        code,_=lift(ins,0,'fixture',lambda a:a in ins);c.write_text(PREAMBLE+code)
        subprocess.run(['clang','-Wall','-Wextra','-Werror','-Wno-unused-function','-O2','-shared','-fPIC',str(c),'-o',str(so)],check=True)
        lib=C.CDLL(str(so));fn=lib.fixture;fn.argtypes=[C.POINTER(State),C.c_uint64,C.c_uint];fn.restype=C.c_int;return fn
    def run_asm(self,asm):return self.compile(asm)(C.byref(self.s),STOP,32)
    def test_scalar_register(self):
        self.s.xmm[0]=Xmm(0xaabbccdd12345678,42);self.s.xmm[1]=Xmm(0x99887766deadbeef,99)
        self.assertEqual(self.run_asm('movss xmm0,xmm1'),1);self.assertEqual((self.s.xmm[0].lo,self.s.xmm[0].hi),(0xaabbccdddeadbeef,42))
    def test_scalar_memory(self):
        self.s.r[1]=32;self.mem[32:40]=struct.pack('<Q',0x123456789abcdef0);self.s.xmm[0]=Xmm(99,99)
        self.assertEqual(self.run_asm('movsd xmm0,qword ptr [rcx]'),1);self.assertEqual((self.s.xmm[0].lo,self.s.xmm[0].hi),(0x123456789abcdef0,0))
    def test_gpr_transfer(self):
        self.s.r[0]=0xabcdef0123456789;self.s.xmm[0]=Xmm(9,9);self.assertEqual(self.run_asm('movd xmm0,eax\nmovd ecx,xmm0'),1);self.assertEqual(self.s.r[1],0x23456789);self.assertEqual((self.s.xmm[0].lo,self.s.xmm[0].hi),(0x23456789,0))
    def test_unaligned_move(self):
        self.s.r[1]=33;self.mem[33:49]=bytes(range(16));self.assertEqual(self.run_asm('movups xmm0,xmmword ptr [rcx]\nmovups xmmword ptr [rcx+17],xmm0'),1);self.assertEqual(self.mem[50:66],bytes(range(16)))
    def test_alignment_fault(self):
        self.s.r[1]=33;self.s.xmm[0]=Xmm(5,7);self.assertEqual(self.run_asm('movaps xmm0,xmmword ptr [rcx]'),-2);self.assertEqual((self.s.xmm[0].lo,self.s.xmm[0].hi),(5,7));self.assertEqual(self.s.rip,0)
    def test_partial_read_fault(self):
        self.s.r[1]=504;self.s.xmm[0]=Xmm(5,7);self.assertEqual(self.run_asm('movups xmm0,xmmword ptr [rcx]'),-2);self.assertEqual((self.s.xmm[0].lo,self.s.xmm[0].hi),(5,7))
    def test_atomic_write_fault(self):
        self.s.r[1]=504;self.s.xmm[0]=Xmm(5,7);self.assertEqual(self.run_asm('movups xmmword ptr [rcx],xmm0'),-2);self.assertEqual(self.mem[504:],bytes(8));self.assertEqual(self.s.rip,0)
    def test_unsupported_fp_controls(self):
        self.s.mxcsr=0x3f80;self.assertEqual(self.run_asm('ucomiss xmm0,xmm1'),-5);self.assertEqual(self.s.rip,0)
    def test_nan_rejection(self):
        self.s.xmm[0]=Xmm(0x7fc00000,0);self.assertEqual(self.run_asm('ucomiss xmm0,xmm1'),-5)
    def test_x64_vector_differential(self):
        if platform.machine().lower() not in ('x86_64','amd64') or sys.platform!='linux':self.skipTest('native Linux x64 required')
        rng=random.Random(720);ops=['movaps xmm0,xmm1','movss xmm0,xmm1','movsd xmm0,xmm1','movq xmm0,xmm1','movdqa xmm0,xmm1','pxor xmm0,xmm1','andnps xmm0,xmm1','por xmm0,xmm1','pand xmm0,xmm1','paddb xmm0,xmm1','paddw xmm0,xmm1','paddd xmm0,xmm1','paddq xmm0,xmm1','psubb xmm0,xmm1','psubw xmm0,xmm1','psubd xmm0,xmm1','psubq xmm0,xmm1','pcmpeqb xmm0,xmm1','pcmpeqw xmm0,xmm1','pcmpeqd xmm0,xmm1','pcmpgtb xmm0,xmm1','pcmpgtw xmm0,xmm1','pcmpgtd xmm0,xmm1','shufps xmm0,xmm1,0x1b','pshufd xmm0,xmm1,0x39','unpcklps xmm0,xmm1','unpckhps xmm0,xmm1','ucomiss xmm0,xmm1','ucomisd xmm0,xmm1','comiss xmm0,xmm1','comisd xmm0,xmm1']
        for op in ops:
            with self.subTest(op=op):
                fn=self.compile(op);ap=self.p/f'r{self.seq}.s';so=ap.with_suffix('.so')
                ap.write_text('.text\n.intel_syntax noprefix\n.globl reference\nreference:\nmovups xmm0,[rdi]\nmovups xmm1,[rsi]\npush 0x202\npopfq\n'+op+'\npushfq\npop rax\nmovups [rdx],xmm0\nret\n.section .note.GNU-stack,"",@progbits\n')
                subprocess.run(['clang','-shared','-fPIC',str(ap),'-o',str(so)],check=True);lib=C.CDLL(str(so));ref=lib.reference;ref.argtypes=[C.POINTER(Xmm),C.POINTER(Xmm),C.POINTER(Xmm)];ref.restype=C.c_uint64
                for i in range(64):
                    a=Xmm(rng.getrandbits(64),rng.getrandbits(64));b=Xmm(rng.getrandbits(64),rng.getrandbits(64))
                    if 'comis' in op:
                        x,y=(rng.randint(-1000,1000),rng.randint(-1000,1000)) if i>=4 else ((0.0,-0.0),(-1.0,-2.0),(1.0,-1.0),(1.0,1.0))[i]
                        if op.startswith(('ucomiss','comiss')):
                            a.lo=(a.lo&0xffffffff00000000)|struct.unpack('<I',struct.pack('<f',x))[0];b.lo=(b.lo&0xffffffff00000000)|struct.unpack('<I',struct.pack('<f',y))[0]
                        else:a.lo=struct.unpack('<Q',struct.pack('<d',x))[0];b.lo=struct.unpack('<Q',struct.pack('<d',y))[0]
                    out=Xmm();flags=ref(C.byref(a),C.byref(b),C.byref(out));self.reset();self.s.xmm[0]=a;self.s.xmm[1]=b
                    self.assertEqual(fn(C.byref(self.s),STOP,8),1);self.assertEqual((self.s.xmm[0].lo,self.s.xmm[0].hi),(out.lo,out.hi));self.assertEqual(self.s.flags&STATUS,flags&STATUS)
    def test_x64_fp_arithmetic(self):
        if platform.machine().lower() not in ('x86_64','amd64') or sys.platform!='linux':self.skipTest('native Linux x64 required')
        rng=random.Random(20261125);cases=0;rejections=0
        for suffix,w in [('ss',32),('sd',64),('ps',32),('pd',64)]:
            p=24 if w==32 else 53;bias=127 if w==32 else 1023
            for stem in ('add','sub','mul','div','min','max'):
                op=stem+suffix+' xmm0,xmm1'
                with self.subTest(op=op):
                    fn=self.compile(op);ap=self.p/f'fp{self.seq}.s';so=ap.with_suffix('.so')
                    ap.write_text('.text\n.intel_syntax noprefix\n.globl reference\nreference:\nstmxcsr [rsp-4]\nmov dword ptr [rsp-8],0x1f80\nldmxcsr [rsp-8]\nmovups xmm0,[rdi]\nmovups xmm1,[rsi]\n'+op+'\nmovups [rdx],xmm0\nstmxcsr [rdx+16]\nldmxcsr [rsp-4]\nret\n.section .note.GNU-stack,"",@progbits\n')
                    subprocess.run(['clang','-shared','-fPIC',str(ap),'-o',str(so)],check=True);lib=C.CDLL(str(so));ref=lib.reference;ref.argtypes=[C.POINTER(Xmm),C.POINTER(Xmm),C.c_void_p];ref.restype=None
                    def vector(i,second):
                        lanes=[]
                        for j in range(128//w):
                            if i<4:
                                x=[0.0,-0.0,1.0,-1.0][(i+j+second)%4];v=int.from_bytes(struct.pack('<f' if w==32 else '<d',x),'little')
                            else:
                                exp=rng.randint(max(1,bias-90),min(2*bias,bias+90)) if i<100 else rng.randint(1,2*bias)
                                v=(rng.getrandbits(1)<<(w-1))|(exp<<(p-1))|rng.getrandbits(p-1)
                            lanes.append(v)
                        val=sum(v<<(i*w) for i,v in enumerate(lanes));return Xmm(val&((1<<64)-1),val>>64)
                    for i in range(128):
                        a,b=vector(i,0),vector(i,1);out=(C.c_uint64*3)();ref(C.byref(a),C.byref(b),out)
                        self.reset();self.s.mxcsr=0x1f80;self.s.xmm[0]=a;self.s.xmm[1]=b
                        status=fn(C.byref(self.s),STOP,8)
                        if status==-5:
                            self.assertEqual((self.s.xmm[0].lo,self.s.xmm[0].hi),(a.lo,a.hi));self.assertEqual(self.s.mxcsr,0x1f80);rejections+=1;continue
                        self.assertEqual(status,1);self.assertEqual((self.s.xmm[0].lo,self.s.xmm[0].hi),(out[0],out[1]));self.assertEqual(self.s.mxcsr,out[2]&0xffffffff);cases+=1
        self.assertGreater(cases,2500);self.assertGreater(rejections,0)
        print(f'FP arithmetic: {cases} native CPU comparisons passed, {rejections} explicit domain rejections')
    def test_x64_fp_conversions(self):
        if platform.machine().lower() not in ('x86_64','amd64') or sys.platform!='linux':self.skipTest('native Linux x64 required')
        rng=random.Random(12);passed=0;rejected=0
        ops=['cvtss2sd xmm0,xmm1','cvtsd2ss xmm0,xmm1','cvtsi2ss xmm0,eax','cvtsi2sd xmm0,eax','cvtsi2ss xmm0,rax','cvtsi2sd xmm0,rax','cvtss2si eax,xmm1','cvtsd2si eax,xmm1','cvttss2si eax,xmm1','cvttsd2si eax,xmm1','cvtss2si rax,xmm1','cvtsd2si rax,xmm1','cvttss2si rax,xmm1','cvttsd2si rax,xmm1']
        for op in ops:
            with self.subTest(op=op):
                fn=self.compile(op);ap=self.p/f'fp{self.seq}.s';so=ap.with_suffix('.so')
                ap.write_text('.text\n.intel_syntax noprefix\n.globl reference\nreference:\nstmxcsr [rsp-4]\nmov dword ptr [rsp-8],0x1f80\nldmxcsr [rsp-8]\nmovups xmm0,[rdi]\nmovups xmm1,[rsi]\nmov rax,rdx\n'+op+'\nmovups [rcx],xmm0\nmov [rcx+16],rax\nstmxcsr [rcx+24]\nldmxcsr [rsp-4]\nret\n.section .note.GNU-stack,"",@progbits\n')
                subprocess.run(['clang','-shared','-fPIC',str(ap),'-o',str(so)],check=True);lib=C.CDLL(str(so));ref=lib.reference;ref.argtypes=[C.POINTER(Xmm),C.POINTER(Xmm),C.c_uint64,C.c_void_p];ref.restype=None
                for i in range(128):
                    a=Xmm(rng.getrandbits(64),rng.getrandbits(64));b=Xmm(rng.getrandbits(64),rng.getrandbits(64));v=rng.getrandbits(64)
                    if 'si2' not in op:
                        f=[-0.0,0.0,0.5,1.5,2.5,-2.5,-0.75,2147483648.0][i] if i<8 else rng.uniform(-1e10,1e10)
                        if 'ss2' in op:b.lo=(b.lo&0xffffffff00000000)|int.from_bytes(struct.pack('<f',f),'little')
                        else:b.lo=int.from_bytes(struct.pack('<d',f),'little')
                    out=(C.c_uint64*4)();ref(C.byref(a),C.byref(b),v,out);self.reset();self.s.mxcsr=0x1f80;self.s.xmm[0]=a;self.s.xmm[1]=b;self.s.r[0]=v
                    status=fn(C.byref(self.s),STOP,8)
                    if status==-5:
                        self.assertTrue(out[3]&1);self.assertEqual(self.s.r[0],v);self.assertEqual(self.s.mxcsr,0x1f80);rejected+=1;continue
                    self.assertEqual(status,1);self.assertEqual((self.s.xmm[0].lo,self.s.xmm[0].hi,self.s.r[0],self.s.mxcsr),(out[0],out[1],out[2],out[3]&0xffffffff));passed+=1
        self.assertGreater(passed,1000);self.assertGreater(rejected,0)
        print(f'FP conversion: {passed} native CPU comparisons passed, {rejected} explicit domain rejections')
    def test_arm64_compile(self):
        c=self.p/'arm.c';o=self.p/'arm.o';c.write_text(PREAMBLE+'int fixture(mxb_cfg*s){s->xmm[0]=xlogic(s->xmm[0],s->xmm[1],2);return xcompare(s,s->xmm[0].lo,s->xmm[1].lo,32);}')
        subprocess.run(['clang','--target=arm64-apple-ios15.0','-ffreestanding','-fno-builtin','-O2','-c',str(c),'-o',str(o)],check=True);self.assertEqual(o.read_bytes()[:8],b'\xcf\xfa\xed\xfe\x0c\x00\x00\x01')
if __name__=='__main__':unittest.main()
