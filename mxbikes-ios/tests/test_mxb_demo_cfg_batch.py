import ctypes as C
import platform
import random
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'scripts'))
from mxb_demo_cfg_batch import decode,lift,PREAMBLE,graph_policy

Read=C.CFUNCTYPE(C.c_int,C.c_void_p,C.c_uint64,C.c_uint,C.POINTER(C.c_uint64))
Write=C.CFUNCTYPE(C.c_int,C.c_void_p,C.c_uint64,C.c_uint,C.c_uint64)
class State(C.Structure):
    _fields_=[('r',C.c_uint64*16),('rip',C.c_uint64),('flags',C.c_uint64),('known',C.c_uint64),('ctx',C.c_void_p),('read',Read),('write',Write)]
STATUS=0x8d5
STOP=0xdeadbeef
class Tests(unittest.TestCase):
    def setUp(self):
        if not shutil.which('clang') or not shutil.which('llvm-objdump'):self.skipTest('LLVM unavailable')
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup);self.p=Path(self.tmp.name)
        self.mem=bytearray(512);self.s=State();self.s.r[4]=400;self.s.known=STATUS
        self.mem[400:408]=STOP.to_bytes(8,'little')
        @Read
        def rd(_,a,n,p):
            if not 0<=a<=a+n<=len(self.mem):return 0
            p[0]=int.from_bytes(self.mem[a:a+n],'little');return 1
        @Write
        def wr(_,a,n,v):
            if not 0<=a<=a+n<=len(self.mem):return 0
            self.mem[a:a+n]=v.to_bytes(n,'little');return 1
        self.s.read=rd;self.s.write=wr
    def translate(self,asm):
        src=self.p/'test.s';obj=self.p/'test.o'
        src.write_text('.text\n.intel_syntax noprefix\n.globl fixture\nfixture:\n'+asm+'\n')
        subprocess.run(['clang','--target=x86_64-unknown-linux-gnu','-c',str(src),'-o',str(obj)],check=True)
        out=subprocess.check_output(['llvm-objdump','-d','--x86-asm-syntax=intel',str(obj)],text=True)
        ins=decode(out.splitlines());return lift(ins,0,'fixture',lambda a:a in ins)
    def run_lift(self,asm,budget=128):
        src,_=self.translate(asm);c=self.p/'lift.c';so=self.p/'lift.so';c.write_text(PREAMBLE+src)
        subprocess.run(['clang','-Wall','-Wextra','-Werror','-Wno-unused-function','-shared','-fPIC','-O2',str(c),'-o',str(so)],check=True)
        lib=C.CDLL(str(so));fn=lib.fixture;fn.argtypes=[C.POINTER(State),C.c_uint64,C.c_uint];fn.restype=C.c_int
        return fn(C.byref(self.s),STOP,budget)
    def test_branch_taken(self):
        self.s.r[1]=0;self.assertEqual(self.run_lift('cmp ecx, 0\nje yes\nmov eax, 1\nret\nyes: mov eax, 2\nret'),1);self.assertEqual(self.s.r[0],2)
    def test_branch_fallthrough(self):
        self.s.r[1]=1;self.assertEqual(self.run_lift('cmp ecx, 0\nje yes\nmov eax, 1\nret\nyes: mov eax, 2\nret'),1);self.assertEqual(self.s.r[0],1)
    def test_signed(self):
        self.s.r[1]=0x80000000;self.assertEqual(self.run_lift('cmp ecx, 1\njl yes\nmov eax, 0\nret\nyes: mov eax, 1\nret'),1);self.assertEqual(self.s.r[0],1)
    def test_unsigned(self):
        self.s.r[1]=0xffffffff;self.run_lift('cmp ecx, 1\nja yes\nmov eax, 0\nret\nyes: mov eax, 1\nret');self.assertEqual(self.s.r[0],1)
    def test_overflow(self):
        self.s.r[0]=0x7fffffff;self.run_lift('add eax, 1\nret');self.assertEqual(self.s.r[0],0x80000000);self.assertEqual(self.s.flags&STATUS,0x894)
    def test_carry(self):
        self.s.r[0]=0xffffffffffffffff;self.run_lift('add rax, 1\nret');self.assertEqual(self.s.flags&STATUS,0x55)
    def test_logic(self):
        self.s.flags=STATUS;self.run_lift('xor eax, eax\nret');self.assertEqual(self.s.flags&STATUS,0x44);self.assertEqual(self.s.known&STATUS,STATUS&~16)
    def test_inc_preserve(self):
        self.s.flags=1;self.run_lift('inc eax\nret');self.assertEqual(self.s.flags&1,1)
    def test_unknown_flags(self):
        self.s.known=0;self.assertEqual(self.run_lift('jz yes\nret\nyes: ret'),-3);self.assertEqual(self.s.rip,0)
    def test_call_stack(self):
        self.s.r[3]=0x12345678;self.s.r[1]=7
        asm='push rbx\nsub rsp, 32\nmov ebx, ecx\ncall child\nadd eax, ebx\nadd rsp, 32\npop rbx\nret\nchild: mov eax, 3\nret'
        self.assertEqual(self.run_lift(asm),1);self.assertEqual(self.s.r[0],10);self.assertEqual(self.s.r[3],0x12345678);self.assertEqual(self.s.r[4],408)
    def test_loop(self):
        self.s.r[1]=5;self.assertEqual(self.run_lift('xor eax,eax\nloop1: add eax, ecx\ndec ecx\njnz loop1\nret'),1);self.assertEqual(self.s.r[0],15)
    def test_budget(self):
        self.s.r[1]=100;self.assertEqual(self.run_lift('loop1: dec ecx\njnz loop1\nret',4),0);self.assertEqual(self.s.r[1],98)
    def test_memory(self):
        self.s.r[1]=32;self.mem[32:36]=b'\x12\x34\x56\x78';self.run_lift('mov eax, dword ptr [rcx]\nmov dword ptr [rcx+4], eax\nret');self.assertEqual(self.mem[36:40],self.mem[32:36])
    def test_fault(self):
        self.s.r[1]=511;self.s.r[0]=99;self.assertEqual(self.run_lift('mov eax, dword ptr [rcx]\nret'),-2);self.assertEqual(self.s.r[0],99);self.assertEqual(self.s.rip,0)
    def test_bad_return(self):
        self.mem[400:408]=(123).to_bytes(8,'little');self.assertEqual(self.run_lift('ret'),-4)
    def test_reject_indirect(self):
        with self.assertRaises(ValueError):self.translate('call rax\nret')
    def test_reject_simd(self):
        with self.assertRaises(ValueError):self.translate('addss xmm0,xmm1\nret')
    def test_reject_rmw(self):
        with self.assertRaises(ValueError):self.translate('add dword ptr [rcx],1\nret')
    def test_reject_ret_imm(self):
        with self.assertRaises(ValueError):self.translate('ret 8')
    def test_cross_interval_call_policy(self):
        ins={0:(b'\xe8\x0b\0\0\0','call',''),5:(b'\xc3','ret',''),16:(b'\xc3','ret','')}
        _,allowed,edge=graph_policy(ins,{0:6,16:17})
        _,nodes=lift(ins,0,'fixture',allowed,edge_allowed=edge)
        self.assertEqual(set(nodes),{0,5,16})
    def test_cross_interval_fallthrough_rejected(self):
        ins={0:(b'\x90','nop',''),1:(b'\xc3','ret','')}
        _,allowed,edge=graph_policy(ins,{0:1,1:2})
        with self.assertRaisesRegex(ValueError,'invalid_graph_edge'):lift(ins,0,'fixture',allowed,edge_allowed=edge)
    def test_cross_interval_mid_entry_rejected(self):
        ins={0:(b'\xe8\x0c\0\0\0','call',''),5:(b'\xc3','ret',''),16:(b'\x90','nop',''),17:(b'\xc3','ret','')}
        _,allowed,edge=graph_policy(ins,{0:6,16:18})
        with self.assertRaisesRegex(ValueError,'invalid_graph_edge'):lift(ins,0,'fixture',allowed,edge_allowed=edge)
    def test_x64_alu_differential(self):
        if platform.machine().lower() not in ('x86_64','amd64') or sys.platform!='linux':self.skipTest('native Linux x64 required')
        rng=random.Random(21021)
        for bits,reg,src in [(8,'al','cl'),(16,'ax','cx'),(32,'eax','ecx'),(64,'rax','rcx')]:
            for op in ('add','sub','and','or','xor','cmp','test','inc','dec','neg','not'):
                asm=f'{op} {reg}'+('' if op in ('inc','dec','neg','not') else f', {src}')
                with self.subTest(bits=bits,op=op):
                    lifted,_=self.translate(asm+'\nret');cp=self.p/'lift.c';so=self.p/'lift.so'
                    cp.write_text(PREAMBLE+lifted)
                    # A unique library path avoids dlopen caching the previous fixture.
                    so=self.p/f'lift-{bits}-{op}.so'
                    subprocess.run(['clang','-shared','-fPIC','-O2',str(cp),'-o',str(so)],check=True)
                    lib=C.CDLL(str(so));fn=lib.fixture;fn.argtypes=[C.POINTER(State),C.c_uint64,C.c_uint];fn.restype=C.c_int
                    ap=self.p/'ref.s';ro=self.p/f'ref-{bits}-{op}.so'
                    ap.write_text('.text\n.intel_syntax noprefix\n.globl reference\nreference:\nmov rax,rdi\nmov r8,rcx\nmov rcx,rsi\npush rdx\npopfq\n'+asm+'\npushfq\npop rdx\nmov [r8],rax\nmov [r8+8],rdx\nret\n.section .note.GNU-stack,"",@progbits\n')
                    subprocess.run(['clang','-shared','-fPIC',str(ap),'-o',str(ro)],check=True)
                    rl=C.CDLL(str(ro));ref=rl.reference;ref.argtypes=[C.c_uint64,C.c_uint64,C.c_uint64,C.POINTER(C.c_uint64)];ref.restype=None
                    mask=(1<<bits)-1;sign=1<<(bits-1)
                    cases=[(0,0),(mask,1),(sign-1,1),(sign,1),(sign,sign),(mask,mask)]
                    cases += [(rng.getrandbits(64),rng.getrandbits(64)) for _ in range(58)]
                    for a,b in cases:
                        initial=rng.getrandbits(12)&STATUS
                        self.s.r[0]=a;self.s.r[1]=b;self.s.r[4]=400;self.s.rip=0;self.s.flags=initial;self.s.known=STATUS
                        result=(C.c_uint64*2)();ref(a,b,initial|0x202,result)
                        self.assertEqual(fn(C.byref(self.s),STOP,8),1)
                        self.assertEqual(self.s.r[0],result[0])
                        self.assertEqual(self.s.flags&self.s.known&STATUS,result[1]&self.s.known&STATUS)
    def test_arm64_compile(self):
        src,_=self.translate('cmp ecx, 1\njne yes\nmov eax,1\nret\nyes: mov eax,2\nret');c=self.p/'lift.c';o=self.p/'arm.o';c.write_text(PREAMBLE+src)
        subprocess.run(['clang','--target=arm64-apple-ios15.0','-ffreestanding','-fno-builtin','-O2','-c',str(c),'-o',str(o)],check=True);self.assertEqual(o.read_bytes()[:8],b'\xcf\xfa\xed\xfe\x0c\x00\x00\x01')
if __name__=='__main__':unittest.main()
