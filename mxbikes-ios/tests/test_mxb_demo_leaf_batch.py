import ctypes as C
from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import shutil
import subprocess
import tempfile
import unittest
from mxb_demo_leaf_batch import decode, lift, PREAMBLE

Read=C.CFUNCTYPE(C.c_int,C.c_void_p,C.c_uint64,C.c_uint,C.POINTER(C.c_uint64))
Write=C.CFUNCTYPE(C.c_int,C.c_void_p,C.c_uint64,C.c_uint,C.c_uint64)
class State(C.Structure):
    _fields_=[('r',C.c_uint64*16),('ctx',C.c_void_p),('read',Read),('write',Write)]

class LiftTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.path=Path(self.tmp.name);self.mem=bytearray(256);self.state=State()
        @Read
        def rd(_,a,n,p):
            if not 0<=a<=a+n<=len(self.mem):return 0
            p[0]=int.from_bytes(self.mem[a:a+n],'little');return 1
        @Write
        def wr(_,a,n,v):
            if not 0<=a<=a+n<=len(self.mem):return 0
            self.mem[a:a+n]=v.to_bytes(n,'little');return 1
        self.state.read=rd;self.state.write=wr
    def translate(self,asm):
        # Synthetic assembly is decoded by the same LLVM backend as the demo.
        if not shutil.which('clang') or not shutil.which('llvm-objdump'):self.skipTest('LLVM unavailable')
        (self.path/'test.s').write_text('.text\n.intel_syntax noprefix\n.globl fixture\nfixture:\n'+asm+'\n')
        subprocess.run(['clang','--target=x86_64-unknown-linux-gnu','-c',str(self.path/'test.s'),'-o',str(self.path/'test.o')],check=True)
        out=subprocess.check_output(['llvm-objdump','-d','--x86-asm-syntax=intel',str(self.path/'test.o')],text=True)
        ins,_=decode(out.splitlines());return lift(ins,0,'fixture')
    def run_lift(self,asm):
        src,n,end=self.translate(asm);(self.path/'lift.c').write_text(PREAMBLE+src)
        subprocess.run(['clang','-Wall','-Wextra','-Werror','-shared','-fPIC','-O2',str(self.path/'lift.c'),'-o',str(self.path/'lift.so')],check=True)
        lib=C.CDLL(str(self.path/'lift.so'));lib.fixture.argtypes=[C.POINTER(State)];lib.fixture.restype=C.c_int
        return lib.fixture(C.byref(self.state))
    def test_mov32(self):
        self.state.r[0]=2**64-1;self.state.r[1]=0xfedcba9876543210
        self.assertEqual(self.run_lift('mov eax, ecx\nret'),1);self.assertEqual(self.state.r[0],0x76543210)
    def test_low8(self):
        self.state.r[0]=0x123456789abcdef0;self.state.r[1]=0x37
        self.run_lift('mov al, cl\nret');self.assertEqual(self.state.r[0],0x123456789abcde37)
    def test_low16(self):
        self.state.r[0]=0x123456789abcdef0;self.state.r[1]=0x9876
        self.run_lift('mov ax, cx\nret');self.assertEqual(self.state.r[0],0x123456789abc9876)
    def test_sign(self):
        self.state.r[1]=0x80;self.run_lift('movsx rax, cl\nret');self.assertEqual(self.state.r[0],2**64-128)
    def test_sign_memory(self):
        self.state.r[1]=16;self.mem[16:20]=b'\x00\x00\x00\x80'
        self.run_lift('movsxd rax, dword ptr [rcx]\nret');self.assertEqual(self.state.r[0],2**64-2**31)
    def test_memory(self):
        self.state.r[1]=32;self.state.r[2]=4;self.mem[44:48]=b'\x78\x56\x34\x12'
        self.assertEqual(self.run_lift('mov eax, dword ptr [rcx + rdx*4 - 4]\nmov dword ptr [rcx + 4], eax\nret'),1)
        self.assertEqual(self.mem[36:40],b'\x78\x56\x34\x12')
    def test_lea(self):
        self.state.r[1]=2**64-1;self.state.r[2]=3
        self.run_lift('lea rax, [rcx + 4*rdx + 1]\nret');self.assertEqual(self.state.r[0],12)
    def test_arithmetic(self):
        self.state.r[1]=0xffffffff;self.run_lift('mov eax, ecx\nadd eax, 1\nsub eax, 1\nshr eax, 33\nret');self.assertEqual(self.state.r[0],0x7fffffff)
    def test_fault(self):
        self.state.r[1]=255;self.state.r[0]=123
        self.assertEqual(self.run_lift('mov eax, dword ptr [rcx]\nret'),0);self.assertEqual(self.state.r[0],123)
    def test_nonvolatile(self):
        with self.assertRaises(ValueError):self.translate('mov rbx, rax\nret')
    def test_control(self):
        with self.assertRaises(ValueError):self.translate('jmp next\nnext: ret')
    def test_flags(self):
        with self.assertRaises(ValueError):self.translate('adc rax, rcx\nret')
    def test_ret_imm(self):
        with self.assertRaises(ValueError):self.translate('ret 8')
    def test_direct_call(self):
        _,targets=decode(['140001000: e8 01 00 00 00   call 0x140001006','140001005: ff d0 call rax'])
        self.assertEqual(dict(targets),{0x140001006:1})

if __name__=='__main__':unittest.main()
