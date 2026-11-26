import ctypes as C
import shutil,subprocess,tempfile,unittest,sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'scripts'))
from mxb_demo_block_batch import generate
from mxb_demo_cfg_batch import decode
from test_mxb_demo_simd_batch import State,Read,Write,Write128,STOP
class Tests(unittest.TestCase):
    def setUp(self):
        if not shutil.which('clang') or not shutil.which('llvm-objdump'):self.skipTest('LLVM unavailable')
        t=tempfile.TemporaryDirectory();self.addCleanup(t.cleanup);self.p=Path(t.name);self.mem=bytearray(512);self.s=State();self.s.mxcsr=0x1f80;self.s.r[4]=400;self.s.known=0x8d5;self.mem[400:408]=STOP.to_bytes(8,'little')
        @Read
        def rd(_,a,n,p):
            if not 0<=a<=a+n<=512:return 0
            p[0]=int.from_bytes(self.mem[a:a+n],'little');return 1
        @Write
        def wr(_,a,n,v):
            if not 0<=a<=a+n<=512:return 0
            self.mem[a:a+n]=v.to_bytes(8,'little')[:n];return 1
        self.s.read=rd;self.s.write=wr
    def build(self,asm,select=None):
        p=self.p/'fixture.s';o=p.with_suffix('.o');c=p.with_suffix('.c');lib=p.with_suffix('.so')
        p.write_text('.text\n.intel_syntax noprefix\n.globl fixture\nfixture:\n'+asm+'\n')
        subprocess.run(['clang','--target=x86_64-unknown-linux-gnu','-c',str(p),'-o',str(o)],check=True)
        ins=decode(subprocess.check_output(['llvm-objdump','-d','--x86-asm-syntax=intel',str(o)],text=True).splitlines())
        src,accepted,reject=generate(ins,set(ins) if select is None else select);c.write_text(src)
        subprocess.run(['clang','-shared','-fPIC','-O2','-Wall','-Wextra','-Werror','-Wno-unused-function',str(c),'-o',str(lib)],check=True)
        self.lib=C.CDLL(str(lib));self.run=self.lib.mxb_block_run;self.run.argtypes=[C.POINTER(State),C.c_uint64,C.c_uint];self.run.restype=C.c_int;return ins,accepted,reject
    def test_indirect_call(self):
        ins,_,_=self.build('call rax\nadd ecx,3\nret\nchild: mov ecx,4\nret');target=next(k for k,v in ins.items() if v[1]=='mov');self.s.r[0]=target
        self.assertEqual(self.run(C.byref(self.s),STOP,16),1);self.assertEqual(self.s.r[1],7);self.assertEqual(self.s.r[4],408)
    def test_import_boundary_and_resume(self):
        self.build('call rax\nadd ecx,3\nret');self.s.r[0]=0x12340000
        self.assertEqual(self.run(C.byref(self.s),STOP,16),2);self.assertEqual(self.s.rip,0x12340000);self.assertEqual(self.s.r[4],392)
        ret=int.from_bytes(self.mem[392:400],'little');self.s.r[4]+=8;self.s.rip=ret;self.s.r[1]=8
        self.assertEqual(self.run(C.byref(self.s),STOP,16),1);self.assertEqual(self.s.r[1],11)
    def test_stack_operand_before_push(self):
        ins,_,_=self.build('call qword ptr [rsp-8]\nret\nchild: mov ecx,9\nret');target=next(k for k,v in ins.items() if v[1]=='mov');self.mem[392:400]=target.to_bytes(8,'little')
        self.assertEqual(self.run(C.byref(self.s),STOP,16),1);self.assertEqual(self.s.r[1],9)
    def test_indirect_jump(self):
        ins,_,_=self.build('jmp rax\nint3\nchild: mov ecx,9\nret');target=next(k for k,v in ins.items() if v[1]=='mov');self.s.r[0]=target
        self.assertEqual(self.run(C.byref(self.s),STOP,16),1);self.assertEqual(self.s.r[1],9);self.assertEqual(self.s.r[4],408)
    def test_unknown_instruction_yields(self):
        _,accepted,reject=self.build('mov eax,1\ncpuid\nret');self.assertEqual(len(accepted),2);self.assertEqual(sum(reject.values()),1)
        self.assertEqual(self.run(C.byref(self.s),STOP,16),2);self.assertEqual(self.s.r[0],1)
    def test_indirect_memory_fault(self):
        self.build('call qword ptr [rcx]\nret');self.s.r[1]=511
        self.assertEqual(self.run(C.byref(self.s),STOP,16),-2);self.assertEqual(self.s.rip,0);self.assertEqual(self.s.r[4],400)
    def test_budget(self):
        self.build('loop1: inc eax\njmp loop1');self.assertEqual(self.run(C.byref(self.s),STOP,4),0);self.assertEqual(self.s.r[0],2)
    def test_arm64_compile(self):
        ins={0:(b'\xff\xd0','call','rax'),2:(b'\xc3','ret','')};src,_,_=generate(ins,set(ins));p=self.p/'arm.c';o=p.with_suffix('.o');p.write_text(src)
        subprocess.run(['clang','--target=arm64-apple-ios15.0','-ffreestanding','-fno-builtin','-O2','-c',str(p),'-o',str(o)],check=True);self.assertEqual(o.read_bytes()[:8],b'\xcf\xfa\xed\xfe\x0c\x00\x00\x01')
if __name__=='__main__':unittest.main()
