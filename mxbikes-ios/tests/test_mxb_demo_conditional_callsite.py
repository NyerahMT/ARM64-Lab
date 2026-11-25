"""Synthetic conditional wrapper verification, no proprietary bytes."""
import struct,sys,unittest
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'scripts'))
from mxb_demo_conditional_callsite import prove_conditional_callsite
BASE=0x140000000;CALL=0x1000;THUNK=0x1100;PTR=0x2000;IAT=0x2008;TARGET=0x710000000
class PE:
    sections=[('.text',0x400,0x1000,0x400,0,0x60000000)]
    def __init__(self):
        self.data=bytearray(0x4000)
        self.data[CALL:CALL+5]=b'\xe8'+struct.pack('<i',THUNK-CALL-5)
        self.data[THUNK:THUNK+22]=(b'\x48\x8b\x05'+struct.pack('<i',PTR-THUNK-7)+
            b'\x48\x85\xc0\x74\x03\x48\xff\xe0\x48\xff\x25'+struct.pack('<i',IAT-THUNK-22))
    def read_rva(self,rva,n):return self.data[rva:rva+n]
class Tests(unittest.TestCase):
    def setUp(self):
        self.pe=PE();self.live=bytearray(self.pe.data);self.live[IAT:IAT+8]=struct.pack('<Q',TARGET)
        self.recent=[CALL,THUNK,THUNK+7,THUNK+10,THUNK+15];self.iat={IAT:('msvcr90.dll','malloc')}
    def prove(self):return prove_conditional_callsite(self.pe,self.iat,BASE,lambda a,n:self.live[a-BASE:a-BASE+n],BASE+CALL+5,TARGET,'MSVCR90.dll','malloc',self.recent)
    def test_valid(self):self.assertEqual(self.prove()['call_form'],'conditional_null_pointer_iat_fallback')
    def test_missing_trace(self):self.recent=[];self.assertIsNone(self.prove())
    def test_wrong_branch(self):self.recent[-1]=THUNK+12;self.assertIsNone(self.prove())
    def test_nonnull_fallback(self):self.live[PTR]=1;self.assertIsNone(self.prove())
    def test_changed_code(self):self.live[THUNK+10]=0x75;self.assertIsNone(self.prove())
    def test_wrong_import(self):self.iat[IAT]=('msvcr90.dll','calloc');self.assertIsNone(self.prove())
    def test_wrong_target(self):self.live[IAT]^=1;self.assertIsNone(self.prove())
    def test_outside_exec(self):self.pe.sections=[];self.assertIsNone(self.prove())
if __name__=='__main__':unittest.main()
