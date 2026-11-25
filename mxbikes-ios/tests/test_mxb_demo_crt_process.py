import struct
import unittest
import sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"scripts"))
from mxb_demo_crt_process import *

class Tests(unittest.TestCase):
    def setUp(self):
        self.p=Process();self.writes=[];self.mem={1040:struct.pack('<Q',2000),2000:bytes(4)}
    def call(self,name,args):
        return self.p.dispatch(name,args,read=lambda p,n:self.mem[p],write=lambda p,d:self.writes.append((p,d)),writable=[(3000,3100)],rsp=1000)
    def test_page(self):
        data=data_page(10,20,b'mxbikes.exe\0')
        self.assertEqual(struct.unpack_from('<QQII',data),(10,20,0x4000,0))
        self.assertEqual(struct.unpack_from('<QQ',data,0x40),(ARGV0,0))
        self.assertEqual(struct.unpack_from('<Q',data,0x60),(0,))
        self.assertEqual(data[0x100:0x10c],b'mxbikes.exe\0')
        self.assertEqual(data_address('MSVCR90.dll','_fmode'),CRT_DATA+16)
        self.assertIsNone(data_address('other.dll','_fmode'))
    def test_invalid_page(self):
        with self.assertRaises(ValueError):data_page(0,20,b'x\0')
    def test_app_and_locale(self):
        self.assertIsNone(self.call('__set_app_type',(0x123400000002,0,0,0)))
        self.assertEqual(self.p.app_type,2)
        self.assertEqual(self.call('_configthreadlocale',(1,0,0,0)),2)
        self.assertEqual(self.call('_configthreadlocale',(0,0,0,0)),1)
        self.assertEqual(self.call('_configthreadlocale',(2,0,0,0)),1)
    def test_invalid_locale(self):
        with self.assertRaises(ValueError):self.call('_configthreadlocale',(3,0,0,0))
        self.assertEqual(self.p.locale_mode,2)
    def test_arguments(self):
        self.assertEqual(self.call('__getmainargs',(3000,3008,3016,0)),0)
        self.assertEqual(self.writes,[(3000,struct.pack('<I',1)),(3008,struct.pack('<Q',ARGV)),(3016,struct.pack('<Q',ENVP))])
    def test_bad_outputs_atomic(self):
        for args in [(3000,3002,3016,0),(3000,3008,3096,0),(3000,3008,3016,1)]:
            with self.assertRaises(ValueError):self.call('__getmainargs',args)
        self.assertEqual(self.writes,[])
    def test_newmode(self):
        self.mem[2000]=struct.pack('<I',1)
        with self.assertRaises(ValueError):self.call('__getmainargs',(3000,3008,3016,0))
        self.assertEqual(self.writes,[])

if __name__=='__main__':unittest.main()
