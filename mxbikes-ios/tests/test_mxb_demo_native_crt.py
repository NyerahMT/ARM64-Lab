"""Native bridge integration checks; no game executable or Unicorn needed."""
import unittest,struct,sys,tempfile,subprocess,shutil
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/"scripts"))
from mxb_demo_native_crt import NativeCRT
B=0x140000000
class T(unittest.TestCase):
 @classmethod
 def setUpClass(cls):
  if not shutil.which("cc"):raise unittest.SkipTest("C compiler unavailable")
  cls.tmp=tempfile.TemporaryDirectory()
  cls.library=Path(cls.tmp.name)/"crt.so"
  subprocess.run(["cc","-shared","-fPIC","-O2","-Wall","-Wextra","-Werror",
                  str(ROOT/"runtime"/"mxb_standalone_crt.c"),"-o",str(cls.library)],check=True)
 @classmethod
 def tearDownClass(cls):cls.tmp.cleanup()
 def setUp(self):
  self.crt=NativeCRT(self.library);self.m=bytearray(512);self.writes=[];self.m[48:56]=struct.pack('<Q',B+80)
 def read(self,p,n):
  if not B<=p<=p+n<=B+len(self.m):raise ValueError('unmapped')
  return self.m[p-B:p-B+n]
 def write(self,p,d):
  self.writes.append((p,d));self.m[p-B:p-B+len(d)]=d
 def call(self,n,a=0,b=0,c=0,d=0):
  return self.crt.dispatch(n,(a,b,c,d),read=self.read,write=self.write,writable=[(B+128,B+512)],rsp=B+8,executable=[(B+0x1000,B+0x1100)],rax=99)
 def test_data(self):
  self.assertEqual(self.crt.data_address('MSVCR90.DLL','_fmode'),0x760000010)
  self.assertIsNone(self.crt.data_address('other.dll','_fmode'))
  page=self.crt.data_page(B+1000,B+2000,b'mxbikes.exe\0');self.assertEqual(len(page),4096);self.assertEqual(page[256:268],b'mxbikes.exe\0')
 def test_args(self):
  self.assertEqual(self.call('__getmainargs',B+128,B+136,B+144),0)
  self.assertEqual(struct.unpack_from('<I',self.m,128)[0],1)
  self.assertEqual(struct.unpack_from('<Q',self.m,136)[0],0x760000040)
  self.assertEqual(struct.unpack_from('<Q',self.m,144)[0],0x760000060)
 def test_invalid_atomic(self):
  for args in [(B+128,B+130,B+144,0),(B+128,B+136,B+508,0),(B+128,B+136,B+144,1)]:
   with self.assertRaises(ValueError):self.call('__getmainargs',*args)
  self.assertEqual(self.writes,[])
 def test_pointer(self):
  for p in [0,1,2**64-1,B+0x1000]:self.assertEqual(self.call('_decode_pointer',self.call('_encode_pointer',p)),p)
 def test_onexit(self):
  self.assertEqual(self.call('_onexit',B+0x1000),B+0x1000)
  with self.assertRaises(ValueError):self.call('_onexit',B+128)
  self.assertEqual(self.crt.exit_count,1)
 def test_lead(self):
  self.assertEqual(self.call('_ismbblead',65),0)
  with self.assertRaises(ValueError):self.call('_ismbblead',129)
 def test_app_locale(self):
  self.assertEqual(self.call('__set_app_type',2),99);self.assertEqual(self.crt.app_type,2)
  self.assertEqual(self.call('_configthreadlocale',1),2);self.assertEqual(self.crt.locale_mode,1)
 def test_read_exception(self):
  self.m[48:56]=struct.pack('<Q',B+1000)
  with self.assertRaises(ValueError):self.call('__getmainargs',B+128,B+136,B+144)
  self.assertEqual(self.writes,[])
if __name__=='__main__':unittest.main()
