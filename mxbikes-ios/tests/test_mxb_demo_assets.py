"""Host streaming integration: uses sparse fixtures, never game assets."""
import ctypes as C
import hashlib
import os
import struct
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/"scripts"))
from mxb_demo_assets import AssetMounts,Files,MAX_SIZE
B=0x140000000
Read=C.CFUNCTYPE(C.c_int,C.c_void_p,C.c_uint64,C.c_void_p,C.c_size_t)
Check=C.CFUNCTYPE(C.c_int,C.c_void_p,C.c_uint64,C.c_size_t)
Write=C.CFUNCTYPE(None,C.c_void_p,C.c_uint64,C.c_void_p,C.c_size_t)
Exec=C.CFUNCTYPE(C.c_int,C.c_void_p,C.c_uint64)
class Memory(C.Structure):
    _fields_=[("ctx",C.c_void_p),("read",Read),("writable",Check),("write",Write),("executable",Exec)]
class Regs(C.Structure):
    _fields_=[(x,C.c_uint64) for x in ("rcx","rdx","r8","r9","rsp","rax")]
class Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp=tempfile.TemporaryDirectory();cls.root=Path(cls.tmp.name)
        lib=cls.root/"files.so"
        subprocess.run(["cc","-shared","-fPIC","-O2","-Wall","-Wextra","-Werror",str(ROOT/"runtime/mxb_standalone_files.c"),"-o",str(lib)],check=True)
        cls.lib=C.CDLL(str(lib));cls.lib.mxb_files_dispatch.argtypes=[C.POINTER(Files),C.POINTER(Memory),C.c_char_p,C.POINTER(Regs)];cls.lib.mxb_files_dispatch.restype=C.c_int
        cls.large=cls.root/"tracks.pkz";cls.size=1751015009
        with cls.large.open("wb") as f:f.seek(cls.size-8);f.write(b"abcdefgh")
        cls.small=cls.root/"core.ini";cls.small.write_bytes(b"one\ntwo")
    @classmethod
    def tearDownClass(cls):cls.tmp.cleanup()
    def setUp(self):
        self.files=Files();self.mount=AssetMounts(self.lib,self.files);self.data=bytearray(65536)
        self.addCleanup(self.mount.close)
        self.callbacks=[Read(self.read),Check(self.valid),Write(self.write),Exec(lambda *_:0)]
        self.mem=Memory(None,*self.callbacks)
    def valid(self,_,p,n):return int(B<=p<=p+n<=B+len(self.data))
    def read(self,_,p,o,n):
        if not self.valid(_,p,n):return 0
        C.memmove(o,bytes(self.data[p-B:p-B+n]),n);return 1
    def write(self,_,p,o,n):self.data[p-B:p-B+n]=C.string_at(o,n)
    def call(self,name,*args,status=1):
        r=Regs(*(list(args)+[0]*(4-len(args))),B+8,99)
        self.assertEqual(self.lib.mxb_files_dispatch(C.byref(self.files),C.byref(self.mem),name.encode(),C.byref(r)),status)
        return r.rax
    def fopen(self,name):
        self.data[0:len(name)+1]=name.encode()+b"\0";self.data[128:131]=b"rb\0";return self.call("fopen",B,B+128)
    def test_sparse_asset(self):
        self.mount.mount_path(self.large,expected_size=self.size)
        h=self.fopen("TRACKS.PKZ");self.assertTrue(h)
        self.assertEqual(self.call("fseek",h,(-8)&0xffffffff,2),0)
        self.assertEqual(self.call("ftell",h),self.size-8)
        self.assertEqual(self.call("fread",B+512,1,12,h),8)
        self.assertEqual(self.data[512:520],b"abcdefgh")
        self.assertEqual(self.call("feof",h),1)
        self.assertEqual(self.call("fclose",h),0)
    def test_stream_multiple_chunks(self):
        self.mount.mount_path(self.large);h=self.fopen("tracks.pkz")
        self.assertEqual(self.call("fread",B+512,1,50000,h),50000)
        self.assertEqual(self.data[512:50512],bytes(50000))
    def test_small_digest(self):
        self.mount.mount_path(self.small,expected_sha=hashlib.sha256(b"one\ntwo").hexdigest())
        h=self.fopen("core.ini");self.assertEqual(self.call("fgets",B+512,10,h),B+512)
        self.assertEqual(self.data[512:517],b"one\n\0")
        self.assertEqual(self.call("fgetc",h),ord('t'))
    def test_reject_mismatch(self):
        with self.assertRaises(ValueError):self.mount.mount_path(self.small,expected_sha="0"*64)
        with self.assertRaises(ValueError):self.mount.mount_path(self.small,expected_size=0)
        self.assertEqual(self.mount.count,0)
    def test_duplicate_and_close(self):
        self.mount.mount_path(self.small)
        with self.assertRaises(ValueError):self.mount.mount_bytes("CORE.INI",b"x")
        h=self.fopen("core.ini");self.mount.close()
        self.call("ftell",h,status=-1)
        with self.assertRaises(ValueError):self.mount.mount_path(self.small)
    def test_reopened_session_stale_handle(self):
        self.mount.mount_path(self.small);h=self.fopen("core.ini");self.mount.close()
        self.mount=AssetMounts(self.lib,self.files);self.addCleanup(self.mount.close)
        self.mount.mount_path(self.small);h2=self.fopen("core.ini")
        self.assertNotEqual(h,h2);self.call("ftell",h,status=-1)
    def test_truncated_backing(self):
        path=self.root/"truncated.pkz";path.write_bytes(b"1234")
        self.mount.mount_path(path);h=self.fopen("truncated.pkz");path.write_bytes(b"1")
        self.assertEqual(self.call("fread",B+512,1,4,h),0)
        self.assertEqual(self.call("ferror",h),1);self.assertEqual(self.call("feof",h),0)
        self.assertEqual(self.call("clearerr",h),99);self.assertEqual(self.call("ferror",h),0)
    def test_invalid_guest_output(self):
        self.mount.mount_bytes("test.ini",b"abc");h=self.fopen("test.ini")
        self.call("fread",B+65535,1,3,h,status=-1);self.assertEqual(self.call("ftell",h),0)
    def test_directory_rejects_unverified_executable(self):
        with tempfile.TemporaryDirectory() as d:
            Path(d,"mxbikes.exe").write_bytes(b"not beta21e")
            with self.assertRaises(ValueError):self.mount.mount_demo_directory(d)
            self.assertEqual(self.mount.count,0)
    def test_symlink(self):
        if not hasattr(os,"O_NOFOLLOW"):self.skipTest("no nofollow")
        p=self.root/"alias.ini";p.symlink_to(self.small)
        with self.assertRaises(OSError):self.mount.mount_path(p)
if __name__=="__main__":unittest.main()
