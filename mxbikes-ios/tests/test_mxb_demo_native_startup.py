"""Host integration tests for the native startup service dispatcher."""
import os, struct, subprocess, tempfile, unittest, sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"scripts"))
from mxb_demo_native_startup import NativeStartup, HEAP_BASE, HEAP_CAP
B=0x140000000
class Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp=tempfile.TemporaryDirectory();cls.lib=Path(cls.tmp.name)/"startup.so"
        root=Path(os.environ.get("MXB_RUNTIME",Path(__file__).resolve().parents[1]/"runtime"))
        subprocess.run(["cc","-shared","-fPIC","-O2","-Wall","-Wextra","-Werror",
          *[str(root/f"mxb_standalone_{n}.c") for n in ("crt","platform","imports","heap","memory","winsock","format","files")],"-o",str(cls.lib)],check=True)
    @classmethod
    def tearDownClass(cls):cls.tmp.cleanup()
    def setUp(self):
        self.p=NativeStartup(self.lib,B);self.mem=bytearray(1024);self.heap=bytearray(256);self.writes=[]
    def read(self,p,n):
        if not B<=p<=p+n<=B+len(self.mem):raise ValueError("unmapped")
        return self.mem[p-B:p-B+n]
    def write(self,p,d):
        self.writes.append((p,d))
        if HEAP_BASE<=p<HEAP_BASE+len(self.heap):self.heap[p-HEAP_BASE:p-HEAP_BASE+len(d)]=d
        else:self.mem[p-B:p-B+len(d)]=d
    def call(self,d,n,a=0,b=0,c=0,e=0):
        return self.p.dispatch_import(d,n,(a,b,c,e),read=self.read,write=self.write,
             writable=[(B+128,B+1024),(HEAP_BASE,HEAP_BASE+len(self.heap))],rsp=B+8,executable=[(B+0x1000,B+0x1100)],rax=99)
    def k(self,n,*args):return self.call("KERNEL32.dll",n,*args)
    def test_module(self):
        self.assertEqual(self.k("GetModuleFileNameA",0,B+128,260),27)
        self.assertEqual(self.mem[128:156],b"C:\\MXBReference\\mxbikes.exe\0")
    def test_directory(self):
        self.mem[32:36]=b"c:/\0";self.assertEqual(self.k("SetCurrentDirectoryA",B+32),1)
        self.assertEqual(self.k("GetCurrentDirectoryA",3,B+128),4)
        self.assertEqual(self.writes,[])
        self.assertEqual(self.k("GetCurrentDirectoryA",4,B+128),3)
        self.assertEqual(self.mem[128:132],b"C:\\\0")
    def test_error(self):
        self.mem[32:43]=b"C:\\missing\0";self.assertEqual(self.k("SetCurrentDirectoryA",B+32),0)
        self.assertEqual(self.k("GetLastError"),3)
        self.assertEqual(self.k("SetLastError",0xabcd00000007),99)
        self.assertEqual(self.k("GetLastError"),7)
    def test_string(self):
        self.mem[32:37]=b"a:b:\0";self.assertEqual(self.call("msvcr90.dll","strcpy",B+128,B+32),B+128)
        self.assertEqual(self.call("msvcr90.dll","strrchr",B+128,ord(":")),B+131)
        self.assertEqual(self.call("msvcr90.dll","strrchr",B+128,0),B+132)
    def test_clock(self):
        self.p.advance_to_instruction(2999);self.assertEqual(self.k("GetTickCount"),0x9abc+2)
        self.p.advance_to_instruction(3000);self.assertEqual(self.call("winmm.dll","timeGetTime"),0x9abc+3)
        with self.assertRaises(ValueError):self.p.advance_to_instruction(2000)
    def test_timer(self):
        self.assertEqual(self.call("winmm.dll","timeBeginPeriod",1),0)
        self.assertEqual(self.p.startup.platform.timer_refs,1)
        self.assertEqual(self.call("winmm.dll","timeEndPeriod",1),0)
        self.assertEqual(self.call("winmm.dll","timeEndPeriod",1),97)
    def test_invalid_atomic(self):
        with self.assertRaises(ValueError):self.k("GetModuleFileNameA",0,B+1010,260)
        with self.assertRaises(ValueError):self.call("msvcr90.dll","strcpy",B+128,B+1024)
        self.assertEqual(self.writes,[])
    def test_crt_and_registration(self):
        self.assertEqual(self.call("msvcr90.dll","__set_app_type",2),99)
        self.assertEqual(self.p.app_type,2)
        self.assertEqual(self.k("SetUnhandledExceptionFilter",B+0x1000),0)
        with self.assertRaises(ValueError):self.k("SetUnhandledExceptionFilter",B+32)
        self.assertEqual(self.k("SetUnhandledExceptionFilter",0),B+0x1000)
        self.assertFalse(self.p.supports("steam_api64.dll","SteamAPI_Init"))
    def test_heap(self):
        self.heap[0]=255
        a=self.call("msvcr90.dll","malloc",8);self.assertEqual(a,HEAP_BASE)
        self.assertEqual(self.heap[0],255)
        self.assertEqual(self.call("msvcr90.dll","free",a),99)
        with self.assertRaises(ValueError):self.call("msvcr90.dll","free",a)
        self.assertEqual(self.call("msvcr90.dll","calloc",1,8),a)
        self.assertEqual(self.heap[:16],bytes(16))
        self.assertEqual(self.call("msvcr90.dll","malloc",HEAP_CAP+1),0)
    def test_memory(self):
        self.assertEqual(self.call("msvcr90.dll","memset",B+128,0x1234,32),B+128)
        self.assertEqual(self.mem[128:160],b"4"*32)
        self.mem[32:36]=b"abcd"
        self.assertEqual(self.call("msvcr90.dll","memcpy",B+256,B+32,4),B+256)
        self.assertEqual(self.call("msvcr90.dll","memmove",B+257,B+256,4),B+257)
        self.assertEqual(self.mem[256:261],b"aabcd")
        self.assertEqual(self.call("msvcr90.dll","memcmp",B+32,B+257,4),0)
    def test_winsock_lifecycle(self):
        self.assertEqual(self.call("WS2_32.dll","#115",2,B+256),0)
        self.assertEqual(self.p.startup.winsock.refs,1)
        self.assertEqual(self.mem[256:260],b"\x02\x00\x02\x02")
        self.assertEqual(self.call("ws2_32.dll","#116"),0)
        self.assertEqual(self.p.startup.winsock.refs,0)
        self.assertFalse(self.p.supports("WS2_32.dll","socket"))
    def test_loopback_resolution(self):
        self.mem[32:42]=b"localhost\0"
        self.assertEqual(self.call("WS2_32.dll","getaddrinfo",B+32,0,0,B+128),0)
        a=struct.unpack_from('<Q',self.mem,128)[0]
        self.assertEqual(a,HEAP_BASE)
        self.assertEqual(self.heap[52:56],b"\x7f\x00\x00\x01")
        self.assertEqual(self.call("WS2_32.dll","freeaddrinfo",a),99)
        with self.assertRaises(ValueError):self.call("WS2_32.dll","freeaddrinfo",a)
    def test_format(self):
        self.mem[32:41]=b"%lu.%lu\0"
        self.assertEqual(self.call("MSVCR90.dll","sprintf",B+128,B+32,127,1),5)
        self.assertEqual(self.mem[128:134],b"127.1\0")
    def test_mounted_file(self):
        self.p.mount_asset("fixture.ini",b"a=1\nb=2")
        self.mem[32:44]=b"fixture.ini\0";self.mem[64:67]=b"rb\0"
        h=self.call("MSVCR90.dll","fopen",B+32,B+64)
        self.assertEqual(self.call("MSVCR90.dll","fgets",B+128,20,h),B+128)
        self.assertEqual(self.mem[128:133],b"a=1\n\0")
        self.assertEqual(self.call("MSVCR90.dll","ftell",h),4)
        self.assertEqual(self.call("MSVCR90.dll","fread",B+128,1,3,h),3)
        self.assertEqual(self.mem[128:131],b"b=2")
        self.assertEqual(self.call("MSVCR90.dll","fclose",h),0)
        with self.assertRaises(ValueError):self.call("MSVCR90.dll","ftell",h)
    def test_mount_rejection(self):
        with self.assertRaises(ValueError):self.p.mount_asset("../file",b"x")
        self.mem[32:44]=b"missing.ini\0";self.mem[64:67]=b"rb\0"
        with self.assertRaises(ValueError):self.call("MSVCR90.dll","fopen",B+32,B+64)
if __name__=="__main__":unittest.main()
