"""Reusable exact-byte CRT read-only FILE* semantics; no imported DLL execution."""
import sys,unittest
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"scripts"))
from mxbikes_owned_file_crt import (
 OwnedReadOnlyFile,ReadOnlyCRT,GuestServiceBlocked,
 FILE_HANDLE,signed32,read_guest_cstring
)

class FakeGuest:
 def __init__(self):
    self.pages={}
 def mem_write(self,addr,data):
    for i,b in enumerate(data):
       if not 0x1000<=addr+i<0x3000:raise ValueError("unmapped")
       self.pages[addr+i]=b
 def mem_read(self,addr,size):
    if not 0x1000<=addr<0x3000 or addr+size>0x3000:
        raise ValueError("unmapped")
    return bytes(self.pages.get(addr+i,0) for i in range(size))

class CrtBatchTests(unittest.TestCase):
 def setUp(self):
    self.cpu=FakeGuest()
    self.file=OwnedReadOnlyFile(b"0123456789ABCDEF")
    self.crt=ReadOnlyCRT(self.file)
 def test_seek_tell_and_exact_bytes(self):
    f=self.crt.dispatch
    self.assertEqual(f(self.cpu,"fseek",FILE_HANDLE,0,2,0),0)
    self.assertEqual(f(self.cpu,"ftell",FILE_HANDLE,0,0,0),16)
    self.assertEqual(f(self.cpu,"fseek",FILE_HANDLE,0xfffffffc,1,0),0)
    self.assertEqual(f(self.cpu,"ftell",FILE_HANDLE,0,0,0),12)
    self.assertEqual(f(self.cpu,"fseek",FILE_HANDLE,0,0,0),0)
    self.assertEqual(f(self.cpu,"fread",0x1100,3,4,FILE_HANDLE),4)
    self.assertEqual(self.cpu.mem_read(0x1100,12),b"0123456789AB")
    self.assertEqual(f(self.cpu,"fread",0x1200,3,4,FILE_HANDLE),1)
    self.assertEqual(self.cpu.mem_read(0x1200,4),b"CDEF")
    self.assertEqual(self.crt.bytes_returned,16)
    self.assertEqual(f(self.cpu,"feof",FILE_HANDLE,0,0,0),1)
 def test_guest_pointer_permissions_and_unknown_services(self):
    with self.assertRaises(GuestServiceBlocked):
       self.crt.dispatch(self.cpu,"fread",0x999999,8,1,FILE_HANDLE)
    self.assertEqual(self.file.cursor,8)
    with self.assertRaises(GuestServiceBlocked):
       self.crt.dispatch(self.cpu,"SteamAPI_Init",0,0,0,0)
    with self.assertRaises(GuestServiceBlocked):
       self.crt.dispatch(self.cpu,"fseek",FILE_HANDLE+1,0,0,0)
    with self.assertRaises(GuestServiceBlocked):
       self.crt.dispatch(self.cpu,"fread",0x1100,0x100000,0x100000,FILE_HANDLE)
 def test_closed_stream_and_read_only_lifecycle(self):
    self.assertEqual(self.crt.dispatch(self.cpu,"fclose",FILE_HANDLE,0,0,0),0)
    with self.assertRaises(GuestServiceBlocked):
       self.crt.dispatch(self.cpu,"ftell",FILE_HANDLE,0,0,0)
    self.cpu.mem_write(0x1100,b"steam_api64.dll\x00")
    self.cpu.mem_write(0x1200,b"rb\x00")
    self.assertEqual(self.crt.dispatch(self.cpu,"fopen",0x1100,0x1200,0,0),FILE_HANDLE)
    self.assertEqual(self.crt.dispatch(self.cpu,"ftell",FILE_HANDLE,0,0,0),0)
    with self.assertRaises(GuestServiceBlocked):
       self.crt.dispatch(self.cpu,"fopen",0x1100,0x1200,0,0)
 def test_cstring_boundaries_and_signed_offset(self):
    self.assertEqual(signed32(0xffffffff),-1)
    self.assertEqual(signed32(0x80000000),-0x80000000)
    self.assertEqual(signed32(0x100000001),1)
    with self.assertRaises(GuestServiceBlocked):
       read_guest_cstring(self.cpu,0)
    self.cpu.mem_write(0x1100,b"file.bin\x00")
    self.assertEqual(read_guest_cstring(self.cpu,0x1100),"file.bin")
    self.cpu.mem_write(0x1200,b"\xff\x00")
    with self.assertRaises(GuestServiceBlocked):
       read_guest_cstring(self.cpu,0x1200)

if __name__=="__main__":
    unittest.main()
