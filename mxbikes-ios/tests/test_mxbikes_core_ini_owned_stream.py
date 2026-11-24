"""Source-only read-only core.ini guest-CRT and safe owned ZIP extraction tests.

All content is synthetic fixture text; no proprietary game bytes included.
"""
import importlib.util
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/"scripts"))
from mxbikes_owned_file_crt import (
    CORE_INI_HANDLE,FILE_HANDLE,OwnedReadOnlyFile,ReadOnlyCRT,GuestServiceBlocked,
)
source=ROOT/"scripts"/"mxbikes_run_owned_local.py"
spec=importlib.util.spec_from_file_location("mxb_local_core_ini_fixture",source)
local=importlib.util.module_from_spec(spec)
spec.loader.exec_module(local)

class FakeGuest:
    NAME=0x1000
    MODE=0x1100
    BUFFER=0x1200
    def __init__(self,name=b"core.ini",mode=b"rb"):
        self.contents={
            self.NAME:name+bytes((0,)),
            self.MODE:mode+bytes((0,)),
        }
        self.writes=[]
    def mem_read(self,p,n):
        for base,data in self.contents.items():
            if base<=p and p+n<=base+len(data):
                return data[p-base:p-base+n]
        raise ValueError("unmapped guest")
    def mem_write(self,p,b):
        self.writes.append((p,bytes(b)))

def core_service():
    steam=OwnedReadOnlyFile(b"steam-synthetic",handle=FILE_HANDLE,
                             filename="steam_api64.dll",open=False)
    core=OwnedReadOnlyFile(b"synthetic-core-file",handle=CORE_INI_HANDLE,
                            filename="core.ini",open=False)
    return ReadOnlyCRT(steam,{"core.ini":core}),steam,core

class CoreIniOwnedGuestTests(unittest.TestCase):
    def test_exact_original_core_ini_file_open_read_seek_close(self):
        crt,steam,core=core_service()
        uc=FakeGuest()
        handle=crt.dispatch(uc,"fopen",uc.NAME,uc.MODE,0,0)
        self.assertEqual(handle,CORE_INI_HANDLE)
        self.assertTrue(core.open)
        self.assertFalse(steam.open)
        n=crt.dispatch(uc,"fread",uc.BUFFER,1,9,handle)
        self.assertEqual(n,9)
        self.assertEqual(uc.writes,[(uc.BUFFER,b"synthetic")])
        self.assertEqual(crt.dispatch(uc,"ftell",handle,0,0,0),9)
        self.assertEqual(crt.dispatch(uc,"fseek",handle,0,0,0),0)
        self.assertEqual(crt.dispatch(uc,"fgetc",handle,0,0,0),ord("s"))
        self.assertEqual(crt.dispatch(uc,"fclose",handle,0,0,0),0)
        self.assertFalse(core.open)
        self.assertFalse(steam.open)
        self.assertEqual(crt.bytes_returned,9)

    def test_unknown_stream_or_write_modes_are_not_opened(self):
        crt,steam,core=core_service()
        for name,mode in ((b"core.ini",b"wb"),(b"no-such-file.txt",b"rb"),
                          (b"C:/other.ini",b"rb")):
            u=FakeGuest(name,mode)
            with self.assertRaises(GuestServiceBlocked):
                crt.dispatch(u,"fopen",u.NAME,u.MODE,0,0)
        with self.assertRaises(GuestServiceBlocked):
            crt.dispatch(FakeGuest(),"fread",FakeGuest.BUFFER,1,4,0xdead)
        self.assertFalse(core.open)
        self.assertFalse(steam.open)

    def test_steam_file_legacy_open_still_separate(self):
        crt,steam,core=core_service()
        u=FakeGuest(b"steam_api64.dll",b"rb")
        self.assertEqual(crt.dispatch(u,"fopen",u.NAME,u.MODE,0,0),FILE_HANDLE)
        self.assertTrue(steam.open)
        self.assertFalse(core.open)
        with self.assertRaises(GuestServiceBlocked):
            crt.dispatch(u,"fopen",u.NAME,u.MODE,0,0)
        self.assertEqual(crt.dispatch(u,"fclose",FILE_HANDLE,0,0,0),0)

    def test_ownership_file_validation_rejects_wrong_size_and_symlink(self):
        with tempfile.TemporaryDirectory() as folder:
            p=Path(folder)
            core=p/"core.ini"
            core.write_bytes(b"AB")
            owned=OwnedReadOnlyFile.from_private_path(
                core,2,filename="core.ini",handle=CORE_INI_HANDLE,
                initially_open=False)
            self.assertEqual(owned.content,b"AB")
            self.assertFalse(owned.open)
            with self.assertRaises(GuestServiceBlocked):
                OwnedReadOnlyFile.from_private_path(core,3)
            symlink=p/"indirect.ini"
            symlink.symlink_to(core)
            with self.assertRaises(GuestServiceBlocked):
                OwnedReadOnlyFile.from_private_path(symlink,2)

    def test_zip_source_must_have_exact_root_core_ini_and_safe_size(self):
        with tempfile.TemporaryDirectory() as folder:
            p=Path(folder)
            archive=p/"game.zip"
            with zipfile.ZipFile(archive,"w") as z:
                z.writestr("core.ini",b"hello\n")
            with zipfile.ZipFile(archive) as z:
                entry=local.optional_owned_core_ini(z)
                self.assertEqual(entry.file_size,6)
                local.bounded_extract(z,entry,p/"core.ini")
            self.assertEqual((p/"core.ini").read_bytes(),b"hello\n")
            with zipfile.ZipFile(archive,"w") as z:
                z.writestr("nested/core.ini",b"not-root")
            with zipfile.ZipFile(archive) as z:
                self.assertIsNone(local.optional_owned_core_ini(z))
            with zipfile.ZipFile(archive,"w") as z:
                z.writestr("core.ini",b"a")
                z.writestr("CORE.INI",b"b")
            with zipfile.ZipFile(archive) as z:
                with self.assertRaises(local.InputRejected):
                    local.optional_owned_core_ini(z)

if __name__=="__main__":
    unittest.main()
