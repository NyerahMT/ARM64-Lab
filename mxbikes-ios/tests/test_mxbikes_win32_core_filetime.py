"""Win64 FILETIME from owned core.ini archive metadata, with zero host API."""
import calendar,struct,sys,tempfile,unittest,zipfile
from pathlib import Path
from unittest.mock import patch
from unicorn.x86_const import (
    UC_X86_REG_RSP,UC_X86_REG_RAX,UC_X86_REG_RCX,
    UC_X86_REG_RDX,UC_X86_REG_R8,UC_X86_REG_R9,
)
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"scripts"))
from mxbikes_win32_owned_core_ini import (
    IMAGE_BASE,CORE_INI_WIN32_HANDLE,CREATEFILEA_ORIGINAL_CALL_RVA,
    CREATEFILEA_ORIGINAL_RETURN_RVA,GETFILETIME_ORIGINAL_CALL_RVA,
    GETFILETIME_ORIGINAL_RETURN_RVA,OwnedCoreIniWin32Research,
    CoreIniWin32Rejected,GENERIC_READ,FILE_SHARE_READ,
)
import mxbikes_run_owned_local as owned

FILETIME=calendar.timegm((2026,6,8,3,2,4,0,0,0))*10_000_000+116444736000000000

class FakeCPU:
    PATH=0x710010000
    OUT=0x710020000
    STACK=0x710030008
    def __init__(self,*,write_output=OUT,creation=0,access=0,
                 handle=CORE_INI_WIN32_HANDLE,
                 ret=IMAGE_BASE+GETFILETIME_ORIGINAL_RETURN_RVA,
                 mapped=True):
        self.regs={
            UC_X86_REG_RSP:self.STACK,
            UC_X86_REG_RCX:handle,UC_X86_REG_RDX:creation,
            UC_X86_REG_R8:access,UC_X86_REG_R9:write_output,UC_X86_REG_RAX:0xBAD,
        }
        self.ret=ret;self.mapped=mapped;self.writes=[]
    def reg_read(self,r):return self.regs[r]
    def reg_write(self,r,v):self.regs[r]=v
    def mem_read(self,ptr,n):
        if ptr==self.STACK and n==8:return struct.pack("<Q",self.ret)
        if ptr==self.OUT and n==8 and self.mapped:return bytes(8)
        raise ValueError("unmapped")
    def mem_write(self,ptr,buffer):self.writes.append((ptr,bytes(buffer)))

def verified(_,return_pc,lib,symbol,slots):
    if slots.get("ok") and return_pc==IMAGE_BASE+GETFILETIME_ORIGINAL_RETURN_RVA and lib.lower()=="kernel32.dll" and symbol=="GetFileTime":
        return hex(GETFILETIME_ORIGINAL_CALL_RVA)
    return None

def opened():
    bridge=OwnedCoreIniWin32Research(b"synthetic",last_write_filetime_100ns=FILETIME)
    bridge.calls=[{"original_call_rva":hex(CREATEFILEA_ORIGINAL_CALL_RVA)}]
    bridge.open=True
    return bridge

class OriginalCoreIniFileTimeTests(unittest.TestCase):
    def test_last_write_only_returns_real_archive_derived_filetime(self):
        cpu=FakeCPU();bridge=opened()
        self.assertTrue(bridge.handle_getfiletime(
            cpu,None,{"ok":True},"KERNEL32.dll","GetFileTime",verified))
        self.assertEqual(cpu.writes,[(cpu.OUT,struct.pack("<Q",FILETIME))])
        self.assertEqual(cpu.reg_read(UC_X86_REG_RAX),1)
        self.assertEqual(bridge.summary()["original_core_ini_win32_getfiletime_count"],1)
        self.assertFalse(bridge.summary()["original_core_ini_win32_getfiletime_calls"][0]["creation_or_access_time_supplied"])
        with self.assertRaisesRegex(CoreIniWin32Rejected,"budget"):
            bridge.handle_getfiletime(
                cpu,None,{"ok":True},"KERNEL32.dll","GetFileTime",verified)

    def test_wrong_abi_or_unmapped_output_fails_without_memory_write(self):
        for cpu,slots in (
            (FakeCPU(creation=0x1100),{"ok":True}),
            (FakeCPU(access=0x1100),{"ok":True}),
            (FakeCPU(write_output=0),{"ok":True}),
            (FakeCPU(write_output=FakeCPU.OUT+1),{"ok":True}),
            (FakeCPU(handle=0xdead),{"ok":True}),
            (FakeCPU(ret=IMAGE_BASE+GETFILETIME_ORIGINAL_RETURN_RVA+1),{"ok":True}),
            (FakeCPU(mapped=False),{"ok":True}),
            (FakeCPU(),{}),
        ):
            bridge=opened()
            with self.assertRaises(CoreIniWin32Rejected):
                bridge.handle_getfiletime(
                    cpu,None,slots,"KERNEL32.dll","GetFileTime",verified)
            self.assertEqual(cpu.reg_read(UC_X86_REG_RAX),0xBAD)
            self.assertEqual(cpu.writes,[])

    def test_file_must_be_open_and_real_metadata_available(self):
        cpu=FakeCPU()
        bridge=OwnedCoreIniWin32Research(b"synthetic",last_write_filetime_100ns=FILETIME)
        with self.assertRaises(CoreIniWin32Rejected):
            bridge.handle_getfiletime(
                cpu,None,{"ok":True},"KERNEL32.dll","GetFileTime",verified)
        bridge=opened();bridge.last_write_filetime_100ns=None
        with self.assertRaisesRegex(CoreIniWin32Rejected,"metadata_not_available"):
            bridge.handle_getfiletime(
                cpu,None,{"ok":True},"KERNEL32.dll","GetFileTime",verified)

    def test_private_zip_extract_preserves_utc_assumed_archive_filetime(self):
        with tempfile.TemporaryDirectory() as root:
            p=Path(root);z=p/"original.zip";dest=p/"extracted";dest.mkdir()
            with zipfile.ZipFile(z,"w") as handle:
                for name,data in (
                    ("mxbikes.exe",b"synthetic executable"),
                    ("steam_api64.dll",b"synthetic library"),
                    ("core.ini",b"synthetic settings")):
                    entry=zipfile.ZipInfo(name,date_time=(2026,6,8,3,2,4))
                    handle.writestr(entry,data)
            with patch.object(owned,"validate_owned_pair",return_value={"synthetic":True}):
                exe,dll=owned.extract_owned_archive(z,dest)
            self.assertTrue(exe.is_file())
            self.assertTrue(dll.is_file())
            ini=dest/"core.ini"
            self.assertEqual(ini.read_bytes(),b"synthetic settings")
            expected_ns=calendar.timegm((2026,6,8,3,2,4,0,0,0))*1_000_000_000
            self.assertEqual(ini.stat().st_mtime_ns,expected_ns)

if __name__=="__main__":
    unittest.main()
