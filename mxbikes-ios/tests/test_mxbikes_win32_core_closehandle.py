"""One exact original Win64 CloseHandle call for owned core.ini guest handle."""
import struct,sys,unittest
from pathlib import Path
from unicorn.x86_const import UC_X86_REG_RSP,UC_X86_REG_RCX,UC_X86_REG_RAX
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"scripts"))
from mxbikes_win32_owned_core_ini import (
    OwnedCoreIniWin32Research,CoreIniWin32Rejected,IMAGE_BASE,
    CORE_INI_WIN32_HANDLE,CLOSEHANDLE_ORIGINAL_CALL_RVA,
    CLOSEHANDLE_ORIGINAL_RETURN_RVA,
)
class CPU:
    STACK=0x750010008
    def __init__(self,*,handle=CORE_INI_WIN32_HANDLE,ret=IMAGE_BASE+CLOSEHANDLE_ORIGINAL_RETURN_RVA,
                 stack=STACK):
        self.ret=ret
        self.regs={UC_X86_REG_RSP:stack,UC_X86_REG_RCX:handle,UC_X86_REG_RAX:0xBADD}
    def reg_read(self,r):return self.regs[r]
    def reg_write(self,r,v):self.regs[r]=v
    def mem_read(self,p,n):
        if p==self.regs[UC_X86_REG_RSP] and n==8:return struct.pack("<Q",self.ret)
        raise ValueError("unmapped")
def verified(_,ret,lib,symbol,slots):
    if (slots.get("ok") and ret==IMAGE_BASE+CLOSEHANDLE_ORIGINAL_RETURN_RVA
        and lib.lower()=="kernel32.dll" and symbol=="CloseHandle"):
        return hex(CLOSEHANDLE_ORIGINAL_CALL_RVA)
    return None
def ready():
    b=OwnedCoreIniWin32Research(b"synthetic",last_write_filetime_100ns=133333333333333333)
    b.open=True
    b.calls=[{"created":True}]
    b.filetime_calls=[{"last_write_time_supplied":True}]
    return b
class OriginalOwnedCoreCloseTests(unittest.TestCase):
    def test_closes_only_original_core_handle_after_filetime(self):
        b=ready();c=CPU()
        self.assertTrue(b.handle_closehandle(
            c,None,{"ok":True},"KERNEL32.dll","CloseHandle",verified))
        self.assertFalse(b.open)
        self.assertEqual(c.reg_read(UC_X86_REG_RAX),1)
        self.assertEqual(b.summary()["original_core_ini_win32_closehandle_count"],1)
        self.assertTrue(b.summary()["original_core_ini_win32_closehandle_calls"][0]
                        ["only_owned_core_ini_guest_handle_closed"])
        with self.assertRaisesRegex(CoreIniWin32Rejected,"order_or_budget"):
            b.handle_closehandle(
                c,None,{"ok":True},"KERNEL32.dll","CloseHandle",verified)
    def test_bad_guest_handle_import_or_order_never_closes(self):
        for cpu,slots in (
            (CPU(handle=0x730050000),{"ok":True}),
            (CPU(handle=0),{"ok":True}),
            (CPU(ret=IMAGE_BASE+CLOSEHANDLE_ORIGINAL_RETURN_RVA+1),{"ok":True}),
            (CPU(stack=0x750010000),{"ok":True}),
            (CPU(),{}),
        ):
            b=ready()
            with self.assertRaises(CoreIniWin32Rejected):
                b.handle_closehandle(
                    cpu,None,slots,"KERNEL32.dll","CloseHandle",verified)
            self.assertTrue(b.open)
            self.assertEqual(cpu.reg_read(UC_X86_REG_RAX),0xBADD)
        b=ready();b.filetime_calls=[]
        with self.assertRaises(CoreIniWin32Rejected):
            b.handle_closehandle(
                CPU(),None,{"ok":True},"KERNEL32.dll","CloseHandle",verified)
        self.assertTrue(b.open)
if __name__=="__main__":
    unittest.main()
