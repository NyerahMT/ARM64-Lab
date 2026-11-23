"""Win64 CreateFileA guest ABI for original owned core.ini, synthetic fixtures."""
import struct,sys,unittest
from pathlib import Path
from unicorn.x86_const import (
    UC_X86_REG_RSP,UC_X86_REG_RAX,UC_X86_REG_RCX,
    UC_X86_REG_RDX,UC_X86_REG_R8,UC_X86_REG_R9,
)
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"scripts"))
from mxbikes_win32_owned_core_ini import (
    IMAGE_BASE,CORE_INI_WIN32_HANDLE,CREATEFILEA_ORIGINAL_CALL_RVA,
    CREATEFILEA_ORIGINAL_RETURN_RVA,OwnedCoreIniWin32Research,
    CoreIniWin32Rejected,GENERIC_READ,FILE_SHARE_READ,OPEN_EXISTING,
)

class Guest:
    NAME=0x770050000
    STACK=0x770060008
    def __init__(self,*,name=b"core.ini",access=GENERIC_READ,
                 share=FILE_SHARE_READ,security=0,creation=OPEN_EXISTING,
                 flags=0,template=0,return_pc=IMAGE_BASE+CREATEFILEA_ORIGINAL_RETURN_RVA,
                 stack=STACK):
        self.name=name+bytes((0,))
        self.return_pc=return_pc
        self.stack_args=(creation,flags,template)
        self.regs={
            UC_X86_REG_RSP:stack,UC_X86_REG_RAX:0xBADD,
            UC_X86_REG_RCX:self.NAME,UC_X86_REG_RDX:access,
            UC_X86_REG_R8:share,UC_X86_REG_R9:security,
        }
        self.writes=[]
    def reg_read(self,r):return self.regs[r]
    def reg_write(self,r,v):self.regs[r]=v
    def mem_read(self,ptr,n):
        if ptr==self.regs[UC_X86_REG_RSP] and n==8:
            return struct.pack("<Q",self.return_pc)
        if ptr==self.regs[UC_X86_REG_RSP]+0x28 and n==24:
            return struct.pack("<QQQ",*self.stack_args)
        if self.NAME<=ptr<self.NAME+len(self.name) and n==1:
            return self.name[ptr-self.NAME:ptr-self.NAME+1]
        raise ValueError("unmapped")
    def mem_write(self,ptr,data):self.writes.append((ptr,bytes(data)))

def verified(_,ret,lib,sym,slots):
    if (slots.get("ok") and ret==IMAGE_BASE+CREATEFILEA_ORIGINAL_RETURN_RVA
        and lib.lower()=="kernel32.dll" and sym=="CreateFileA"):
        return hex(CREATEFILEA_ORIGINAL_CALL_RVA)
    return None

class CoreIniWin32OriginalTests(unittest.TestCase):
    def test_exact_original_readonly_existing_file(self):
        bridge=OwnedCoreIniWin32Research(b"fixture core.ini")
        guest=Guest()
        self.assertTrue(bridge.handle_createfilea(
            guest,None,{"ok":True},"KERNEL32.dll","CreateFileA",verified))
        self.assertEqual(guest.reg_read(UC_X86_REG_RAX),CORE_INI_WIN32_HANDLE)
        self.assertEqual(bridge.summary()["original_core_ini_win32_createfile_count"],1)
        self.assertEqual(bridge.summary()["win32_guest_file_cursor"],0)
        self.assertTrue(bridge.open)
        self.assertEqual(guest.writes,[])
        self.assertTrue(bridge.summary()["no_host_file_api_called"])
        with self.assertRaisesRegex(CoreIniWin32Rejected,"budget"):
            bridge.handle_createfilea(
                guest,None,{"ok":True},"KERNEL32.dll","CreateFileA",verified)

    def test_incorrect_file_access_or_original_callsite_rejected(self):
        cases=[
            (Guest(name=b"not_core.ini"),{"ok":True}),
            (Guest(access=0x40000000),{"ok":True}),
            (Guest(share=0),{"ok":True}),
            (Guest(security=0x1111),{"ok":True}),
            (Guest(creation=2),{"ok":True}),
            (Guest(flags=0x80),{"ok":True}),
            (Guest(template=1),{"ok":True}),
            (Guest(return_pc=IMAGE_BASE+CREATEFILEA_ORIGINAL_RETURN_RVA+1),{"ok":True}),
            (Guest(stack=0x770060000),{"ok":True}),
            (Guest(),{}),
        ]
        for guest,slots in cases:
            bridge=OwnedCoreIniWin32Research(b"fixture")
            with self.assertRaises(CoreIniWin32Rejected):
                bridge.handle_createfilea(
                    guest,None,slots,"KERNEL32.dll","CreateFileA",verified)
            self.assertEqual(guest.reg_read(UC_X86_REG_RAX),0xBADD)
            self.assertFalse(bridge.open)
            self.assertEqual(guest.writes,[])

    def test_unrelated_import_cannot_open_core(self):
        b=OwnedCoreIniWin32Research(b"fixture")
        g=Guest()
        self.assertFalse(b.handle_createfilea(
            g,None,{"ok":True},"KERNEL32.dll","ReadFile",verified))
        self.assertEqual(g.reg_read(UC_X86_REG_RAX),0xBADD)

    def test_requires_real_nonempty_owned_file_bytes(self):
        with self.assertRaises(CoreIniWin32Rejected):
            OwnedCoreIniWin32Research(b"")
        with self.assertRaises(CoreIniWin32Rejected):
            OwnedCoreIniWin32Research(b"X"*(64*1024+1))

if __name__=="__main__":
    unittest.main()
