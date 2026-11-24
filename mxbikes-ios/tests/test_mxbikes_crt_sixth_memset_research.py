"""Test the exact sixth original CRT memset after the second 48-byte malloc.

All bytes live in synthetic Unicorn guest memory. No game or Steam files.
"""
import struct
import sys
import unittest
from pathlib import Path
from unicorn.x86_const import (
    UC_X86_REG_RSP, UC_X86_REG_RAX, UC_X86_REG_RCX,
    UC_X86_REG_RDX, UC_X86_REG_R8,
)
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from mxbikes_crt_guest_malloc_research import (
    SingleGuestMallocResearch, GuestHeapResearchRejected,
    IMAGE_BASE, IMAGE_SCN_MEM_WRITE, IMAGE_SCN_MEM_EXECUTE,
    SIXTH_MEMSET_CALL_RVA, SIXTH_MEMSET_RETURN_RVA, SIXTH_MEMSET_LENGTH,
)

class PE:
    def __init__(self, *, flags=IMAGE_SCN_MEM_WRITE, length=0x300000):
        self.sections=[(".data",length,0x390000,length,0,flags)]

class Guest:
    DEST=IMAGE_BASE+0x394000
    STACK=0x770010008
    def __init__(self, *, return_va=IMAGE_BASE+SIXTH_MEMSET_RETURN_RVA,
                 length=SIXTH_MEMSET_LENGTH, fill=0, output=DEST,
                 mapped=True, stack=STACK):
        self.ret=return_va
        self.mapped=mapped
        self.regs={
            UC_X86_REG_RSP:stack, UC_X86_REG_RAX:0xBADD,
            UC_X86_REG_RCX:output, UC_X86_REG_RDX:fill,
            UC_X86_REG_R8:length,
        }
        self.writes=[]
    def reg_read(self,r): return self.regs[r]
    def reg_write(self,r,v): self.regs[r]=v
    def mem_read(self,ptr,size):
        if ptr==self.regs[UC_X86_REG_RSP] and size==8:
            return struct.pack("<Q",self.ret)
        if ptr==self.regs[UC_X86_REG_RCX] and size==SIXTH_MEMSET_LENGTH and self.mapped:
            return b"X"*size
        raise ValueError("unmapped")
    def mem_write(self,ptr,content):
        self.writes.append((ptr,bytes(content)))

def verified(_,ret,lib,sym,slots):
    if slots.get("ok") and ret==IMAGE_BASE+SIXTH_MEMSET_RETURN_RVA and lib.lower()=="msvcr90.dll" and sym=="memset":
        return hex(SIXTH_MEMSET_CALL_RVA)
    return None

def ready():
    m=SingleGuestMallocResearch()
    m.called=True
    m.memset_events=[{"malloc_heap_9600":True}]
    m.image_memset_events=[
        {"call":"0x284cf9","length":400},
        {"call":"0x2a7d03","length":3776},
        {"call":"0x297857","length":4666112},
        {"call":"0x297885","length":45056},
    ]
    m.sprintf_events=[{"loopback_ipv4":True}]
    m.second_malloc_events=[{"size":48}]
    return m

class SixthImageMemsetTests(unittest.TestCase):
    def test_exact_5184_byte_writable_nonexecutable_original_data(self):
        u=Guest()
        bridge=ready()
        self.assertTrue(bridge.handle_image_memset(
            u,PE(),{"ok":True},"MSVCR90.dll","memset",verified))
        self.assertEqual(u.writes,[(u.DEST,bytes(SIXTH_MEMSET_LENGTH))])
        self.assertEqual(u.reg_read(UC_X86_REG_RAX),u.DEST)
        summary=bridge.summary()
        self.assertEqual(summary["synthetic_original_image_memset_count"],5)
        self.assertEqual(summary["original_image_memset_events"][-1]["original_call_rva"],hex(SIXTH_MEMSET_CALL_RVA))
        self.assertEqual(summary["original_image_memset_events"][-1]["zeroed_original_guest_data_bytes"],5184)
        with self.assertRaisesRegex(GuestHeapResearchRejected,"budget"):
            bridge.handle_image_memset(u,PE(),{"ok":True},
                                      "MSVCR90.dll","memset",verified)

    def test_unknown_import_size_or_memory_never_writes(self):
        cases=[
            (Guest(length=SIXTH_MEMSET_LENGTH-1),PE(),{"ok":True}),
            (Guest(fill=1),PE(),{"ok":True}),
            (Guest(return_va=IMAGE_BASE+SIXTH_MEMSET_RETURN_RVA+1),PE(),{"ok":True}),
            (Guest(output=IMAGE_BASE+0x9000000),PE(),{"ok":True}),
            (Guest(output=IMAGE_BASE+0x390000),PE(length=0x1000),{"ok":True}),
            (Guest(),PE(flags=IMAGE_SCN_MEM_WRITE|IMAGE_SCN_MEM_EXECUTE),{"ok":True}),
            (Guest(),PE(flags=IMAGE_SCN_MEM_EXECUTE),{"ok":True}),
            (Guest(mapped=False),PE(),{"ok":True}),
            (Guest(stack=0x770010000),PE(),{"ok":True}),
            (Guest(),PE(),{}),
        ]
        for guest,pe,slots in cases:
            bridge=ready()
            with self.assertRaises(GuestHeapResearchRejected):
                bridge.handle_image_memset(guest,pe,slots,
                                          "MSVCR90.dll","memset",verified)
            self.assertEqual(guest.writes,[])
            self.assertEqual(guest.reg_read(UC_X86_REG_RAX),0xBADD)

    def test_second_malloc_is_required_prior_to_fifth_pe_memset(self):
        bridge=ready()
        bridge.second_malloc_events=[]
        guest=Guest()
        with self.assertRaisesRegex(GuestHeapResearchRejected,"before_verified_second_malloc"):
            bridge.handle_image_memset(
                guest,PE(),{"ok":True},"MSVCR90.dll","memset",verified)
        self.assertEqual(guest.writes,[])

if __name__=="__main__":
    unittest.main()
