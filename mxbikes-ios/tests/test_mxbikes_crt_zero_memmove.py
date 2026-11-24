"""Zero-length original memmove ABI: returns dst, never copies any guest bytes."""
import struct,sys,unittest
from pathlib import Path
from unicorn.x86_const import UC_X86_REG_RSP,UC_X86_REG_RAX,UC_X86_REG_RCX,UC_X86_REG_RDX,UC_X86_REG_R8
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"scripts"))
from mxbikes_crt_guest_malloc_research import (
 SingleGuestMallocResearch, GuestHeapResearchRejected, IMAGE_BASE,
 FOLLOWUP_HEAP_BASE, MEMMOVE_ZERO_ORIGINAL_CALL_RVA,
 MEMMOVE_ZERO_ORIGINAL_RETURN_RVA,
)
class CPU:
    STACK=0x750020008
    DEST=FOLLOWUP_HEAP_BASE+0x404
    SRC=FOLLOWUP_HEAP_BASE+0x504
    def __init__(self,*,dst=DEST,src=SRC,count=0,ret=IMAGE_BASE+MEMMOVE_ZERO_ORIGINAL_RETURN_RVA,
                 stack=STACK):
        self.ret=ret;self.accesses=[]
        self.regs={UC_X86_REG_RSP:stack,UC_X86_REG_RAX:0xBAD,
                   UC_X86_REG_RCX:dst,UC_X86_REG_RDX:src,UC_X86_REG_R8:count}
    def reg_read(self,r):return self.regs[r]
    def reg_write(self,r,v):self.regs[r]=v
    def mem_read(self,ptr,n):
        self.accesses.append(("read",ptr,n))
        if ptr==self.regs[UC_X86_REG_RSP] and n==8:
            return struct.pack("<Q",self.ret)
        raise ValueError("non-stack original guest byte read forbidden")
    def mem_write(self,ptr,b):
        self.accesses.append(("write",ptr,len(b)))
        raise AssertionError("memmove zero may not modify guest memory")
def verified(_,ret,lib,symbol,slots):
    if slots.get("ok") and lib.lower()=="msvcr90.dll" and symbol=="memmove" and ret==IMAGE_BASE+MEMMOVE_ZERO_ORIGINAL_RETURN_RVA:
        return hex(MEMMOVE_ZERO_ORIGINAL_CALL_RVA)
    return None
def ready():
    h=SingleGuestMallocResearch()
    h.followup_heap_cursor=0x1000
    h.followup_malloc_events=[{"original_guest_malloc":True}]
    return h
class ZeroLengthOriginalMemmoveTests(unittest.TestCase):
    def test_only_verified_original_zero_move_returns_destination(self):
        cpu=CPU();bridge=ready()
        self.assertTrue(bridge.handle_zero_len_memmove(
            cpu,None,{"ok":True},"MSVCR90.dll","memmove",verified))
        self.assertEqual(cpu.reg_read(UC_X86_REG_RAX),cpu.DEST)
        self.assertEqual(cpu.accesses,[("read",cpu.STACK,8)])
        self.assertEqual(bridge.summary()["original_zero_length_memmove_count"],1)
        with self.assertRaisesRegex(GuestHeapResearchRejected,"budget"):
            bridge.handle_zero_len_memmove(
                cpu,None,{"ok":True},"MSVCR90.dll","memmove",verified)
    def test_outside_heap_nonzero_length_and_bad_call_fail_closed(self):
        cases=[
            (CPU(count=1),{"ok":True}),
            (CPU(src=FOLLOWUP_HEAP_BASE+0x2000),{"ok":True}),
            (CPU(dst=IMAGE_BASE+0x1234),{"ok":True}),
            (CPU(dst=0),{"ok":True}),
            (CPU(ret=IMAGE_BASE+MEMMOVE_ZERO_ORIGINAL_RETURN_RVA+1),{"ok":True}),
            (CPU(stack=0x750020000),{"ok":True}),
            (CPU(),{}),
        ]
        for cpu,slots in cases:
            bridge=ready()
            with self.assertRaises(GuestHeapResearchRejected):
                bridge.handle_zero_len_memmove(
                    cpu,None,slots,"MSVCR90.dll","memmove",verified)
            self.assertEqual(cpu.reg_read(UC_X86_REG_RAX),0xBAD)
            self.assertFalse(any(event[0]=="write" for event in cpu.accesses))
        bridge=SingleGuestMallocResearch()
        with self.assertRaises(GuestHeapResearchRejected):
            bridge.handle_zero_len_memmove(
                CPU(),None,{"ok":True},"MSVCR90.dll","memmove",verified)
if __name__=="__main__":
    unittest.main()
