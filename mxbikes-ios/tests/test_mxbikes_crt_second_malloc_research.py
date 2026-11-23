"""Second original malloc through verified lazy CRT import wrapper, guest-only."""
import struct
import sys
import unittest
from pathlib import Path
from unicorn.x86_const import UC_X86_REG_RSP,UC_X86_REG_RAX,UC_X86_REG_RCX

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"scripts"))
from mxbikes_crt_guest_malloc_research import (
    SingleGuestMallocResearch, GuestHeapResearchRejected, IMAGE_BASE,
    IMAGE_MEMSET_STEPS, SECOND_MALLOC_CALL_RVA, SECOND_MALLOC_RETURN_RVA,
    SECOND_MALLOC_BYTES, SECOND_HEAP_BASE, SECOND_HEAP_MAP_SIZE,
    SECOND_HEAP_RESULT,
)

class CPU:
    RSP=0x730040008
    def __init__(self, *, ret=IMAGE_BASE+SECOND_MALLOC_RETURN_RVA,
                 size=SECOND_MALLOC_BYTES,rsp=RSP):
        self.ret=ret
        self.regs={UC_X86_REG_RSP:rsp,UC_X86_REG_RAX:0xBADD,
                   UC_X86_REG_RCX:size}
        self.maps=[]
    def reg_read(self,r):return self.regs[r]
    def reg_write(self,r,v):self.regs[r]=v
    def mem_read(self,p,n):
        if p==self.regs[UC_X86_REG_RSP] and n==8:return struct.pack("<Q",self.ret)
        raise ValueError("unmapped")
    def mem_map(self,p,n):self.maps.append((p,n))

def verified(_,ret,library,symbol,slots):
    if (slots.get("ok") and library.lower()=="msvcr90.dll" and
        symbol=="malloc" and ret==IMAGE_BASE+SECOND_MALLOC_RETURN_RVA):
        return hex(SECOND_MALLOC_CALL_RVA)
    return None

def ready():
    m=SingleGuestMallocResearch()
    m.called=True
    m.events=[{"original_initial_malloc":True}]
    m.image_memset_events=[{"original_call":hex(r)}
                           for r,ret,sz in IMAGE_MEMSET_STEPS]
    m.sprintf_events=[{"completed_original_dotted_ipv4":True}]
    return m

class SecondOriginalMallocTests(unittest.TestCase):
    def test_exact_original_48byte_allocation_in_guest_page(self):
        cpu=CPU();m=ready()
        self.assertTrue(m.handle_second_malloc(
            cpu,None,{"ok":True},"MSVCR90.dll","malloc",verified))
        self.assertEqual(cpu.reg_read(UC_X86_REG_RAX),SECOND_HEAP_RESULT)
        self.assertEqual(cpu.maps,[(SECOND_HEAP_BASE,SECOND_HEAP_MAP_SIZE)])
        self.assertEqual(m.summary()["synthetic_original_second_malloc_count"],1)
        self.assertEqual(m.summary()["second_malloc_events"][0]["requested_bytes"],48)
        self.assertFalse(m.summary()["original_windows_crt_executed"])
        with self.assertRaisesRegex(GuestHeapResearchRejected,"budget"):
            m.handle_second_malloc(
                cpu,None,{"ok":True},"MSVCR90.dll","malloc",verified)

    def test_wrong_size_return_or_mapped_page_fail_closed(self):
        for cpu,slots in (
            (CPU(size=47),{"ok":True}),
            (CPU(size=49),{"ok":True}),
            (CPU(ret=IMAGE_BASE+SECOND_MALLOC_RETURN_RVA+1),{"ok":True}),
            (CPU(rsp=0x730040000),{"ok":True}),
            (CPU(),{}),
        ):
            m=ready()
            with self.assertRaises(GuestHeapResearchRejected):
                m.handle_second_malloc(
                    cpu,None,slots,"MSVCR90.dll","malloc",verified)
            self.assertEqual(cpu.maps,[])
            self.assertEqual(cpu.reg_read(UC_X86_REG_RAX),0xBADD)

    def test_original_guest_sequence_required(self):
        cpu=CPU();m=ready();m.image_memset_events=m.image_memset_events[:-1]
        with self.assertRaisesRegex(GuestHeapResearchRejected,"order"):
            m.handle_second_malloc(cpu,None,{"ok":True},"MSVCR90.dll","malloc",verified)
        self.assertEqual(cpu.maps,[])

    def test_other_symbol_not_handled(self):
        cpu=CPU();m=ready()
        self.assertFalse(m.handle_second_malloc(
            cpu,None,{"ok":True},"MSVCR90.dll","calloc",verified))
        self.assertEqual(cpu.maps,[])

if __name__=="__main__":
    unittest.main()
