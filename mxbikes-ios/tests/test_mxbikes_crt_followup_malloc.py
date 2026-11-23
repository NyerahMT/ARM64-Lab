"""Research-only original Win64 CRT malloc guest bump heap tests.

Synthetic CPU and imported-call provenance fixtures; no game data.
"""
import struct,sys,unittest
from pathlib import Path
from unicorn.x86_const import UC_X86_REG_RSP,UC_X86_REG_RAX,UC_X86_REG_RCX
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"scripts"))
from mxbikes_crt_guest_malloc_research import (
    SingleGuestMallocResearch, GuestHeapResearchRejected,
    IMAGE_BASE, IMAGE_MEMSET_STEPS,
    FOLLOWUP_HEAP_BASE, FOLLOWUP_HEAP_MAX_CALLS,
    FOLLOWUP_HEAP_MAX_SINGLE_BYTES, FOLLOWUP_HEAP_MAX_TOTAL_BYTES,
    FOLLOWUP_HEAP_GUEST_OFFSET,
)
CALL=0x2ad4b9
RETURN=CALL+5

class Guest:
    STACK=0x770040008
    def __init__(self,*,size=160,return_va=IMAGE_BASE+RETURN,stack=STACK,map_fails=False):
        self.ret=return_va
        self.map_fails=map_fails
        self.regs={UC_X86_REG_RSP:stack,UC_X86_REG_RAX:0xBADD,UC_X86_REG_RCX:size}
        self.maps=[]
    def reg_read(self,reg):return self.regs[reg]
    def reg_write(self,reg,value):self.regs[reg]=value
    def mem_read(self,p,n):
        if p==self.regs[UC_X86_REG_RSP] and n==8:return struct.pack("<Q",self.ret)
        raise ValueError("unmapped stack")
    def mem_map(self,addr,length):
        if self.map_fails:raise ValueError("allocation failed")
        self.maps.append((addr,length))

def verified(_,return_va,library,symbol,slots):
    if (slots.get("ok") and library.lower()=="msvcr90.dll"
        and symbol=="malloc" and return_va==IMAGE_BASE+RETURN):
        return hex(CALL)
    return None

def ready():
    m=SingleGuestMallocResearch()
    m.called=True
    m.memset_events=[{"original_9600_byte_malloc_zeroed":True}]
    m.image_memset_events=[{"call":hex(r)} for r,_,_ in IMAGE_MEMSET_STEPS]
    m.sprintf_events=[{"original_ipv4":True}]
    m.second_malloc_events=[{"bytes":48}]
    m.bounded_image_memset_events=[
        {"original_call_rva":"0x1b970f","zeroed_original_guest_data_bytes":24928}]
    return m

class FollowupOriginalMallocTests(unittest.TestCase):
    def test_real_third_original_request_160_bytes_in_new_guest_page(self):
        cpu=Guest()
        m=ready()
        self.assertTrue(m.handle_followup_malloc(
            cpu,None,{"ok":True},"MSVCR90.dll","malloc",verified))
        self.assertEqual(cpu.maps,[(FOLLOWUP_HEAP_BASE,0x1000)])
        self.assertEqual(cpu.reg_read(UC_X86_REG_RAX),
                         FOLLOWUP_HEAP_BASE+FOLLOWUP_HEAP_GUEST_OFFSET)
        summary=m.summary()
        self.assertEqual(summary["bounded_followup_malloc_count"],1)
        self.assertEqual(summary["bounded_followup_malloc_events"][0]["requested_bytes"],160)
        self.assertEqual(summary["bounded_followup_malloc_events"][0]["original_call_rva"],hex(CALL))
        self.assertFalse(summary["original_windows_crt_executed"])

    def test_deterministic_next_guest_page_and_no_overlapping_mapping(self):
        cpu=Guest()
        m=ready()
        m.handle_followup_malloc(cpu,None,{"ok":True},"MSVCR90.dll","malloc",verified)
        cpu.reg_write(UC_X86_REG_RCX,4096)
        m.handle_followup_malloc(cpu,None,{"ok":True},"MSVCR90.dll","malloc",verified)
        self.assertEqual(cpu.maps,[
            (FOLLOWUP_HEAP_BASE,0x1000),
            (FOLLOWUP_HEAP_BASE+0x1000,0x2000),
        ])
        self.assertEqual(cpu.reg_read(UC_X86_REG_RAX),
                         FOLLOWUP_HEAP_BASE+0x1000+FOLLOWUP_HEAP_GUEST_OFFSET)

    def test_bad_size_callsite_stack_or_budget_fails_closed(self):
        cases=[
            (Guest(size=0),{"ok":True}),
            (Guest(size=FOLLOWUP_HEAP_MAX_SINGLE_BYTES+1),{"ok":True}),
            (Guest(return_va=IMAGE_BASE+RETURN+1),{"ok":True}),
            (Guest(stack=0x770040000),{"ok":True}),
            (Guest(map_fails=True),{"ok":True}),
            (Guest(),{}),
        ]
        for cpu,slots in cases:
            m=ready()
            with self.assertRaises(GuestHeapResearchRejected):
                m.handle_followup_malloc(
                    cpu,None,slots,"MSVCR90.dll","malloc",verified)
            self.assertEqual(cpu.reg_read(UC_X86_REG_RAX),0xBADD)
            self.assertEqual(cpu.maps,[])
            self.assertEqual(m.summary()["bounded_followup_malloc_count"],0)
        cpu=Guest();m=ready()
        m.followup_malloc_events=[{} for _ in range(FOLLOWUP_HEAP_MAX_CALLS)]
        with self.assertRaisesRegex(GuestHeapResearchRejected,"call_budget"):
            m.handle_followup_malloc(
                cpu,None,{"ok":True},"MSVCR90.dll","malloc",verified)
        m=ready()
        m.followup_heap_cursor=FOLLOWUP_HEAP_MAX_TOTAL_BYTES
        with self.assertRaisesRegex(GuestHeapResearchRejected,"aggregate_memory_budget"):
            m.handle_followup_malloc(
                Guest(),None,{"ok":True},"MSVCR90.dll","malloc",verified)

    def test_requires_prior_24928_byte_original_memory_initialization(self):
        m=ready();m.bounded_image_memset_events=[]
        cpu=Guest()
        with self.assertRaisesRegex(GuestHeapResearchRejected,"original_sequence"):
            m.handle_followup_malloc(
                cpu,None,{"ok":True},"MSVCR90.dll","malloc",verified)
        self.assertEqual(cpu.maps,[])
        self.assertEqual(cpu.reg_read(UC_X86_REG_RAX),0xBADD)

if __name__=="__main__":
    unittest.main()
