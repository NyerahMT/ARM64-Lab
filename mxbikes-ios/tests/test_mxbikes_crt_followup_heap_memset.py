"""Original 296-byte guest CRT memset in exact last malloc allocation."""
import struct,sys,unittest
from pathlib import Path
from unicorn.x86_const import UC_X86_REG_RSP,UC_X86_REG_RAX,UC_X86_REG_RCX,UC_X86_REG_RDX,UC_X86_REG_R8
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"scripts"))
from mxbikes_crt_guest_malloc_research import (
    SingleGuestMallocResearch, GuestHeapResearchRejected, IMAGE_BASE,
    FOLLOWUP_HEAP_BASE,FOLLOWUP_HEAP_GUEST_OFFSET,
    INITIALIZE_296_MEMSET_CALL_RVA,INITIALIZE_296_MEMSET_RETURN_RVA,
    INITIALIZE_296_BYTES,
)
class Guest:
    STACK=0x770050008
    LAST=FOLLOWUP_HEAP_BASE+0x2000+FOLLOWUP_HEAP_GUEST_OFFSET
    def __init__(self,*,dst=LAST,length=INITIALIZE_296_BYTES,fill=0,
                 return_va=IMAGE_BASE+INITIALIZE_296_MEMSET_RETURN_RVA,
                 stack=STACK,mapped=True):
        self.ret=return_va;self.mapped=mapped
        self.regs={UC_X86_REG_RSP:stack,UC_X86_REG_RCX:dst,
                   UC_X86_REG_RDX:fill,UC_X86_REG_R8:length,UC_X86_REG_RAX:0xBAD}
        self.writes=[]
    def reg_read(self,r):return self.regs[r]
    def reg_write(self,r,v):self.regs[r]=v
    def mem_read(self,ptr,n):
        if ptr==self.regs[UC_X86_REG_RSP] and n==8:return struct.pack("<Q",self.ret)
        if ptr==self.regs[UC_X86_REG_RCX] and n==INITIALIZE_296_BYTES and self.mapped:
            return bytes(n)
        raise ValueError("unmapped")
    def mem_write(self,ptr,data):self.writes.append((ptr,bytes(data)))
def verified(_,ret,lib,sym,slots):
    if (slots.get("ok") and ret==IMAGE_BASE+INITIALIZE_296_MEMSET_RETURN_RVA and
        lib.lower()=="msvcr90.dll" and sym=="memset"):
        return hex(INITIALIZE_296_MEMSET_CALL_RVA)
    return None
def ready():
    service=SingleGuestMallocResearch()
    service.zero_len_memmove_events=[{"original":True}]
    service.followup_heap_cursor=0x3000
    service.followup_malloc_events=[{"requested_bytes":160,"mapped_guest_bytes":0x1000},
                                    {"requested_bytes":20,"mapped_guest_bytes":0x1000},
                                    {"requested_bytes":296,"mapped_guest_bytes":0x1000}]
    return service
class FollowupHeapMemsetTests(unittest.TestCase):
    def test_exact_original_296_bytes_in_last_user_guest_malloc(self):
        guest=Guest();service=ready()
        self.assertTrue(service.handle_followup_heap_memset(
            guest,None,{"ok":True},"MSVCR90.dll","memset",verified))
        self.assertEqual(guest.writes,[(guest.LAST,bytes(296))])
        self.assertEqual(guest.reg_read(UC_X86_REG_RAX),guest.LAST)
        self.assertEqual(service.summary()["original_followup_heap_memset_count"],1)
        with self.assertRaisesRegex(GuestHeapResearchRejected,"budget"):
            service.handle_followup_heap_memset(
                guest,None,{"ok":True},"MSVCR90.dll","memset",verified)

    def test_wrong_source_dest_length_or_call_must_not_write(self):
        cases=[
            (Guest(length=295),{"ok":True}),
            (Guest(fill=1),{"ok":True}),
            (Guest(dst=Guest.LAST+1),{"ok":True}),
            (Guest(dst=FOLLOWUP_HEAP_BASE+0x100),{"ok":True}),
            (Guest(dst=IMAGE_BASE+0x1234),{"ok":True}),
            (Guest(return_va=IMAGE_BASE+INITIALIZE_296_MEMSET_RETURN_RVA+1),{"ok":True}),
            (Guest(stack=0x770050000),{"ok":True}),
            (Guest(mapped=False),{"ok":True}),
            (Guest(),{}),
        ]
        for guest,slots in cases:
            service=ready()
            with self.assertRaises(GuestHeapResearchRejected):
                service.handle_followup_heap_memset(
                    guest,None,slots,"MSVCR90.dll","memset",verified)
            self.assertEqual(guest.reg_read(UC_X86_REG_RAX),0xBAD)
            self.assertEqual(guest.writes,[])
    def test_prior_original_memmove_and_last_296_malloc_required(self):
        service=ready();service.zero_len_memmove_events=[]
        with self.assertRaises(GuestHeapResearchRejected):
            service.handle_followup_heap_memset(
                Guest(),None,{"ok":True},"MSVCR90.dll","memset",verified)
        service=ready();service.followup_malloc_events[-1]["requested_bytes"]=295
        with self.assertRaisesRegex(GuestHeapResearchRejected,"last_allocation_mismatch"):
            service.handle_followup_heap_memset(
                Guest(),None,{"ok":True},"MSVCR90.dll","memset",verified)
if __name__=="__main__":unittest.main()
