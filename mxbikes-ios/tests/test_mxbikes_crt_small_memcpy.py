"""Exact 4-byte original Win64 memcpy from verified bounded malloc to guest data."""
import struct,sys,unittest
from pathlib import Path
from unicorn.x86_const import UC_X86_REG_RSP,UC_X86_REG_RAX,UC_X86_REG_RCX,UC_X86_REG_RDX,UC_X86_REG_R8
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"scripts"))
from mxbikes_crt_guest_malloc_research import (
    SingleGuestMallocResearch,GuestHeapResearchRejected,
    IMAGE_BASE,FOLLOWUP_HEAP_BASE,FOLLOWUP_HEAP_GUEST_OFFSET,
    MEMCPY_FOUR_ORIGINAL_CALL_RVA,MEMCPY_FOUR_ORIGINAL_RETURN_RVA,
    GUEST_TEMP_DATA_MIN,
)
SRC=FOLLOWUP_HEAP_BASE+0x2000+FOLLOWUP_HEAP_GUEST_OFFSET+7
DEST=GUEST_TEMP_DATA_MIN+0x1104
class CPU:
    STACK=0x770050008
    def __init__(self,*,src=SRC,dest=DEST,n=4,ret=IMAGE_BASE+MEMCPY_FOUR_ORIGINAL_RETURN_RVA,
                 mapped=True):
        self.ret=ret;self.mapped=mapped
        self.regs={
            UC_X86_REG_RSP:self.STACK,UC_X86_REG_RAX:0xBAD,
            UC_X86_REG_RCX:dest,UC_X86_REG_RDX:src,UC_X86_REG_R8:n,
        }
        self.writes=[]
    def reg_read(self,r):return self.regs[r]
    def reg_write(self,r,v):self.regs[r]=v
    def mem_read(self,p,n):
        if p==self.STACK and n==8:return struct.pack("<Q",self.ret)
        if self.mapped and p==self.regs[UC_X86_REG_RDX] and n==4:
            return b"ABCD"
        if self.mapped and p==self.regs[UC_X86_REG_RCX] and n==4:
            return b"zzzz"
        raise ValueError("unmapped guest")
    def mem_write(self,p,b):self.writes.append((p,bytes(b)))
def verified(_,ret,lib,sym,slots):
    if (slots.get("ok") and lib.lower()=="msvcr90.dll" and sym=="memcpy"
        and ret==IMAGE_BASE+MEMCPY_FOUR_ORIGINAL_RETURN_RVA):
        return hex(MEMCPY_FOUR_ORIGINAL_CALL_RVA)
    return None
def ready():
    h=SingleGuestMallocResearch()
    h.followup_heap_cursor=0x3000
    h.followup_malloc_events=[{"requested_bytes":160,"mapped_guest_bytes":4096},
                              {"requested_bytes":20,"mapped_guest_bytes":4096},
                              {"requested_bytes":296,"mapped_guest_bytes":4096}]
    h.followup_heap_memset_events=[{"original":True}]
    return h
class FourByteOriginalMemcpyTests(unittest.TestCase):
    def test_exact_original_src_malloc_and_guest_data_write(self):
        cpu=CPU();bridge=ready()
        self.assertTrue(bridge.handle_guest_small_memcpy(
            cpu,None,{"ok":True},"MSVCR90.dll","memcpy",verified))
        self.assertEqual(cpu.writes,[(DEST,b"ABCD")])
        self.assertEqual(cpu.reg_read(UC_X86_REG_RAX),DEST)
        self.assertEqual(bridge.summary()["original_small_memcpy_guest_count"],1)
        with self.assertRaisesRegex(GuestHeapResearchRejected,"budget"):
            bridge.handle_guest_small_memcpy(
                cpu,None,{"ok":True},"MSVCR90.dll","memcpy",verified)
    def test_outside_owned_bounds_bad_abi_and_unmapped_guest_blocked(self):
        cases=[
            (CPU(src=FOLLOWUP_HEAP_BASE+0x2000+FOLLOWUP_HEAP_GUEST_OFFSET+296),{"ok":True}),
            (CPU(dest=IMAGE_BASE+0x1000),{"ok":True}),
            (CPU(dest=FOLLOWUP_HEAP_BASE+0x100),{"ok":True}),
            (CPU(n=5),{"ok":True}),
            (CPU(ret=IMAGE_BASE+MEMCPY_FOUR_ORIGINAL_RETURN_RVA+1),{"ok":True}),
            (CPU(mapped=False),{"ok":True}),
            (CPU(),{}),
        ]
        for cpu,slots in cases:
            bridge=ready()
            with self.assertRaises(GuestHeapResearchRejected):
                bridge.handle_guest_small_memcpy(
                    cpu,None,slots,"MSVCR90.dll","memcpy",verified)
            self.assertEqual(cpu.writes,[])
            self.assertEqual(cpu.reg_read(UC_X86_REG_RAX),0xBAD)
    def test_original_allocation_sequence_is_required(self):
        cpu=CPU();bridge=ready();bridge.followup_heap_memset_events=[]
        with self.assertRaisesRegex(GuestHeapResearchRejected,"original_sequence"):
            bridge.handle_guest_small_memcpy(
                cpu,None,{"ok":True},"MSVCR90.dll","memcpy",verified)
if __name__=="__main__":
    unittest.main()
