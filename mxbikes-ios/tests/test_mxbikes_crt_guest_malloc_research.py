"""Single audited original malloc call to a bounded guest RAM allocation."""
import struct,sys,unittest
from pathlib import Path
from unicorn.x86_const import UC_X86_REG_RSP,UC_X86_REG_RAX,UC_X86_REG_RCX
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"scripts"))
from mxbikes_crt_guest_malloc_research import (
    SingleGuestMallocResearch,GuestHeapResearchRejected,
    IMAGE_BASE,MALLOC_ORIGINAL_CALL_RVA,MALLOC_ORIGINAL_RETURN_RVA,
    EXPECTED_ALLOC_BYTES,HEAP_BASE,HEAP_BYTES,HEAP_RESULT)

class Guest:
    def __init__(self,rcx=EXPECTED_ALLOC_BYTES,ret=IMAGE_BASE+MALLOC_ORIGINAL_RETURN_RVA,
                 rsp=0x710000008):
        self.regs={UC_X86_REG_RSP:rsp,UC_X86_REG_RAX:0x77,UC_X86_REG_RCX:rcx}
        self.ret=ret;self.mem_maps=[]
    def reg_read(self,reg):return self.regs[reg]
    def reg_write(self,reg,v):self.regs[reg]=v
    def mem_read(self,addr,n):
        if addr!=self.regs[UC_X86_REG_RSP] or n!=8:raise ValueError("unmapped")
        return struct.pack("<Q",self.ret)
    def mem_map(self,addr,length):self.mem_maps.append((addr,length))

def verified(_,ret,library,symbol,slots):
    if (ret==IMAGE_BASE+MALLOC_ORIGINAL_RETURN_RVA and
        slots.get("ok") and library.lower()=="msvcr90.dll" and symbol=="malloc"):
        return hex(MALLOC_ORIGINAL_CALL_RVA)
    return None

class OriginalMallocGuestResearchTests(unittest.TestCase):
    def test_bound_0x2580_allocated_in_guest_not_host_memory(self):
        cpu=Guest();heap=SingleGuestMallocResearch()
        self.assertTrue(heap.handle(cpu,None,{"ok":True},
                           "MSVCR90.dll","malloc",verified))
        self.assertEqual(cpu.reg_read(UC_X86_REG_RAX),HEAP_RESULT)
        self.assertEqual(cpu.mem_maps,[(HEAP_BASE,HEAP_BYTES)])
        self.assertEqual(heap.summary()["synthetic_original_malloc_count"],1)
        self.assertFalse(heap.summary()["original_windows_crt_executed"])
        with self.assertRaisesRegex(GuestHeapResearchRejected,"second"):
            heap.handle(cpu,None,{"ok":True},"MSVCR90.dll","malloc",verified)

    def test_all_failed_preconditions_leave_registers_untouched(self):
        for cpu,slots in (
           (Guest(rcx=0x500000),{"ok":True}),
           (Guest(ret=IMAGE_BASE+MALLOC_ORIGINAL_RETURN_RVA+1),{"ok":True}),
           (Guest(rsp=0x710000000),{"ok":True}),
           (Guest(),{}),
        ):
            heap=SingleGuestMallocResearch()
            with self.assertRaises(GuestHeapResearchRejected):
                heap.handle(cpu,None,slots,"MSVCR90.dll","malloc",verified)
            self.assertEqual(cpu.reg_read(UC_X86_REG_RAX),0x77)
            self.assertEqual(cpu.mem_maps,[])
            self.assertFalse(heap.called)

    def test_other_crt_import_still_blocked(self):
        cpu=Guest();heap=SingleGuestMallocResearch()
        self.assertFalse(heap.handle(cpu,None,{"ok":True},
                         "MSVCR90.dll","realloc",verified))
        self.assertEqual(cpu.mem_maps,[])
if __name__=="__main__":unittest.main()
