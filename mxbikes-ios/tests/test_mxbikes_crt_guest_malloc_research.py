"""Single audited original malloc call to a bounded guest RAM allocation."""
import struct,sys,unittest
from pathlib import Path
from unicorn.x86_const import UC_X86_REG_RSP,UC_X86_REG_RAX,UC_X86_REG_RCX,UC_X86_REG_RDX,UC_X86_REG_R8
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"scripts"))
from mxbikes_crt_guest_malloc_research import (
    SingleGuestMallocResearch,GuestHeapResearchRejected,
    IMAGE_BASE,MALLOC_ORIGINAL_CALL_RVA,MALLOC_ORIGINAL_RETURN_RVA,
    MEMSET_ORIGINAL_CALL_RVA,MEMSET_ORIGINAL_RETURN_RVA,
    SECOND_MEMSET_CALL_RVA,SECOND_MEMSET_RETURN_RVA,SECOND_MEMSET_LENGTH,
    IMAGE_SCN_MEM_WRITE, IMAGE_SCN_MEM_EXECUTE,
    EXPECTED_ALLOC_BYTES,HEAP_BASE,HEAP_BYTES,HEAP_RESULT)

class Guest:
    def __init__(self,rcx=EXPECTED_ALLOC_BYTES,ret=IMAGE_BASE+MALLOC_ORIGINAL_RETURN_RVA,
                 rsp=0x710000008):
        self.regs={UC_X86_REG_RSP:rsp,UC_X86_REG_RAX:0x77,UC_X86_REG_RCX:rcx,
                   UC_X86_REG_RDX:0,UC_X86_REG_R8:EXPECTED_ALLOC_BYTES}
        self.ret=ret;self.mem_maps=[];self.mem_writes=[]
    def reg_read(self,reg):return self.regs[reg]
    def reg_write(self,reg,v):self.regs[reg]=v
    def mem_read(self,addr,n):
        if addr!=self.regs[UC_X86_REG_RSP] or n!=8:raise ValueError("unmapped")
        return struct.pack("<Q",self.ret)
    def mem_map(self,addr,length):self.mem_maps.append((addr,length))
    def mem_write(self,addr,payload):self.mem_writes.append((addr,bytes(payload)))

def verified(_,ret,library,symbol,slots):
    if slots.get("ok") and library.lower()=="msvcr90.dll":
        if ret==IMAGE_BASE+MALLOC_ORIGINAL_RETURN_RVA and symbol=="malloc":
            return hex(MALLOC_ORIGINAL_CALL_RVA)
        if ret==IMAGE_BASE+MEMSET_ORIGINAL_RETURN_RVA and symbol=="memset":
            return hex(MEMSET_ORIGINAL_CALL_RVA)
        if ret==IMAGE_BASE+SECOND_MEMSET_RETURN_RVA and symbol=="memset":
            return hex(SECOND_MEMSET_CALL_RVA)
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

    def test_real_original_memset_zeroes_malloc_guest_buffer(self):
        cpu=Guest();heap=SingleGuestMallocResearch()
        self.assertTrue(heap.handle(cpu,None,{"ok":True},
                                     "MSVCR90.dll","malloc",verified))
        cpu.reg_write(UC_X86_REG_RCX,HEAP_RESULT)
        cpu.ret=IMAGE_BASE+MEMSET_ORIGINAL_RETURN_RVA
        self.assertTrue(heap.handle_memset(cpu,None,{"ok":True},
                                           "MSVCR90.dll","memset",verified))
        self.assertEqual(cpu.reg_read(UC_X86_REG_RAX),HEAP_RESULT)
        self.assertEqual(len(cpu.mem_writes),1)
        self.assertEqual(cpu.mem_writes[0],(HEAP_RESULT,bytes(EXPECTED_ALLOC_BYTES)))
        self.assertEqual(heap.summary()["synthetic_original_memset_count"],1)
        with self.assertRaises(GuestHeapResearchRejected):
            heap.handle_memset(cpu,None,{"ok":True},
                               "MSVCR90.dll","memset",verified)

    def test_second_original_memset_of_writable_pe_data(self):
        ptr=IMAGE_BASE+0x399000
        class PE:
            sections=[(".text",0x1000,0x1000,0x1000,0,
                       IMAGE_SCN_MEM_EXECUTE),
                      (".data",0x2000,0x398000,0x2000,0,
                       IMAGE_SCN_MEM_WRITE)]
        class ImageGuest(Guest):
            def mem_read(self,addr,n):
                if addr==ptr and n==SECOND_MEMSET_LENGTH:
                    return b"X"*n
                return super().mem_read(addr,n)
        cpu=ImageGuest();mem=SingleGuestMallocResearch()
        mem.handle(cpu,None,{"ok":True},"MSVCR90.dll","malloc",verified)
        cpu.reg_write(UC_X86_REG_RCX,HEAP_RESULT)
        cpu.ret=IMAGE_BASE+MEMSET_ORIGINAL_RETURN_RVA
        mem.handle_memset(cpu,None,{"ok":True},"MSVCR90.dll","memset",verified)
        cpu.reg_write(UC_X86_REG_RCX,ptr)
        cpu.reg_write(UC_X86_REG_R8,SECOND_MEMSET_LENGTH)
        cpu.ret=IMAGE_BASE+SECOND_MEMSET_RETURN_RVA
        self.assertTrue(mem.handle_image_memset(
            cpu,PE(),{"ok":True},"MSVCR90.dll","memset",verified))
        self.assertEqual(cpu.mem_writes[-1],(ptr,bytes(SECOND_MEMSET_LENGTH)))
        self.assertEqual(cpu.reg_read(UC_X86_REG_RAX),ptr)
        self.assertEqual(mem.summary()["synthetic_original_image_memset_count"],1)
        with self.assertRaisesRegex(GuestHeapResearchRejected,"budget"):
            mem.handle_image_memset(
                cpu,PE(),{"ok":True},"MSVCR90.dll","memset",verified)

    def test_second_memset_never_writes_executable_section_or_bad_call(self):
        ptr=IMAGE_BASE+0x399000
        class PE:
            def __init__(self,flags):self.sections=[
                (".unsafe",0x2000,0x398000,0x2000,0,flags)]
        class GuestData(Guest):
            def mem_read(self,addr,n):
                if addr==ptr and n==SECOND_MEMSET_LENGTH:return bytes(n)
                return super().mem_read(addr,n)
        for flags,return_va in (
            (IMAGE_SCN_MEM_EXECUTE|IMAGE_SCN_MEM_WRITE,
             IMAGE_BASE+SECOND_MEMSET_RETURN_RVA),
            (0,IMAGE_BASE+SECOND_MEMSET_RETURN_RVA),
            (IMAGE_SCN_MEM_WRITE,IMAGE_BASE+SECOND_MEMSET_RETURN_RVA+1),
        ):
            cpu=GuestData();mem=SingleGuestMallocResearch()
            mem.handle(cpu,None,{"ok":True},"MSVCR90.dll","malloc",verified)
            cpu.reg_write(UC_X86_REG_RCX,HEAP_RESULT)
            cpu.ret=IMAGE_BASE+MEMSET_ORIGINAL_RETURN_RVA
            mem.handle_memset(cpu,None,{"ok":True},"MSVCR90.dll","memset",verified)
            cpu.reg_write(UC_X86_REG_RCX,ptr)
            cpu.reg_write(UC_X86_REG_R8,SECOND_MEMSET_LENGTH)
            cpu.ret=return_va
            before=len(cpu.mem_writes)
            with self.assertRaises(GuestHeapResearchRejected):
                mem.handle_image_memset(
                    cpu,PE(flags),{"ok":True},"MSVCR90.dll","memset",verified)
            self.assertEqual(len(cpu.mem_writes),before)
            self.assertEqual(mem.summary()["synthetic_original_image_memset_count"],0)

    def test_memset_invalid_source_and_size_fail_closed(self):
        for invalid_size,invalid_ptr in (
            (EXPECTED_ALLOC_BYTES+1,HEAP_RESULT),
            (EXPECTED_ALLOC_BYTES,HEAP_RESULT+32),
        ):
            cpu=Guest();heap=SingleGuestMallocResearch()
            heap.handle(cpu,None,{"ok":True},"MSVCR90.dll","malloc",verified)
            cpu.ret=IMAGE_BASE+MEMSET_ORIGINAL_RETURN_RVA
            cpu.reg_write(UC_X86_REG_RCX,invalid_ptr)
            cpu.reg_write(UC_X86_REG_R8,invalid_size)
            with self.assertRaises(GuestHeapResearchRejected):
                heap.handle_memset(cpu,None,{"ok":True},
                                   "MSVCR90.dll","memset",verified)
            self.assertEqual(cpu.mem_writes,[])
            self.assertFalse(heap.memset_events)

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
