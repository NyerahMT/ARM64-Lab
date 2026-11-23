"""Fourth original writable-PE-image memset: 45,056 bytes at RVA 0x297885."""
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
    FIFTH_MEMSET_CALL_RVA, FIFTH_MEMSET_RETURN_RVA, FIFTH_MEMSET_LENGTH,
)

class PE:
    def __init__(self, flags=IMAGE_SCN_MEM_WRITE, span=0x200000):
        self.sections=[(".data",span,0x300000,span,0,flags)]

class CPU:
    DEST=IMAGE_BASE+0x310000
    STACK=0x760040008
    def __init__(self, *, ret=IMAGE_BASE+FIFTH_MEMSET_RETURN_RVA,
                 length=FIFTH_MEMSET_LENGTH, fill=0, dst=DEST,
                 output_mapped=True):
        self.ret=ret
        self.output_mapped=output_mapped
        self.regs={
            UC_X86_REG_RSP:self.STACK, UC_X86_REG_RAX:0xBADD,
            UC_X86_REG_RCX:dst, UC_X86_REG_RDX:fill, UC_X86_REG_R8:length,
        }
        self.writes=[]
    def reg_read(self,reg): return self.regs[reg]
    def reg_write(self,reg,value): self.regs[reg]=value
    def mem_read(self,address,length):
        if address==self.STACK and length==8:
            return struct.pack("<Q",self.ret)
        if (address==self.regs[UC_X86_REG_RCX]
            and length==FIFTH_MEMSET_LENGTH and self.output_mapped):
            return bytes(length)
        raise ValueError("unmapped fake guest")
    def mem_write(self,address,data):
        self.writes.append((address,bytes(data)))

def verified(_, ret, library, symbol, slots):
    if (slots.get("ok") and library.lower()=="msvcr90.dll"
        and symbol=="memset" and ret==IMAGE_BASE+FIFTH_MEMSET_RETURN_RVA):
        return hex(FIFTH_MEMSET_CALL_RVA)
    return None

def ready():
    service=SingleGuestMallocResearch()
    service.memset_events=[{"initial_malloc_memset":True}]
    service.image_memset_events=[
        {"rva":"0x284cf9","count":400},
        {"rva":"0x2a7d03","count":3776},
        {"rva":"0x297857","count":4666112},
    ]
    service.sprintf_events=[{"ipv4":True}]
    return service

class FifthMemsetTests(unittest.TestCase):
    def test_exact_45056_byte_write_to_original_guest_pe_data(self):
        cpu=CPU()
        service=ready()
        self.assertTrue(service.handle_image_memset(
            cpu,PE(),{"ok":True},"MSVCR90.dll","memset",verified))
        self.assertEqual(len(cpu.writes),1)
        self.assertEqual(cpu.writes[0][0],cpu.DEST)
        self.assertEqual(len(cpu.writes[0][1]),FIFTH_MEMSET_LENGTH)
        self.assertEqual(cpu.writes[0][1],bytes(FIFTH_MEMSET_LENGTH))
        self.assertEqual(cpu.reg_read(UC_X86_REG_RAX),cpu.DEST)
        self.assertEqual(service.summary()["synthetic_original_image_memset_count"],4)
        self.assertEqual(service.summary()["original_image_memset_events"][-1]
                         ["original_call_rva"],hex(FIFTH_MEMSET_CALL_RVA))
        with self.assertRaisesRegex(GuestHeapResearchRejected,"budget"):
            service.handle_image_memset(
                cpu,PE(),{"ok":True},"MSVCR90.dll","memset",verified)

    def test_wrong_abi_callsite_or_pe_permissions_cannot_modify_guest(self):
        scenarios=[
            (CPU(length=FIFTH_MEMSET_LENGTH-1),PE(),{"ok":True}),
            (CPU(fill=1),PE(),{"ok":True}),
            (CPU(ret=IMAGE_BASE+FIFTH_MEMSET_RETURN_RVA+1),PE(),{"ok":True}),
            (CPU(dst=IMAGE_BASE+0x500000),PE(),{"ok":True}),
            (CPU(),PE(flags=IMAGE_SCN_MEM_WRITE|IMAGE_SCN_MEM_EXECUTE),{"ok":True}),
            (CPU(),PE(flags=0),{"ok":True}),
            (CPU(),PE(span=0x10000),{"ok":True}),
            (CPU(output_mapped=False),PE(),{"ok":True}),
            (CPU(),PE(),{}),
        ]
        for cpu,pe,slots in scenarios:
            service=ready()
            with self.assertRaises(GuestHeapResearchRejected):
                service.handle_image_memset(
                    cpu,pe,slots,"MSVCR90.dll","memset",verified)
            self.assertEqual(cpu.writes,[])
            self.assertEqual(cpu.reg_read(UC_X86_REG_RAX),0xBADD)

    def test_requires_original_successful_sprintf(self):
        service=ready()
        service.sprintf_events=[]
        cpu=CPU()
        with self.assertRaisesRegex(GuestHeapResearchRejected,"before_original_ipv4_sprintf"):
            service.handle_image_memset(
                cpu,PE(),{"ok":True},"MSVCR90.dll","memset",verified)
        self.assertEqual(cpu.writes,[])

if __name__=="__main__":
    unittest.main()
