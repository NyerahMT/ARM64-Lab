"""Unit tests for original Win64 ordinal-14 ntohl, no network involved."""
import struct,sys,unittest
from pathlib import Path
from unicorn.x86_const import UC_X86_REG_RSP,UC_X86_REG_RAX,UC_X86_REG_RCX
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"scripts"))
from mxbikes_winsock_startup_research import (
    OfflineWinsockResearch,OfflineWinsockRejected,
    IMAGE_BASE,NTOHL_CALL_RVA,NTOHL_RETURN_RVA,NTOHS_CALL_RVA,NTOHS_RETURN_RVA
)
class FakeCPU:
    RSP=0x770040008
    def __init__(self,*,input_value=0x11223344,
                 return_pc=IMAGE_BASE+NTOHL_RETURN_RVA,stack=RSP):
        self.regs={UC_X86_REG_RSP:stack,UC_X86_REG_RCX:input_value,
                   UC_X86_REG_RAX:0xBAD}
        self.return_pc=return_pc
    def reg_read(self,r):return self.regs[r]
    def reg_write(self,r,v):self.regs[r]=v
    def mem_read(self,ptr,length):
        if ptr==self.regs[UC_X86_REG_RSP] and length==8:
            return struct.pack("<Q",self.return_pc)
        raise ValueError("unmapped")
def verify(_,ret,lib,sym,slots):
    if slots.get("ok") and lib.lower()=="ws2_32.dll":
        if ret==IMAGE_BASE+NTOHL_RETURN_RVA and sym=="#14":
            return hex(NTOHL_CALL_RVA)
        if ret==IMAGE_BASE+NTOHS_RETURN_RVA and sym=="#15":
            return hex(NTOHS_CALL_RVA)
    return None
def ready():
    service=OfflineWinsockResearch()
    service.freeaddrinfo_events=[{"freed_own_guest_addrinfo":True}]
    return service
class OriginalNtohlTests(unittest.TestCase):
    def test_original_32bit_network_endian_conversion(self):
        for value,expected in (
            (0x11223344,0x44332211),
            (0x0100007f,0x7f000001),
            (0x00000000,0x00000000),
            (0xFFFFFFFF,0xFFFFFFFF),
            (0x12345678abcdef01,0x01efcdab),
        ):
            cpu=FakeCPU(input_value=value);service=ready()
            self.assertTrue(service.handle_ntohl(
                cpu,None,{"ok":True},"WS2_32.dll","#14",verify))
            self.assertEqual(cpu.reg_read(UC_X86_REG_RAX),expected)
            self.assertEqual(service.summary()["verified_original_guest_ntohl_handled"],1)
            self.assertFalse(service.summary()["host_network_initialized"])
            with self.assertRaisesRegex(OfflineWinsockRejected,"budget"):
                service.handle_ntohl(
                    cpu,None,{"ok":True},"WS2_32.dll","#14",verify)
    def test_invalid_sequence_stack_and_call_rejected(self):
        for cpu,slots in (
            (FakeCPU(return_pc=IMAGE_BASE+NTOHL_RETURN_RVA+1),{"ok":True}),
            (FakeCPU(stack=0x770040000),{"ok":True}),
            (FakeCPU(),{}),
        ):
            service=ready()
            with self.assertRaises(OfflineWinsockRejected):
                service.handle_ntohl(
                    cpu,None,slots,"WS2_32.dll","#14",verify)
            self.assertEqual(cpu.reg_read(UC_X86_REG_RAX),0xBAD)
        service=OfflineWinsockResearch()
        with self.assertRaises(OfflineWinsockRejected):
            service.handle_ntohl(
                FakeCPU(),None,{"ok":True},"WS2_32.dll","#14",verify)
    def test_ntohs_original_16bit_endian_swap(self):
        for original,expected in ((0x1234,0x3412),(0xabcd,0xcdab),
                                   (0x1,0x100),(0xffff,0xffff),
                                   (0x123456789abc,0xbc9a)):
            cpu=FakeCPU(input_value=original,
                        return_pc=IMAGE_BASE+NTOHS_RETURN_RVA)
            service=ready()
            service.ntohl_events=[{"original_ntohl":True}]
            self.assertTrue(service.handle_ntohs(
                cpu,None,{"ok":True},"WS2_32.dll","#15",verify))
            self.assertEqual(cpu.reg_read(UC_X86_REG_RAX),expected)
            self.assertEqual(service.summary()["verified_original_guest_ntohs_handled"],1)
            self.assertFalse(service.summary()["host_network_initialized"])
            with self.assertRaisesRegex(OfflineWinsockRejected,"budget"):
                service.handle_ntohs(
                    cpu,None,{"ok":True},"WS2_32.dll","#15",verify)

    def test_ntohs_bad_source_or_sequence_rejected(self):
        for cpu,slots in (
            (FakeCPU(return_pc=IMAGE_BASE+NTOHS_RETURN_RVA+1),{"ok":True}),
            (FakeCPU(return_pc=IMAGE_BASE+NTOHS_RETURN_RVA,
                     stack=0x770040000),{"ok":True}),
            (FakeCPU(return_pc=IMAGE_BASE+NTOHS_RETURN_RVA),{}),
        ):
            service=ready()
            service.ntohl_events=[{"original_ntohl":True}]
            with self.assertRaises(OfflineWinsockRejected):
                service.handle_ntohs(
                    cpu,None,slots,"WS2_32.dll","#15",verify)
            self.assertEqual(cpu.reg_read(UC_X86_REG_RAX),0xBAD)
        service=ready()
        cpu=FakeCPU(return_pc=IMAGE_BASE+NTOHS_RETURN_RVA)
        with self.assertRaisesRegex(OfflineWinsockRejected,"order"):
            service.handle_ntohs(cpu,None,{"ok":True},"WS2_32.dll","#15",verify)

    def test_unrelated_import_not_handled(self):
        cpu=FakeCPU();service=ready()
        self.assertFalse(service.handle_ntohl(
            cpu,None,{"ok":True},"WS2_32.dll","#15",verify))
        self.assertEqual(cpu.reg_read(UC_X86_REG_RAX),0xBAD)
if __name__=="__main__":
    unittest.main()
