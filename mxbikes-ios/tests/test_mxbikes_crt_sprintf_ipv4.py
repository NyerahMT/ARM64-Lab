"""Original game's one fixed dotted IPv4 sprintf Win64 ABI, no host CRT."""
import struct,sys,unittest
from pathlib import Path
from unicorn.x86_const import (
    UC_X86_REG_RSP,UC_X86_REG_RAX,UC_X86_REG_RCX,
    UC_X86_REG_RDX,UC_X86_REG_R8,UC_X86_REG_R9
)
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"scripts"))
from mxbikes_crt_guest_malloc_research import (
    SingleGuestMallocResearch,GuestHeapResearchRejected,
    IMAGE_BASE,SPRINTF_ORIGINAL_CALL_RVA,SPRINTF_ORIGINAL_RETURN_RVA,
    SPRINTF_IPV4_FORMAT,SPRINTF_IPV4_OUTPUT
)

class Guest:
    DEST=0x750020000
    FMT=IMAGE_BASE+0x350000
    STACK=0x750030008
    def __init__(self,*,octets=(127,0,0,1),fmt=SPRINTF_IPV4_FORMAT,
                 ret=IMAGE_BASE+SPRINTF_ORIGINAL_RETURN_RVA,stack=STACK,
                 dst=DEST,output_mapped=True):
        self.fmt=fmt;self.ret=ret;self.octets=octets
        self.output_mapped=output_mapped;self.writes=[]
        self.regs={UC_X86_REG_RSP:stack,UC_X86_REG_RAX:0xBAD,
                   UC_X86_REG_RCX:dst,UC_X86_REG_RDX:self.FMT,
                   UC_X86_REG_R8:octets[0],UC_X86_REG_R9:octets[1]}
    def reg_read(self,r):return self.regs[r]
    def reg_write(self,r,v):self.regs[r]=v
    def mem_read(self,addr,n):
        if addr==self.regs[UC_X86_REG_RSP] and n==8:
            return struct.pack("<Q",self.ret)
        if addr==self.regs[UC_X86_REG_RSP]+0x28 and n==16:
            return struct.pack("<QQ",self.octets[2],self.octets[3])
        if addr==self.FMT and n==len(SPRINTF_IPV4_FORMAT):
            return self.fmt
        if addr==self.regs[UC_X86_REG_RCX] and n==len(SPRINTF_IPV4_OUTPUT) and self.output_mapped:
            return bytes(n)
        raise ValueError("unmapped")
    def mem_write(self,addr,data):self.writes.append((addr,bytes(data)))

def verified(_,ret,library,symbol,slots):
    if slots.get("ok") and library.lower()=="msvcr90.dll" and symbol=="sprintf" and ret==IMAGE_BASE+SPRINTF_ORIGINAL_RETURN_RVA:
        return hex(SPRINTF_ORIGINAL_CALL_RVA)
    return None

def ready():
    obj=SingleGuestMallocResearch()
    obj.image_memset_events=[{"original":True}]
    return obj

class OriginalSprintfTest(unittest.TestCase):
    def test_exact_original_four_decimal_fields_and_return_length(self):
        cpu=Guest();crt=ready()
        self.assertTrue(crt.handle_sprintf_ipv4(
            cpu,None,{"ok":True},"MSVCR90.dll","sprintf",verified))
        self.assertEqual(cpu.writes,[(cpu.DEST,SPRINTF_IPV4_OUTPUT)])
        self.assertEqual(cpu.reg_read(UC_X86_REG_RAX),9)
        self.assertEqual(crt.summary()["original_ipv4_sprintf_count"],1)
        with self.assertRaisesRegex(GuestHeapResearchRejected,"budget"):
            crt.handle_sprintf_ipv4(
                cpu,None,{"ok":True},"MSVCR90.dll","sprintf",verified)

    def test_does_not_run_generic_formatting_or_untrusted_destinations(self):
        for cpu,slots in (
            (Guest(fmt=b"%n"+bytes(14)),{"ok":True}),
            (Guest(octets=(127,0,0,2)),{"ok":True}),
            (Guest(ret=IMAGE_BASE+SPRINTF_ORIGINAL_RETURN_RVA+1),{"ok":True}),
            (Guest(stack=0x750030000),{"ok":True}),
            (Guest(dst=IMAGE_BASE+0x350400),{"ok":True}),
            (Guest(output_mapped=False),{"ok":True}),
            (Guest(),{}),
        ):
            crt=ready()
            with self.assertRaises(GuestHeapResearchRejected):
                crt.handle_sprintf_ipv4(
                    cpu,None,slots,"MSVCR90.dll","sprintf",verified)
            self.assertEqual(cpu.writes,[])
            self.assertEqual(cpu.reg_read(UC_X86_REG_RAX),0xBAD)

    def test_only_original_import_is_supported(self):
        cpu=Guest();crt=ready()
        self.assertFalse(crt.handle_sprintf_ipv4(
            cpu,None,{"ok":True},"MSVCR90.dll","vsprintf",verified))
        self.assertEqual(cpu.writes,[])
if __name__=="__main__":
    unittest.main()
