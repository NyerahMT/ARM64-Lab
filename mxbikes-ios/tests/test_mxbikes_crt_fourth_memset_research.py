"""Original fourth writable-PE memset: 4666112-byte guest state zero-fill."""
import struct,sys,unittest
from pathlib import Path
from unicorn.x86_const import UC_X86_REG_RSP,UC_X86_REG_RAX,UC_X86_REG_RCX,UC_X86_REG_RDX,UC_X86_REG_R8
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"scripts"))
from mxbikes_crt_guest_malloc_research import (
    SingleGuestMallocResearch,GuestHeapResearchRejected,
    IMAGE_BASE,IMAGE_SCN_MEM_WRITE,IMAGE_SCN_MEM_EXECUTE,
    FOURTH_MEMSET_CALL_RVA,FOURTH_MEMSET_RETURN_RVA,FOURTH_MEMSET_LENGTH
)
class PE:
    def __init__(self,flags=IMAGE_SCN_MEM_WRITE,vsize=0x900000):
        self.sections=[(".bss",vsize,0x300000,vsize,0,flags)]
class CPU:
    DST=IMAGE_BASE+0x400000
    STACK=0x760040008
    def __init__(self,*,ret=IMAGE_BASE+FOURTH_MEMSET_RETURN_RVA,
                 length=FOURTH_MEMSET_LENGTH,fill=0,dst=DST,output_mapped=True):
        self.ret=ret;self.output_mapped=output_mapped
        self.regs={UC_X86_REG_RSP:self.STACK,UC_X86_REG_RAX:0xBAD,
                   UC_X86_REG_RCX:dst,UC_X86_REG_RDX:fill,UC_X86_REG_R8:length}
        self.writes=[]
    def reg_read(self,r):return self.regs[r]
    def reg_write(self,r,v):self.regs[r]=v
    def mem_read(self,addr,n):
        if addr==self.STACK and n==8:return struct.pack("<Q",self.ret)
        if addr==self.regs[UC_X86_REG_RCX] and n==FOURTH_MEMSET_LENGTH and self.output_mapped:
            return bytes(n)
        raise ValueError("unmapped")
    def mem_write(self,addr,data):self.writes.append((addr,bytes(data)))
def verify(_,ret,library,symbol,slots):
    if (slots.get("ok") and library.lower()=="msvcr90.dll" and symbol=="memset"
        and ret==IMAGE_BASE+FOURTH_MEMSET_RETURN_RVA):
        return hex(FOURTH_MEMSET_CALL_RVA)
    return None
def ready():
    mem=SingleGuestMallocResearch()
    mem.memset_events=[{"guest_initialization":True}]
    mem.image_memset_events=[
        {"original_rva":"0x284cf9","bytes":400},
        {"original_rva":"0x2a7d03","bytes":3776},
    ]
    mem.sprintf_events=[{"original_ipv4_formatter":True}]
    return mem
class FourthMemsetTest(unittest.TestCase):
    def test_original_4point45mib_state_region_is_zeroed(self):
        cpu=CPU();mem=ready()
        self.assertTrue(mem.handle_image_memset(
            cpu,PE(),{"ok":True},"MSVCR90.dll","memset",verify))
        self.assertEqual(len(cpu.writes),1)
        self.assertEqual(cpu.writes[0][0],cpu.DST)
        self.assertEqual(len(cpu.writes[0][1]),4666112)
        self.assertEqual(cpu.writes[0][1].count(0),4666112)
        self.assertEqual(cpu.reg_read(UC_X86_REG_RAX),cpu.DST)
        self.assertEqual(mem.summary()["synthetic_original_image_memset_count"],3)
        with self.assertRaisesRegex(GuestHeapResearchRejected,"abi_mismatch"):
            mem.handle_image_memset(
                cpu,PE(),{"ok":True},"MSVCR90.dll","memset",verify)
    def test_bad_original_abi_or_unsafe_pe_permissions_rejected_without_write(self):
        for cpu,pe,slots in (
            (CPU(length=4666111),PE(),{"ok":True}),
            (CPU(fill=1),PE(),{"ok":True}),
            (CPU(ret=IMAGE_BASE+FOURTH_MEMSET_RETURN_RVA+1),PE(),{"ok":True}),
            (CPU(dst=IMAGE_BASE+0xF00000),PE(),{"ok":True}),
            (CPU(),PE(flags=IMAGE_SCN_MEM_WRITE|IMAGE_SCN_MEM_EXECUTE),{"ok":True}),
            (CPU(),PE(flags=0),{"ok":True}),
            (CPU(),PE(vsize=0x200000),{"ok":True}),
            (CPU(output_mapped=False),PE(),{"ok":True}),
            (CPU(),PE(),{}),
        ):
            mem=ready()
            with self.assertRaises(GuestHeapResearchRejected):
                mem.handle_image_memset(
                    cpu,pe,slots,"MSVCR90.dll","memset",verify)
            self.assertEqual(cpu.writes,[])
            self.assertEqual(cpu.reg_read(UC_X86_REG_RAX),0xBAD)
    def test_reject_out_of_sequence(self):
        cpu=CPU();mem=ready();mem.sprintf_events=[]
        with self.assertRaises(GuestHeapResearchRejected):
            mem.handle_image_memset(cpu,PE(),{"ok":True},"MSVCR90.dll","memset",verify)
if __name__=="__main__":
    unittest.main()
