"""Third original 3776-byte CRT memset after IPv4 sprintf, guest-only."""
import struct,sys,unittest
from pathlib import Path
from unicorn.x86_const import UC_X86_REG_RSP,UC_X86_REG_RAX,UC_X86_REG_RCX,UC_X86_REG_RDX,UC_X86_REG_R8
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"scripts"))
from mxbikes_crt_guest_malloc_research import (
    SingleGuestMallocResearch,GuestHeapResearchRejected,
    IMAGE_BASE,IMAGE_SCN_MEM_WRITE,IMAGE_SCN_MEM_EXECUTE,
    THIRD_MEMSET_CALL_RVA,THIRD_MEMSET_RETURN_RVA,THIRD_MEMSET_LENGTH
)

class PE:
    def __init__(self,flags=IMAGE_SCN_MEM_WRITE):
        self.sections=[(".data",0x2000,0x398000,0x2000,0,flags)]

class Guest:
    DST=IMAGE_BASE+0x399000
    RSP=0x750040008
    def __init__(self,*,return_pc=IMAGE_BASE+THIRD_MEMSET_RETURN_RVA,
                 length=THIRD_MEMSET_LENGTH,dst=DST,fill=0,output_mapped=True):
        self.ret=return_pc;self.output_mapped=output_mapped
        self.regs={UC_X86_REG_RSP:self.RSP,UC_X86_REG_RCX:dst,
                   UC_X86_REG_RDX:fill,UC_X86_REG_R8:length,UC_X86_REG_RAX:0xBAD}
        self.writes=[]
    def reg_read(self,r):return self.regs[r]
    def reg_write(self,r,v):self.regs[r]=v
    def mem_read(self,p,n):
        if p==self.RSP and n==8:return struct.pack("<Q",self.ret)
        if p==self.regs[UC_X86_REG_RCX] and n==THIRD_MEMSET_LENGTH and self.output_mapped:
            return b"Z"*n
        raise ValueError("unmapped")
    def mem_write(self,p,data):self.writes.append((p,bytes(data)))

def verify(_,ret,library,symbol,slots):
    if (slots.get("ok") and ret==IMAGE_BASE+THIRD_MEMSET_RETURN_RVA
        and library.lower()=="msvcr90.dll" and symbol=="memset"):
        return hex(THIRD_MEMSET_CALL_RVA)
    return None

def prepared():
    m=SingleGuestMallocResearch()
    m.memset_events=[{"initial_guest_heap_zeroed":True}]
    m.image_memset_events=[{"first_image_400_bytes_zeroed":True}]
    m.sprintf_events=[{"original_ipv4_dotted_quad_formatted":True}]
    return m

class ThirdMemsetTest(unittest.TestCase):
    def test_exact_3776_byte_writable_nonexecuting_data_zero(self):
        u=Guest();m=prepared()
        self.assertTrue(m.handle_image_memset(
            u,PE(),{"ok":True},"MSVCR90.dll","memset",verify))
        self.assertEqual(u.writes,[(u.DST,bytes(THIRD_MEMSET_LENGTH))])
        self.assertEqual(u.reg_read(UC_X86_REG_RAX),u.DST)
        self.assertEqual(m.summary()["synthetic_original_image_memset_count"],2)
        self.assertEqual(m.summary()["original_image_memset_events"][-1]["zeroed_original_guest_data_bytes"],3776)
        with self.assertRaisesRegex(GuestHeapResearchRejected,"budget"):
            m.handle_image_memset(
                u,PE(),{"ok":True},"MSVCR90.dll","memset",verify)

    def test_bad_abi_and_unsafe_original_section_fail_without_writes(self):
        for u,pe,slots in (
            (Guest(length=3775),PE(),{"ok":True}),
            (Guest(fill=1),PE(),{"ok":True}),
            (Guest(dst=IMAGE_BASE+0x390000),PE(),{"ok":True}),
            (Guest(return_pc=IMAGE_BASE+THIRD_MEMSET_RETURN_RVA+1),PE(),{"ok":True}),
            (Guest(),PE(IMAGE_SCN_MEM_WRITE|IMAGE_SCN_MEM_EXECUTE),{"ok":True}),
            (Guest(),PE(0),{"ok":True}),
            (Guest(output_mapped=False),PE(),{"ok":True}),
            (Guest(),PE(),{}),
        ):
            m=prepared()
            with self.assertRaises(GuestHeapResearchRejected):
                m.handle_image_memset(
                    u,pe,slots,"MSVCR90.dll","memset",verify)
            self.assertEqual(u.writes,[])
            self.assertEqual(u.reg_read(UC_X86_REG_RAX),0xBAD)

    def test_not_before_ipv4_formatter(self):
        u=Guest();m=prepared()
        m.sprintf_events=[]
        with self.assertRaisesRegex(GuestHeapResearchRejected,"before_original_ipv4_sprintf"):
            m.handle_image_memset(u,PE(),{"ok":True},"MSVCR90.dll","memset",verify)

if __name__=="__main__":unittest.main()
