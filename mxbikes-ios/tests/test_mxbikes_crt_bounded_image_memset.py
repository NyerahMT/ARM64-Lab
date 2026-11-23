"""Audited additional original guest CRT zero fills after fixed startup calls.

Only synthetic Win64 CPU / PE section fixtures, no original game assets.
"""
import struct,sys,unittest
from pathlib import Path
from unicorn.x86_const import (
    UC_X86_REG_RSP,UC_X86_REG_RAX,UC_X86_REG_RCX,
    UC_X86_REG_RDX,UC_X86_REG_R8,
)
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"scripts"))
from mxbikes_crt_guest_malloc_research import (
    IMAGE_BASE, IMAGE_MEMSET_STEPS, IMAGE_SCN_MEM_WRITE, IMAGE_SCN_MEM_EXECUTE,
    BOUNDED_IMAGE_MEMSET_MAX_CALLS, BOUNDED_IMAGE_MEMSET_MAX_BYTES,
    BOUNDED_IMAGE_MEMSET_TOTAL_LIMIT,
    SingleGuestMallocResearch,GuestHeapResearchRejected,
)
ORIGINAL_CALL=0x1b970f
ORIGINAL_RETURN=ORIGINAL_CALL+5
SIZE=24928

class PE:
    def __init__(self,*,flags=IMAGE_SCN_MEM_WRITE,span=0x200000):
        self.sections=[(".data",span,0x390000,span,0,flags)]

class CPU:
    DEST=IMAGE_BASE+0x395000
    STACK=0x770050008
    def __init__(self,*,call_return=IMAGE_BASE+ORIGINAL_RETURN,
                 size=SIZE,fill=0,dst=DEST,mapped=True):
        self.ret=call_return
        self.mapped=mapped
        self.regs={UC_X86_REG_RSP:self.STACK,UC_X86_REG_RAX:0xBADD,
                   UC_X86_REG_RCX:dst,UC_X86_REG_RDX:fill,UC_X86_REG_R8:size}
        self.writes=[]
    def reg_read(self,reg):return self.regs[reg]
    def reg_write(self,reg,val):self.regs[reg]=val
    def mem_read(self,addr,length):
        if addr==self.STACK and length==8:
            return struct.pack("<Q",self.ret)
        if addr==self.regs[UC_X86_REG_RCX] and length==self.regs[UC_X86_REG_R8] and self.mapped:
            return bytes(length)
        raise ValueError("unmapped guest")
    def mem_write(self,addr,data):self.writes.append((addr,bytes(data)))

def verified(_,ret,library,symbol,slots):
    if not slots.get("ok") or library.lower()!="msvcr90.dll" or symbol!="memset":
        return None
    if ret==IMAGE_BASE+ORIGINAL_RETURN:
        return hex(ORIGINAL_CALL)
    if ret==IMAGE_BASE+IMAGE_MEMSET_STEPS[-1][1]:
        return hex(IMAGE_MEMSET_STEPS[-1][0])
    return None

def ready():
    bridge=SingleGuestMallocResearch()
    bridge.called=True
    bridge.memset_events=[{"guest_heap_zeroed":True}]
    bridge.image_memset_events=[
        {"original_call_rva":hex(call),
         "zeroed_original_guest_data_bytes":length}
        for call,_,length in IMAGE_MEMSET_STEPS
    ]
    bridge.sprintf_events=[{"ipv4":True}]
    bridge.second_malloc_events=[{"bytes":48}]
    return bridge

class AdditionalGuestImageMemsetTests(unittest.TestCase):
    def test_real_following_24928_byte_original_call_in_writable_data(self):
        bridge=ready();cpu=CPU()
        self.assertTrue(bridge.handle_bounded_image_memset(
            cpu,PE(),{"ok":True},"MSVCR90.dll","memset",verified))
        self.assertEqual(cpu.reg_read(UC_X86_REG_RAX),cpu.DEST)
        self.assertEqual(cpu.writes,[(cpu.DEST,bytes(SIZE))])
        record=bridge.summary()
        self.assertEqual(record["bounded_original_image_memset_count"],1)
        self.assertEqual(record["bounded_original_image_memset_total_bytes"],SIZE)
        self.assertEqual(record["bounded_original_image_memset_events"][0]["original_call_rva"],hex(ORIGINAL_CALL))
        self.assertFalse(record["original_windows_crt_executed"])

    def test_untrusted_import_or_memory_permissions_cannot_modify_guest(self):
        samples=[
            (CPU(call_return=IMAGE_BASE+ORIGINAL_RETURN+1),PE(),{"ok":True}),
            (CPU(),PE(),{}),
            (CPU(size=0),PE(),{"ok":True}),
            (CPU(size=BOUNDED_IMAGE_MEMSET_MAX_BYTES+1),PE(),{"ok":True}),
            (CPU(fill=1),PE(),{"ok":True}),
            (CPU(dst=IMAGE_BASE+0x1000),PE(),{"ok":True}),
            (CPU(dst=0x710000000),PE(),{"ok":True}),
            (CPU(),PE(flags=IMAGE_SCN_MEM_EXECUTE|IMAGE_SCN_MEM_WRITE),{"ok":True}),
            (CPU(),PE(flags=0),{"ok":True}),
            (CPU(),PE(span=0x5000),{"ok":True}),
            (CPU(mapped=False),PE(),{"ok":True}),
            (CPU(call_return=IMAGE_BASE+IMAGE_MEMSET_STEPS[-1][1]),PE(),{"ok":True}),
        ]
        for cpu,pe,slots in samples:
            bridge=ready()
            with self.assertRaises(GuestHeapResearchRejected):
                bridge.handle_bounded_image_memset(
                    cpu,pe,slots,"MSVCR90.dll","memset",verified)
            self.assertEqual(cpu.reg_read(UC_X86_REG_RAX),0xBADD)
            self.assertEqual(cpu.writes,[])
            self.assertEqual(bridge.summary()["bounded_original_image_memset_count"],0)

    def test_sequence_and_budgets_fail_closed(self):
        cpu=CPU()
        bridge=ready()
        bridge.second_malloc_events=[]
        with self.assertRaisesRegex(GuestHeapResearchRejected,"prerequisite"):
            bridge.handle_bounded_image_memset(
                cpu,PE(),{"ok":True},"MSVCR90.dll","memset",verified)
        bridge=ready()
        bridge.bounded_image_memset_events=[
            {"zeroed_original_guest_data_bytes":1}
            for _ in range(BOUNDED_IMAGE_MEMSET_MAX_CALLS)]
        with self.assertRaisesRegex(GuestHeapResearchRejected,"call_budget"):
            bridge.handle_bounded_image_memset(
                cpu,PE(),{"ok":True},"MSVCR90.dll","memset",verified)
        bridge=ready()
        bridge.bounded_image_memset_events=[
            {"zeroed_original_guest_data_bytes":BOUNDED_IMAGE_MEMSET_TOTAL_LIMIT}]
        with self.assertRaisesRegex(GuestHeapResearchRejected,"aggregate_budget"):
            bridge.handle_bounded_image_memset(
                cpu,PE(),{"ok":True},"MSVCR90.dll","memset",verified)
        self.assertEqual(cpu.writes,[])

if __name__=="__main__":
    unittest.main()
