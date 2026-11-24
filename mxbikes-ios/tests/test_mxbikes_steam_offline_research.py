"""Strict mock context/ISteamApps ABI fixture tests; NO original EXE bytes."""
import struct,sys,unittest
from pathlib import Path
from unicorn.x86_const import UC_X86_REG_RAX,UC_X86_REG_RCX,UC_X86_REG_RDX,UC_X86_REG_RSP
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"scripts"))
from mxbikes_steam_offline_research import (
    BASE, CONTEXT_DATA_RVA, CONTEXT_CALLBACK_RVA, CONTEXT_RETURN_RVA,
    SUBSCRIPTION_RETURN_RVA, SUBSCRIPTION_METHOD, SUBSCRIPTION_APP_ID,
    APPS_OBJECT, STEAM_APPS_CONTEXT_OFFSET,MOCK_BASE,
    OfflineAppsResearchProbe,OfflineResearchRejected
)
class FakeCPU:
    def __init__(self):
        self.regs={
          UC_X86_REG_RAX:0,
          UC_X86_REG_RCX:BASE+CONTEXT_DATA_RVA,
          UC_X86_REG_RDX:0,
          UC_X86_REG_RSP:0x700001008,
        }
        self.writes={}
        self.mem={BASE+CONTEXT_DATA_RVA:struct.pack(
            "<QQQ",BASE+CONTEXT_CALLBACK_RVA,0,0),
            self.regs[UC_X86_REG_RSP]:struct.pack("<Q",BASE+CONTEXT_RETURN_RVA),
        }
    def reg_read(self,r):return self.regs[r]
    def reg_write(self,r,v):self.regs[r]=v
    def mem_read(self,a,n):
        if a not in self.mem or len(self.mem[a])<n:raise ValueError("unmapped")
        return self.mem[a][:n]
    def mem_write(self,a,v):self.mem[a]=bytes(v);self.writes[a]=bytes(v)
    def mem_map(self,a,n):
        if a!=MOCK_BASE or n!=4096:raise ValueError("unexpected mock map")

class OfflineAppsResearchTests(unittest.TestCase):
    def test_bound_context_and_single_subscription(self):
        cpu=FakeCPU()
        bridge=OfflineAppsResearchProbe()
        bridge.context_init(cpu,BASE+0x400000)
        ctx=BASE+CONTEXT_DATA_RVA+16
        self.assertEqual(cpu.reg_read(UC_X86_REG_RAX),ctx)
        self.assertEqual(struct.unpack("<Q",cpu.mem[ctx+STEAM_APPS_CONTEXT_OFFSET])[0],APPS_OBJECT)
        self.assertEqual(cpu.mem[SUBSCRIPTION_METHOD],bytes((0xc3,)))
        cpu.reg_write(UC_X86_REG_RCX,APPS_OBJECT)
        cpu.reg_write(UC_X86_REG_RDX,SUBSCRIPTION_APP_ID)
        cpu.mem[cpu.reg_read(UC_X86_REG_RSP)]=struct.pack("<Q",BASE+SUBSCRIPTION_RETURN_RVA)
        bridge.subscription_method(cpu)
        self.assertEqual(cpu.reg_read(UC_X86_REG_RAX),1)
        self.assertTrue(bridge.summary()["original_subscription_vtable_call_reached"])
        self.assertFalse(bridge.summary()["steam_entitlement_verified"])
        with self.assertRaises(OfflineResearchRejected):
            bridge.subscription_method(cpu)

    def test_wrong_context_and_method_fail_before_response(self):
        cpu=FakeCPU()
        bridge=OfflineAppsResearchProbe()
        cpu.mem[BASE+CONTEXT_DATA_RVA]=struct.pack("<QQQ",BASE+CONTEXT_CALLBACK_RVA,0,1)
        with self.assertRaisesRegex(OfflineResearchRejected,"context"):
            bridge.context_init(cpu,BASE+0x400000)
        self.assertFalse(bridge.summary()["context_init_handled_in_test"])
        cpu=FakeCPU()
        bridge=OfflineAppsResearchProbe()
        bridge.context_init(cpu,BASE+0x400000)
        cpu.reg_write(UC_X86_REG_RCX,APPS_OBJECT)
        cpu.reg_write(UC_X86_REG_RDX,SUBSCRIPTION_APP_ID+1)
        with self.assertRaisesRegex(OfflineResearchRejected,"arguments"):
            bridge.subscription_method(cpu)
        self.assertFalse(bridge.summary()["original_subscription_vtable_call_reached"])

if __name__=="__main__":
    unittest.main()
