"""Deterministic WinMM clock in research-only SHA-pinned guest environment."""
import struct,sys,unittest
from pathlib import Path
from unicorn.x86_const import UC_X86_REG_RSP,UC_X86_REG_RAX
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"scripts"))
from mxbikes_steam_winmm_time_probe import (
    WinMMTimeGetTimeResearch,TimeGetTimeProbeRejected,
    IMAGE_BASE,CALL_RVA,RETURN_RVA,TEST_CLOCK_MS,MAX_CALLS)

class CPU:
    def __init__(self,ret=IMAGE_BASE+RETURN_RVA,rsp=0x720000008):
        self.regs={UC_X86_REG_RSP:rsp,UC_X86_REG_RAX:0x9988}
        self.ret=ret
    def reg_read(self,reg):return self.regs[reg]
    def reg_write(self,reg,v):self.regs[reg]=v
    def mem_read(self,addr,n):
        if addr!=self.regs[UC_X86_REG_RSP] or n!=8:
            raise ValueError("unmapped")
        return struct.pack("<Q",self.ret)

def verified(pe,ret,lib,sym,slots):
    if ret==IMAGE_BASE+RETURN_RVA and lib.lower()=="winmm.dll" and sym=="timeGetTime" and slots.get("match"):
        return hex(CALL_RVA)
    return None

class WinMMTimeResearchTests(unittest.TestCase):
    def test_exact_original_call_and_wrong_import(self):
        clock=WinMMTimeGetTimeResearch()
        cpu=CPU()
        self.assertTrue(clock.handle(cpu,None,{"match":True},
                                     "WINMM.dll","timeGetTime",verified))
        self.assertEqual(cpu.reg_read(UC_X86_REG_RAX),TEST_CLOCK_MS)
        self.assertEqual(clock.summary()["synthetic_deterministic_winmm_timegettime_count"],1)
        self.assertFalse(clock.summary()["original_winmm_dll_executed"])
        bad=CPU()
        self.assertFalse(clock.handle(bad,None,{"match":True},
                                      "kernel32.dll","timeGetTime",verified))
        self.assertEqual(bad.reg_read(UC_X86_REG_RAX),0x9988)

    def test_unverified_return_and_unmapped_stack_are_denied(self):
        for cpu,slots in ((CPU(ret=IMAGE_BASE+RETURN_RVA+1),{"match":True}),
                          (CPU(rsp=0x720000000),{"match":True}),
                          (CPU(),{})):
            clock=WinMMTimeGetTimeResearch()
            with self.assertRaises(TimeGetTimeProbeRejected):
                clock.handle(cpu,None,slots,"WINMM.dll","timeGetTime",verified)
            self.assertEqual(cpu.reg_read(UC_X86_REG_RAX),0x9988)
            self.assertEqual(clock.summary()["calls"],[])

    def test_call_limit_fails_closed(self):
        clock=WinMMTimeGetTimeResearch()
        clock.calls=[{} for _ in range(MAX_CALLS)]
        with self.assertRaisesRegex(TimeGetTimeProbeRejected,"budget"):
            clock.handle(CPU(),None,{"match":True},
                         "WINMM.dll","timeGetTime",verified)

if __name__=="__main__":
    unittest.main()
