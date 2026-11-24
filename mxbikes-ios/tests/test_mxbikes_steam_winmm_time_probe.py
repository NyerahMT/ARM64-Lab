"""Deterministic WinMM clock in research-only SHA-pinned guest environment."""
import struct,sys,unittest
from pathlib import Path
from unicorn.x86_const import UC_X86_REG_RSP,UC_X86_REG_RAX,UC_X86_REG_RCX
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"scripts"))
from mxbikes_steam_winmm_time_probe import (
    WinMMTimeGetTimeResearch,TimeGetTimeProbeRejected,
    IMAGE_BASE,CALL_RVA,RETURN_RVA,SECOND_CALL_RVA,SECOND_RETURN_RVA,BEGIN_PERIOD_CALL_RVA,BEGIN_PERIOD_RETURN_RVA,TEST_CLOCK_MS,MAX_CALLS)

class CPU:
    def __init__(self,ret=IMAGE_BASE+RETURN_RVA,rsp=0x720000008,period=1):
        self.regs={UC_X86_REG_RSP:rsp,UC_X86_REG_RAX:0x9988,
                   UC_X86_REG_RCX:period}
        self.ret=ret
    def reg_read(self,reg):return self.regs[reg]
    def reg_write(self,reg,v):self.regs[reg]=v
    def mem_read(self,addr,n):
        if addr!=self.regs[UC_X86_REG_RSP] or n!=8:
            raise ValueError("unmapped")
        return struct.pack("<Q",self.ret)

def verified(pe,ret,lib,sym,slots):
    if lib.lower()!="winmm.dll" or not slots.get("match"):
        return None
    if sym=="timeGetTime":
        if ret==IMAGE_BASE+RETURN_RVA:return hex(CALL_RVA)
        if ret==IMAGE_BASE+SECOND_RETURN_RVA:return hex(SECOND_CALL_RVA)
    if ret==IMAGE_BASE+BEGIN_PERIOD_RETURN_RVA and sym=="timeBeginPeriod":
        return hex(BEGIN_PERIOD_CALL_RVA)
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

    def test_second_authentic_time_get_time_import_callsite(self):
        clock=WinMMTimeGetTimeResearch()
        cpu=CPU(ret=IMAGE_BASE+SECOND_RETURN_RVA)
        self.assertTrue(clock.handle(cpu,None,{"match":True},
                                     "WINMM.dll","timeGetTime",verified))
        self.assertEqual(cpu.reg_read(UC_X86_REG_RAX),TEST_CLOCK_MS)
        self.assertEqual(clock.summary()["calls"][0]["original_call_rva"],hex(SECOND_CALL_RVA))
        self.assertEqual(clock.summary()["calls"][0]["return_rva"],hex(SECOND_RETURN_RVA))

    def test_unverified_return_and_unmapped_stack_are_denied(self):
        for cpu,slots in ((CPU(ret=IMAGE_BASE+RETURN_RVA+1),{"match":True}),
                          (CPU(rsp=0x720000000),{"match":True}),
                          (CPU(),{})):
            clock=WinMMTimeGetTimeResearch()
            with self.assertRaises(TimeGetTimeProbeRejected):
                clock.handle(cpu,None,slots,"WINMM.dll","timeGetTime",verified)
            self.assertEqual(cpu.reg_read(UC_X86_REG_RAX),0x9988)
            self.assertEqual(clock.summary()["calls"],[])

    def test_bounded_time_begin_period_success_is_host_side_only(self):
        clock=WinMMTimeGetTimeResearch()
        cpu=CPU(ret=IMAGE_BASE+BEGIN_PERIOD_RETURN_RVA,period=1)
        self.assertTrue(clock.handle(cpu,None,{"match":True},
                                     "WINMM.dll","timeBeginPeriod",verified))
        self.assertEqual(cpu.reg_read(UC_X86_REG_RAX),0)
        self.assertEqual(clock.summary()["synthetic_winmm_timebeginperiod_count"],1)
        self.assertEqual(clock.summary()["period_calls"][0]["requested_resolution_ms"],1)
        self.assertFalse(clock.summary()["period_calls"][0]["host_timer_changed"])

    def test_time_begin_period_rejects_unknown_duration_and_wrong_site(self):
        for cpu,slots in (
            (CPU(ret=IMAGE_BASE+BEGIN_PERIOD_RETURN_RVA,period=0),{"match":True}),
            (CPU(ret=IMAGE_BASE+BEGIN_PERIOD_RETURN_RVA,period=17),{"match":True}),
            (CPU(ret=IMAGE_BASE+BEGIN_PERIOD_RETURN_RVA,period=1),{}),
            (CPU(ret=IMAGE_BASE+RETURN_RVA,period=1),{"match":True}),
        ):
            clock=WinMMTimeGetTimeResearch()
            with self.assertRaises(TimeGetTimeProbeRejected):
                clock.handle(cpu,None,slots,"WINMM.dll","timeBeginPeriod",verified)
            self.assertEqual(clock.summary()["period_calls"],[])
            self.assertEqual(cpu.reg_read(UC_X86_REG_RAX),0x9988)

    def test_call_limit_fails_closed(self):
        clock=WinMMTimeGetTimeResearch()
        clock.calls=[{} for _ in range(MAX_CALLS)]
        with self.assertRaisesRegex(TimeGetTimeProbeRejected,"budget"):
            clock.handle(CPU(),None,{"match":True},
                         "WINMM.dll","timeGetTime",verified)

if __name__=="__main__":
    unittest.main()
