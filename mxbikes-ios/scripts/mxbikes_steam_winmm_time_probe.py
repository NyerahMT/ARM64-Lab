#!/usr/bin/env python3
"""Audited WinMM timeGetTime import for the *research-only* original x64 runner.

This is a deterministic stand-in for a monotonic millisecond clock, NOT the
native production clock. It permits one authenticated original IAT CALL site
in a SHA-pinned MX Bikes binary and leaves every other time call unsupported.
No game bytes, Steam entitlement, or client state are modified.
"""
from __future__ import annotations
import struct
from unicorn.x86_const import UC_X86_REG_RSP,UC_X86_REG_RAX

CALL_RVA=0x133F24
RETURN_RVA=CALL_RVA+6
MAX_CALLS=64
TEST_CLOCK_MS=0x1A2B3C
IMAGE_BASE=0x140000000

class TimeGetTimeProbeRejected(ValueError):
    pass

class WinMMTimeGetTimeResearch:
    def __init__(self):
        self.calls=[]

    def handle(self, guest, pe, original_slots, library, symbol, verify):
        if library.lower()!="winmm.dll" or symbol!="timeGetTime":
            return False
        if len(self.calls)>=MAX_CALLS:
            raise TimeGetTimeProbeRejected("time_get_time_test_call_budget")
        rsp=guest.reg_read(UC_X86_REG_RSP)
        if rsp&15!=8:
            raise TimeGetTimeProbeRejected("time_get_time_guest_stack_alignment")
        try:
            ret=struct.unpack("<Q",bytes(guest.mem_read(rsp,8)))[0]
        except Exception as exc:
            raise TimeGetTimeProbeRejected("time_get_time_unmapped_return") from exc
        if ret!=IMAGE_BASE+RETURN_RVA or verify(pe,ret,library,symbol,original_slots)!=hex(CALL_RVA):
            raise TimeGetTimeProbeRejected("time_get_time_original_import_mismatch")
        # Windows DWORD return is zero-extended in EAX. No host wall-clock used.
        guest.reg_write(UC_X86_REG_RAX,TEST_CLOCK_MS)
        self.calls.append({
            "original_call_rva":hex(CALL_RVA),
            "return_rva":hex(RETURN_RVA),
            "modeled_ms":TEST_CLOCK_MS,
            "original_windows_function_executed":False,
        })
        return True

    def summary(self):
        return {"synthetic_deterministic_winmm_timegettime_count":len(self.calls),
                "calls":list(self.calls),
                "production_clock_used":False,
                "original_winmm_dll_executed":False}
