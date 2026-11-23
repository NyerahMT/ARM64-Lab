#!/usr/bin/env python3
"""Audited WinMM timeGetTime import for the *research-only* original x64 runner.

This is a deterministic stand-in for a monotonic millisecond clock, NOT the
native production clock. It permits one authenticated original IAT CALL site
in a SHA-pinned MX Bikes binary and leaves every other time call unsupported.
No game bytes, Steam entitlement, or client state are modified.
"""
from __future__ import annotations
import struct
from unicorn.x86_const import UC_X86_REG_RSP,UC_X86_REG_RAX,UC_X86_REG_RCX

CALL_RVA=0x133F24
RETURN_RVA=CALL_RVA+6
SECOND_CALL_RVA=0x133F60
SECOND_RETURN_RVA=SECOND_CALL_RVA+6
GET_TIME_ORIGINAL_CALL_RVAS=(CALL_RVA,SECOND_CALL_RVA)
BEGIN_PERIOD_CALL_RVA=0x133F5A
BEGIN_PERIOD_RETURN_RVA=BEGIN_PERIOD_CALL_RVA+6
MAX_CALLS=64
TEST_CLOCK_MS=0x1A2B3C
IMAGE_BASE=0x140000000

class TimeGetTimeProbeRejected(ValueError):
    pass

class WinMMTimeGetTimeResearch:
    def __init__(self):
        self.calls=[]
        self.period_calls=[]

    def handle(self, guest, pe, original_slots, library, symbol, verify):
        if library.lower()!="winmm.dll" or symbol not in ("timeGetTime","timeBeginPeriod"):
            return False
        is_begin = symbol == "timeBeginPeriod"
        if len(self.period_calls if is_begin else self.calls)>=MAX_CALLS:
            raise TimeGetTimeProbeRejected("winmm_research_call_budget")
        rsp=guest.reg_read(UC_X86_REG_RSP)
        if rsp&15!=8:
            raise TimeGetTimeProbeRejected("time_get_time_guest_stack_alignment")
        try:
            ret=struct.unpack("<Q",bytes(guest.mem_read(rsp,8)))[0]
        except Exception as exc:
            raise TimeGetTimeProbeRejected("time_get_time_unmapped_return") from exc
        if is_begin:
            call,return_rva=BEGIN_PERIOD_CALL_RVA,BEGIN_PERIOD_RETURN_RVA
            valid = (ret==IMAGE_BASE+return_rva and
                     verify(pe,ret,library,symbol,original_slots)==hex(call))
        else:
            call=ret-IMAGE_BASE-6
            return_rva=call+6
            valid=(call in GET_TIME_ORIGINAL_CALL_RVAS and
                   verify(pe,ret,library,symbol,original_slots)==hex(call))
        if not valid:
            raise TimeGetTimeProbeRejected("winmm_original_import_mismatch")
        if is_begin:
            period = guest.reg_read(UC_X86_REG_RCX) & 0xFFFFFFFF
            if period<1 or period>16:
                raise TimeGetTimeProbeRejected("winmm_unexpected_requested_timer_period")
            # WinMM TIMERR_NOERROR = 0. No actual host scheduling changes.
            guest.reg_write(UC_X86_REG_RAX,0)
            self.period_calls.append({
                "original_call_rva":hex(call),
                "return_rva":hex(return_rva),
                "requested_resolution_ms":period,
                "test_return":0,
                "host_timer_changed":False,
            })
        else:
            # Windows DWORD return is zero-extended in EAX. No host wall-clock used.
            guest.reg_write(UC_X86_REG_RAX,TEST_CLOCK_MS)
            self.calls.append({
                "original_call_rva":hex(call),
                "return_rva":hex(return_rva),
                "modeled_ms":TEST_CLOCK_MS,
                "original_windows_function_executed":False,
            })
        return True

    def summary(self):
        return {"synthetic_deterministic_winmm_timegettime_count":len(self.calls),
                "synthetic_winmm_timebeginperiod_count":len(self.period_calls),
                "calls":list(self.calls),
                "period_calls":list(self.period_calls),
                "production_clock_used":False,
                "original_winmm_dll_executed":False}
