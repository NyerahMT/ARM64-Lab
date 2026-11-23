"""Fail-closed original Steam import callsite validation (source-only fixtures)."""
from pathlib import Path
import struct
import sys
import unittest
from unittest.mock import patch
from unicorn.x86_const import UC_X86_REG_RAX, UC_X86_REG_RCX, UC_X86_REG_RSP

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from mxbikes_steam_failure_path import (
    BASE, RESTART_APP_ID, STEAM_FAILURE_SITES,
    SteamFailureProbe, SteamFailureProbeRejected,
)

SLOTS = {
    "SteamAPI_RestartAppIfNecessary": 0x321A18,
    "SteamAPI_Init": 0x321A20,
}

class SyntheticPE:
    def __init__(self):
        self.code = {
            call: b"\xff\x15" + struct.pack("<i", SLOTS[name]-(call+6))
            for name,call in STEAM_FAILURE_SITES.items()
        }
    def read_rva(self, rva, size):
        if size != 6 or rva not in self.code:
            raise ValueError("synthetic PE out of bounds")
        return self.code[rva]

class FakeCPU:
    def __init__(self, call, app_id=RESTART_APP_ID, rsp=0x71000008):
        self.regs = {
            UC_X86_REG_RAX: 0x1337,
            UC_X86_REG_RCX: app_id,
            UC_X86_REG_RSP: rsp,
        }
        self.return_address = BASE + call + 6
    def reg_read(self, reg):
        return self.regs[reg]
    def reg_write(self, reg, value):
        self.regs[reg] = value
    def mem_read(self, address, size):
        if address != self.regs[UC_X86_REG_RSP] or size != 8:
            raise ValueError("unmapped fake guest stack")
        return struct.pack("<Q", self.return_address)

class SteamFailureProbeTests(unittest.TestCase):
    def setUp(self):
        self.pe = SyntheticPE()

    def probe(self, *, init_success_branch_probe=False):
        # import_slots from the PE reader is overridden only for fixtures.
        from unittest.mock import patch
        imported = [
            (SLOTS[name], "steam_api64.dll", name)
            for name in STEAM_FAILURE_SITES
        ]
        with patch("mxbikes_steam_failure_path.import_slots", return_value=imported):
            return SteamFailureProbe(self.pe,
                init_success_branch_probe=init_success_branch_probe)

    def test_exact_two_original_calls_return_failed_results(self):
        handler = self.probe()
        for symbol, call in STEAM_FAILURE_SITES.items():
            cpu = FakeCPU(call, app_id=RESTART_APP_ID)
            assert handler.handle(cpu, "steam_api64.dll", symbol)
            self.assertEqual(cpu.reg_read(UC_X86_REG_RAX), 0)
            self.assertEqual(cpu.reg_read(UC_X86_REG_RSP), 0x71000008)
            self.assertEqual(cpu.return_address, BASE + call + 6)
        self.assertEqual(handler.summary()[
            "original_guest_steam_failure_return_count"], 2)
        self.assertFalse(handler.summary()["steam_client_initialized"])
        self.assertFalse(handler.summary()["license_or_entitlement_granted"])

    def test_counterfactual_success_is_never_real_authentication(self):
        handler = self.probe(init_success_branch_probe=True)
        for symbol, call in STEAM_FAILURE_SITES.items():
            cpu = FakeCPU(call)
            self.assertTrue(handler.handle(cpu, "steam_api64.dll", symbol))
            self.assertEqual(cpu.reg_read(UC_X86_REG_RAX),
                             int(symbol == "SteamAPI_Init"))
        summary = handler.summary()
        self.assertEqual(summary["original_guest_steam_modeled_return_count"], 2)
        self.assertEqual(summary["original_guest_steam_failure_return_count"], 0)
        self.assertTrue(summary["init_success_is_counterfactual_not_authenticated"])
        self.assertFalse(summary["steam_client_initialized"])
        self.assertFalse(summary["license_or_entitlement_granted"])
        self.assertFalse(summary["all_steam_interfaces_implemented"])
        self.assertTrue(summary["original_guest_steam_calls_given_modeled_returns"][1]
                        ["modeled_test_return"])
        self.assertFalse(summary["original_guest_steam_calls_given_modeled_returns"][0]
                         ["modeled_test_return"])

    def test_does_not_emulate_context_or_other_imports(self):
        handler = self.probe()
        cpu = FakeCPU(STEAM_FAILURE_SITES["SteamAPI_Init"])
        self.assertFalse(handler.handle(cpu, "steam_api64.dll", "SteamInternal_ContextInit"))
        self.assertFalse(handler.handle(cpu, "kernel32.dll", "SteamAPI_Init"))
        self.assertEqual(cpu.reg_read(UC_X86_REG_RAX), 0x1337)
        self.assertEqual(handler.events, [])

    def test_wrong_return_stack_and_appid_rejected_without_state_change(self):
        cases = []
        wrong = FakeCPU(STEAM_FAILURE_SITES["SteamAPI_Init"])
        wrong.return_address += 1
        cases.append(wrong)
        cases.append(FakeCPU(STEAM_FAILURE_SITES["SteamAPI_Init"], rsp=0x71000000))
        cases.append(FakeCPU(STEAM_FAILURE_SITES["SteamAPI_RestartAppIfNecessary"], app_id=1))
        for cpu in cases:
            h = self.probe()
            name = ("SteamAPI_RestartAppIfNecessary"
                    if cpu.reg_read(UC_X86_REG_RCX)==1 else "SteamAPI_Init")
            with self.assertRaises(SteamFailureProbeRejected):
                h.handle(cpu, "steam_api64.dll", name)
            self.assertEqual(cpu.reg_read(UC_X86_REG_RAX), 0x1337)
            self.assertEqual(h.events, [])

    def test_callsite_opcode_and_import_identity_are_mandatory(self):
        from unittest.mock import patch
        h = self.probe()
        rva = STEAM_FAILURE_SITES["SteamAPI_Init"]
        orig = self.pe.code[rva]
        self.pe.code[rva] = b"\x90" + orig[1:]
        with self.assertRaisesRegex(SteamFailureProbeRejected, "callsite"):
            h.handle(FakeCPU(rva), "steam_api64.dll", "SteamAPI_Init")
        self.pe.code[rva] = orig
        h.slots[SLOTS["SteamAPI_Init"]] = ("steam_api64.dll", "SteamAPI_Shutdown")
        with self.assertRaisesRegex(SteamFailureProbeRejected, "iat"):
            h.handle(FakeCPU(rva), "steam_api64.dll", "SteamAPI_Init")

    def test_fail_closed_on_event_budget_and_duplicate_iat(self):
        h = self.probe()
        h.events = [{}] * 4
        with self.assertRaisesRegex(SteamFailureProbeRejected, "budget"):
            h.handle(FakeCPU(STEAM_FAILURE_SITES["SteamAPI_Init"]),
                     "steam_api64.dll", "SteamAPI_Init")
        with patch("mxbikes_steam_failure_path.import_slots", return_value=[
            (0x1000, "steam_api64.dll", "SteamAPI_Init"),
            (0x1000, "kernel32.dll", "GetTickCount")
        ]):
            with self.assertRaisesRegex(SteamFailureProbeRejected, "duplicate"):
                SteamFailureProbe(self.pe)

if __name__ == "__main__":
    unittest.main()
