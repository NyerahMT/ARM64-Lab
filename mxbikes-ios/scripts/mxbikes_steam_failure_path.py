#!/usr/bin/env python3
"""Observe actual original MX Bikes guest code after *failed* Steam startup.

This is a bounded, opt-in diagnostics adapter, not a Steamworks replacement:
RestartAppIfNecessary=false is a no-relaunch decision; SteamAPI_Init=false
means initialization FAILED. Never supply Steam users, pipe handles, contexts,
ownership, license keys, or interface pointers. Original guest code chooses
the subsequent control flow, which must be inspected separately.
"""
from __future__ import annotations

import struct
import sys
from pathlib import Path

# The canonical public tools/ tree sits at the repository root.
REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from unicorn.x86_const import UC_X86_REG_RAX, UC_X86_REG_RCX, UC_X86_REG_RSP

from mxbikes_first_callee_emu import import_slots

BASE = 0x140000000
RESTART_APP_ID = 655500
STEAM_FAILURE_SITES = {
    "SteamAPI_RestartAppIfNecessary": 0x1306ED,
    "SteamAPI_Init": 0x1306FB,
}
MAX_EVENTS = 4


class SteamFailureProbeRejected(ValueError):
    """Unexpected original callsite, IAT, or guest ABI; do not continue."""


class SteamFailureProbe:
    def __init__(self, pe):
        self.pe = pe
        self.slots = {}
        for rva, lib, name in import_slots(pe):
            if rva in self.slots:
                raise SteamFailureProbeRejected("duplicate original IAT slot")
            self.slots[rva] = (lib.lower(), name)
        self.events = []

    def handle(self, machine, library: str, symbol: str) -> bool:
        """Handle only two *documented failure outcomes*. Others fail closed.

        The caller's hook is at an IAT trampoline containing RET, so setting
        RAX is enough: Unicorn itself executes RET with authentic guest stack.
        """
        if library.lower() != "steam_api64.dll" or symbol not in STEAM_FAILURE_SITES:
            return False
        if len(self.events) >= MAX_EVENTS:
            raise SteamFailureProbeRejected("steam_failure_event_budget")

        call_rva = STEAM_FAILURE_SITES[symbol]
        stack = machine.reg_read(UC_X86_REG_RSP)
        if stack & 15 != 8:
            raise SteamFailureProbeRejected("original_win64_import_stack_alignment")
        try:
            return_va = struct.unpack("<Q", machine.mem_read(stack, 8))[0]
            original = bytes(self.pe.read_rva(call_rva, 6))
        except (ValueError, struct.error, TypeError, OSError) as exc:
            raise SteamFailureProbeRejected("unreadable_guest_return_or_original_call") from exc
        if return_va != BASE + call_rva + 6 or original[:2] != b"\xff\x15":
            raise SteamFailureProbeRejected("original_steam_callsite_mismatch")
        slot = call_rva + 6 + struct.unpack_from("<i", original, 2)[0]
        if self.slots.get(slot) != ("steam_api64.dll", symbol):
            raise SteamFailureProbeRejected("original_steam_iat_mismatch")
        if (symbol == "SteamAPI_RestartAppIfNecessary" and
            machine.reg_read(UC_X86_REG_RCX) != RESTART_APP_ID):
            raise SteamFailureProbeRejected("unexpected_original_steam_app_id")

        # A FALSE Init result is explicitly a *failed* Steam initialization.
        # This reports the game's genuine failure-control-flow behavior, not
        # a success path or a usable authentication/Steamworks context.
        machine.reg_write(UC_X86_REG_RAX, 0)
        self.events.append({
            "original_call_rva": hex(call_rva),
            "original_return_rva": hex(call_rva + 6),
            "api": symbol,
            "observed_test_return": False,
            "auth_or_steam_context_established": False,
        })
        return True

    def summary(self):
        return {
            "mode": "steam_explicit_failure_path",
            "mode_is_opt_in": True,
            "original_guest_steam_calls_given_failure_results": list(self.events),
            "original_guest_steam_failure_return_count": len(self.events),
            "steam_client_initialized": False,
            "license_or_entitlement_granted": False,
            "all_steam_interfaces_implemented": False,
            "guest_execution_after_failure_not_implied": True,
        }
