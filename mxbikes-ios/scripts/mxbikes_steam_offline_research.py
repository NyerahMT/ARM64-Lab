#!/usr/bin/env python3
"""STRICT opt-in research-only Steam Apps mock for one original MX Bikes call.

This runs only under Unicorn using an owned SHA-pinned original executable.
It is a counterfactual exploration of the original *post-subscription*
control flow. It DOES NOT verify, grant, or persist any Steam entitlement,
cannot be used as a native iOS Steam client, and never writes the EXE/DLL.
All unexpected API interactions stop before they are invoked.
"""
from __future__ import annotations

import struct
from unicorn.x86_const import (
    UC_X86_REG_RAX,UC_X86_REG_RCX,UC_X86_REG_RDX,
    UC_X86_REG_RSP
)
from mxbikes_steam_context_layout import inspect_context_init_data

BASE=0x140000000
CONTEXT_CALL_RVA=0x130710
CONTEXT_RETURN_RVA=0x130716
CONTEXT_DATA_RVA=0x3965D0
CONTEXT_CALLBACK_RVA=0x1301C0
SUBSCRIPTION_RETURN_RVA=0x130725
SUBSCRIPTION_APP_ID=655500
STEAM_APPS_CONTEXT_OFFSET=0x30
STEAM_APPS_SUBSCRIBED_VTABLE_OFFSET=0x30

MOCK_BASE=0x760000000
MOCK_REGION_SIZE=0x1000
APPS_OBJECT=MOCK_BASE+0x100
APPS_VTABLE=MOCK_BASE+0x200
SUBSCRIPTION_METHOD=MOCK_BASE+0x300

class OfflineResearchRejected(ValueError):
    pass

class OfflineAppsResearchProbe:
    def __init__(self):
        self.context_seen=False
        self.method_seen=False
        self.layout=None
        self.synthetic_method_count=0

    def context_init(self,u,image_end):
        """Respond to exactly the verified first ContextInit import call.

        On Win64 the trampoline already has a real return address at RSP.
        Return a pointer to synthetic context storage in original guest RAM.
        All other fields remain absent (zero), as do Steam users and pipes.
        """
        if self.context_seen:
            raise OfflineResearchRejected("unexpected_multiple_context_calls")
        self.layout=inspect_context_init_data(u,BASE,image_end)
        report=self.layout
        if not (report["mapped_data_read"] and
                report["original_image_argument_rva"]==hex(CONTEXT_DATA_RVA) and
                report["initializer_callback_rva"]==hex(CONTEXT_CALLBACK_RVA) and
                report["counter_zero"] and report["cached_interface_pointer_zero"]):
            raise OfflineResearchRejected("unverified_original_steam_context")
        rsp=u.reg_read(UC_X86_REG_RSP)
        if rsp%16!=8:
            raise OfflineResearchRejected("context_win64_stack_alignment")
        try:
            ret=struct.unpack("<Q",bytes(u.mem_read(rsp,8)))[0]
        except Exception as exc:
            raise OfflineResearchRejected("context_unmapped_return") from exc
        if ret!=BASE+CONTEXT_RETURN_RVA:
            raise OfflineResearchRejected("context_original_return_mismatch")
        context=BASE+CONTEXT_DATA_RVA+16
        try:
            # Allocate only a single bounded synthetic object/vtable page.
            u.mem_map(MOCK_BASE,MOCK_REGION_SIZE)
            u.mem_write(APPS_OBJECT,struct.pack("<Q",APPS_VTABLE))
            u.mem_write(APPS_VTABLE+STEAM_APPS_SUBSCRIBED_VTABLE_OFFSET,
                        struct.pack("<Q",SUBSCRIPTION_METHOD))
            u.mem_write(SUBSCRIPTION_METHOD,bytes((0xc3,))) # synthetic RET only
            u.mem_write(context+STEAM_APPS_CONTEXT_OFFSET,
                        struct.pack("<Q",APPS_OBJECT))
        except Exception as exc:
            raise OfflineResearchRejected("mock_guest_memory_unavailable") from exc
        u.reg_write(UC_X86_REG_RAX,context)
        self.context_seen=True

    def subscription_method(self,u):
        """Observe real virtual CALL ABI and model one true *test-only* result.

        The x64 CPU executes the authentic indirect CALL and a one-byte mock
        RET in a separate allocated region; never skip original instructions.
        """
        if not self.context_seen or self.method_seen:
            raise OfflineResearchRejected("mock_subscription_call_unexpected")
        if (u.reg_read(UC_X86_REG_RCX)!=APPS_OBJECT or
            u.reg_read(UC_X86_REG_RDX)!=SUBSCRIPTION_APP_ID):
            raise OfflineResearchRejected("subscription_arguments_mismatch")
        rsp=u.reg_read(UC_X86_REG_RSP)
        if rsp%16!=8:
            raise OfflineResearchRejected("subscription_stack_alignment")
        try:
            ret=struct.unpack("<Q",bytes(u.mem_read(rsp,8)))[0]
        except Exception as exc:
            raise OfflineResearchRejected("subscription_unmapped_return") from exc
        if ret!=BASE+SUBSCRIPTION_RETURN_RVA:
            raise OfflineResearchRejected("subscription_original_return_mismatch")
        u.reg_write(UC_X86_REG_RAX,1)  # Counterfactual, NOT a license verification.
        self.method_seen=True
        self.synthetic_method_count+=1

    def summary(self):
        return {
            "context_init_handled_in_test":self.context_seen,
            "original_subscription_vtable_call_reached":self.method_seen,
            "counterfactual_subscription_true_count":self.synthetic_method_count,
            "steam_entitlement_verified":False,
            "steam_client_running":False,
            "original_game_patched":False,
            "native_ios_game_executed":False,
            "original_context_layout":self.layout,
        }
