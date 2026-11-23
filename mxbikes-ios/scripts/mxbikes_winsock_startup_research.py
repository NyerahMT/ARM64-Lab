#!/usr/bin/env python3
"""Bounded, offline-only WSAStartup (WS2_32 ordinal 115) original-guest probe.

The owned, SHA-verified MX Bikes x64 startup requests Winsock version 2.0,
and calls through its verified original IAT at RVA 0x284ec3. This diagnostic
populates an ABI-correct Win64 WSADATA record in Unicorn GUEST memory only.
No host socket is created, no online traffic or Steam context is established.
All other Winsock services remain unsupported (fail closed).
"""
from __future__ import annotations
import struct
from unicorn.x86_const import (
    UC_X86_REG_RSP, UC_X86_REG_RAX, UC_X86_REG_RCX, UC_X86_REG_RDX
)

IMAGE_BASE=0x140000000
WSA_STARTUP_CALL_RVA=0x284EC3
WSA_STARTUP_RETURN_RVA=WSA_STARTUP_CALL_RVA+6
WSA_REQUESTED_VERSION=0x0002
WSA_HIGHEST_VERSION=0x0202
WSADATA64_SIZE=408
WSADATA64_DESCRIPTION_OFFSET=16
WSADATA64_STATUS_OFFSET=273

class OfflineWinsockRejected(ValueError):
    pass


def offline_wsadata64(version_word=WSA_REQUESTED_VERSION):
    """Win64 WSADATA ABI: HH HH Q, char[257], char[129], pad[6].

    Layout verified against the 64-bit winsock2.h definition:
    0-1 wVersion, 2-3 wHighVersion, 4-5 iMaxSockets, 6-7 iMaxUdpDg,
    8-15 lpVendorInfo, 16-272 szDescription, 273-401 szSystemStatus.
    """
    if version_word!=WSA_REQUESTED_VERSION:
        raise OfflineWinsockRejected("unsupported_original_winsock_version")
    data=bytearray(WSADATA64_SIZE)
    struct.pack_into("<HHHHQ",data,0,version_word,WSA_HIGHEST_VERSION,0,0,0)
    desc=b"MXB offline research Winsock guest (no network)"
    status=b"Offline guest only"
    data[WSADATA64_DESCRIPTION_OFFSET:
         WSADATA64_DESCRIPTION_OFFSET+len(desc)]=desc
    data[WSADATA64_STATUS_OFFSET:
         WSADATA64_STATUS_OFFSET+len(status)]=status
    return bytes(data)


class OfflineWinsockResearch:
    def __init__(self):
        self.events=[]

    def handle(self, guest, pe, slots, library, symbol, verify):
        if library.lower()!="ws2_32.dll" or symbol!="#115":
            return False
        if self.events:
            raise OfflineWinsockRejected("additional_wsa_startup_requires_independent_audit")
        rsp=guest.reg_read(UC_X86_REG_RSP)
        version=guest.reg_read(UC_X86_REG_RCX)
        output=guest.reg_read(UC_X86_REG_RDX)
        if rsp&15!=8:
            raise OfflineWinsockRejected("wsa_original_win64_stack_alignment")
        if version!=WSA_REQUESTED_VERSION:
            raise OfflineWinsockRejected("wsa_original_version_changed")
        if not output or output&7:
            raise OfflineWinsockRejected("wsa_original_output_pointer_unaligned")
        try:
            ret=struct.unpack("<Q",bytes(guest.mem_read(rsp,8)))[0]
        except Exception as exc:
            raise OfflineWinsockRejected("wsa_original_stack_unmapped") from exc
        if (ret!=IMAGE_BASE+WSA_STARTUP_RETURN_RVA or
            verify(pe,ret,library,symbol,slots)!=hex(WSA_STARTUP_CALL_RVA)):
            raise OfflineWinsockRejected("wsa_original_import_call_mismatch")
        # Validate that the complete (408 byte) record fits the mapped guest
        # memory range BEFORE modifying any bytes or CPU return registers.
        try:
            if len(guest.mem_read(output,WSADATA64_SIZE))!=WSADATA64_SIZE:
                raise OfflineWinsockRejected("wsa_original_output_short")
        except OfflineWinsockRejected:
            raise
        except Exception as exc:
            raise OfflineWinsockRejected("wsa_original_output_unmapped") from exc
        data=offline_wsadata64(version)
        try:
            guest.mem_write(output,data)
        except Exception as exc:
            raise OfflineWinsockRejected("wsa_original_output_not_writable") from exc
        guest.reg_write(UC_X86_REG_RAX,0)  # WSASUCCESS (synthetic, offline)
        self.events.append({
            "original_iat_call_rva":hex(WSA_STARTUP_CALL_RVA),
            "original_return_rva":hex(WSA_STARTUP_RETURN_RVA),
            "requested_version_word":hex(version),
            "guest_wsadata64_bytes":len(data),
            "win32_wsa_success_return_synthetic":True,
            "network_stack_initialized":False,
        })
        return True

    def summary(self):
        return {
            "verified_original_guest_wsa_startup_handled":len(self.events),
            "events":list(self.events),
            "real_winsock_library_executed":False,
            "host_network_initialized":False,
            "real_sockets_created":0,
            "supports_online_play":False,
        }
