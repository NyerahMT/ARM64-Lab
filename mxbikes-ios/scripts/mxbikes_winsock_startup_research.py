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
import ipaddress
from unicorn.x86_const import (
    UC_X86_REG_RSP, UC_X86_REG_RAX, UC_X86_REG_RCX, UC_X86_REG_RDX,
    UC_X86_REG_R8, UC_X86_REG_R9
)

IMAGE_BASE=0x140000000
WSA_STARTUP_CALL_RVA=0x284EC3
WSA_STARTUP_RETURN_RVA=WSA_STARTUP_CALL_RVA+6
INET_PTON_CALL_RVA=0x284D26
INET_PTON_RETURN_RVA=INET_PTON_CALL_RVA+6
GETNAMEINFO_CALL_RVA=0x284D4C
GETNAMEINFO_RETURN_RVA=GETNAMEINFO_CALL_RVA+6
ORIGINAL_SOCKADDR_LENGTH=28
ORIGINAL_GNI_HOST_BUFFER_SIZE=1025
MAX_IP_TEXT_BYTES=64
AF_INET_WINDOWS=2
AF_INET6_WINDOWS=23
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
        self.pton_events=[]
        self.nameinfo_events=[]

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

    def handle_inet_pton(self,guest,pe,slots,library,symbol,verify):
        """Execute one exact original inet_pton CALL without creating sockets.

        Validates native Win64 ABI, original callsite, and source terminator;
        only writes the 4/16-byte binary address after a complete mapped
        guest destination preflight. Never transmits anything over a network.
        """
        if library.lower()!="ws2_32.dll" or symbol!="inet_pton":
            return False
        if not self.events or self.pton_events:
            raise OfflineWinsockRejected("inet_pton_without_wsa_startup_or_repeat")
        rsp=guest.reg_read(UC_X86_REG_RSP)
        family=guest.reg_read(UC_X86_REG_RCX)
        text_ptr=guest.reg_read(UC_X86_REG_RDX)
        output=guest.reg_read(UC_X86_REG_R8)
        if rsp&15!=8:
            raise OfflineWinsockRejected("inet_pton_guest_stack_alignment")
        if family not in (AF_INET_WINDOWS,AF_INET6_WINDOWS):
            raise OfflineWinsockRejected("inet_pton_unsupported_original_family")
        if not text_ptr or not output:
            raise OfflineWinsockRejected("inet_pton_original_null_pointer")
        try:
            ret=struct.unpack("<Q",bytes(guest.mem_read(rsp,8)))[0]
        except Exception as exc:
            raise OfflineWinsockRejected("inet_pton_original_unreadable_return") from exc
        if (ret!=IMAGE_BASE+INET_PTON_RETURN_RVA or
            verify(pe,ret,library,symbol,slots)!=hex(INET_PTON_CALL_RVA)):
            raise OfflineWinsockRejected("inet_pton_original_callsite_mismatch")
        chars=bytearray()
        for i in range(MAX_IP_TEXT_BYTES):
            try:
                ch=bytes(guest.mem_read(text_ptr+i,1))
            except Exception as exc:
                raise OfflineWinsockRejected("inet_pton_original_string_unmapped") from exc
            if len(ch)!=1:
                raise OfflineWinsockRejected("inet_pton_original_string_truncated")
            if ch==bytes((0,)):
                break
            if not 32<=ch[0]<127:
                raise OfflineWinsockRejected("inet_pton_original_nonascii_string")
            chars.extend(ch)
        else:
            raise OfflineWinsockRejected("inet_pton_original_string_unterminated")
        try:
            address=ipaddress.ip_address(chars.decode("ascii"))
            if address.version!=(4 if family==AF_INET_WINDOWS else 6):
                raise ValueError("family mismatch")
        except ValueError:
            guest.reg_write(UC_X86_REG_RAX,0)
            self.pton_events.append({
                "original_call_rva":hex(INET_PTON_CALL_RVA),
                "address_was_valid":False,
                "bytes_written":0,
                "host_network_used":False,
            })
            return True
        output_bytes=address.packed
        if IMAGE_BASE<=output<IMAGE_BASE+0x8000000:
            rva=output-IMAGE_BASE
            if not any((rva>=base and
                        rva-base<=max(vsize,rawsize)-len(output_bytes) and
                        flags&0x80000000 and not flags&0x20000000)
                       for _,vsize,base,rawsize,_,flags in pe.sections):
                raise OfflineWinsockRejected("inet_pton_original_output_not_writable_pe_data")
        try:
            if len(guest.mem_read(output,len(output_bytes)))!=len(output_bytes):
                raise OfflineWinsockRejected("inet_pton_original_output_short")
        except OfflineWinsockRejected:
            raise
        except Exception as exc:
            raise OfflineWinsockRejected("inet_pton_original_output_unmapped") from exc
        try:
            guest.mem_write(output,output_bytes)
        except Exception as exc:
            raise OfflineWinsockRejected("inet_pton_original_output_not_writable") from exc
        guest.reg_write(UC_X86_REG_RAX,1)
        self.pton_events.append({
            "original_call_rva":hex(INET_PTON_CALL_RVA),
            "address_was_valid":True,
            "ip_version":address.version,
            "is_unspecified":address.is_unspecified,
            "is_loopback":address.is_loopback,
            "bytes_written":len(output_bytes),
            "host_network_used":False,
        })
        return True

    def handle_getnameinfo(self,guest,pe,slots,library,symbol,verify):
        """Model numeric fallback, NOT reverse DNS, for one original IPv4 query.

        The exact original getnameinfo request has Flags=0, no service buffer,
        and a 1025-byte node buffer. Windows can return numeric IP text when
        a name is unavailable and NI_NAMEREQD was not set. We deliberately do
        not resolve names or contact the network. Unverified requests fail.
        """
        if library.lower()!="ws2_32.dll" or symbol!="getnameinfo":
            return False
        if not self.pton_events or self.nameinfo_events:
            raise OfflineWinsockRejected("getnameinfo_not_in_original_sequence")
        rsp=guest.reg_read(UC_X86_REG_RSP)
        sockaddr=guest.reg_read(UC_X86_REG_RCX)
        sockaddr_len=guest.reg_read(UC_X86_REG_RDX)
        node=guest.reg_read(UC_X86_REG_R8)
        node_len=guest.reg_read(UC_X86_REG_R9)
        if rsp&15!=8:
            raise OfflineWinsockRejected("getnameinfo_original_win64_stack_alignment")
        if (not sockaddr or not node or
            sockaddr_len!=ORIGINAL_SOCKADDR_LENGTH or
            node_len!=ORIGINAL_GNI_HOST_BUFFER_SIZE):
            raise OfflineWinsockRejected("getnameinfo_original_buffer_sizes_changed")
        try:
            ret=struct.unpack("<Q",bytes(guest.mem_read(rsp,8)))[0]
            service,service_len,flags=struct.unpack(
                "<QQQ",bytes(guest.mem_read(rsp+0x28,24)))
        except Exception as exc:
            raise OfflineWinsockRejected("getnameinfo_unreadable_guest_stack") from exc
        if (ret!=IMAGE_BASE+GETNAMEINFO_RETURN_RVA or
            verify(pe,ret,library,symbol,slots)!=hex(GETNAMEINFO_CALL_RVA)):
            raise OfflineWinsockRejected("getnameinfo_original_import_mismatch")
        if service or service_len or flags:
            raise OfflineWinsockRejected("getnameinfo_guest_dns_or_service_policy_changed")
        try:
            binary=bytes(guest.mem_read(sockaddr,16))
        except Exception as exc:
            raise OfflineWinsockRejected("getnameinfo_unreadable_sockaddr") from exc
        if len(binary)!=16 or struct.unpack_from("<H",binary,0)[0]!=AF_INET_WINDOWS:
            raise OfflineWinsockRejected("getnameinfo_original_not_ipv4")
        address=ipaddress.IPv4Address(binary[4:8])
        output=(str(address).encode("ascii")+bytes((0,)))
        if len(output)>node_len:
            raise OfflineWinsockRejected("getnameinfo_original_node_buffer_too_small")
        if IMAGE_BASE<=node<IMAGE_BASE+0x8000000:
            rva=node-IMAGE_BASE
            if not any((rva>=base and
                        rva-base<=max(vsize,rawsize)-len(output) and
                        f&0x80000000 and not f&0x20000000)
                       for _,vsize,base,rawsize,_,f in pe.sections):
                raise OfflineWinsockRejected("getnameinfo_node_not_writable_pe_data")
        try:
            if len(guest.mem_read(node,len(output)))!=len(output):
                raise OfflineWinsockRejected("getnameinfo_unmapped_node_buffer")
        except OfflineWinsockRejected:
            raise
        except Exception as exc:
            raise OfflineWinsockRejected("getnameinfo_unmapped_node_buffer") from exc
        try:
            guest.mem_write(node,output)
        except Exception as exc:
            raise OfflineWinsockRejected("getnameinfo_node_not_writable") from exc
        guest.reg_write(UC_X86_REG_RAX,0)
        self.nameinfo_events.append({
            "original_call_rva":hex(GETNAMEINFO_CALL_RVA),
            "offline_numeric_fallback_only":True,
            "reverse_dns_performed":False,
            "is_loopback":address.is_loopback,
            "is_unspecified":address.is_unspecified,
            "host_text_bytes_written":len(output),
            "service_text_written":False,
        })
        return True

    def summary(self):
        return {
            "verified_original_guest_wsa_startup_handled":len(self.events),
            "events":list(self.events),
            "verified_original_guest_inet_pton_handled":len(self.pton_events),
            "inet_pton_events":list(self.pton_events),
            "verified_original_guest_getnameinfo_handled":len(self.nameinfo_events),
            "getnameinfo_events":list(self.nameinfo_events),
            "real_winsock_library_executed":False,
            "host_network_initialized":False,
            "real_sockets_created":0,
            "supports_online_play":False,
        }
