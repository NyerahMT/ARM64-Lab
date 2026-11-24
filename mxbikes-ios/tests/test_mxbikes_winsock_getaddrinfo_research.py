"""Research-only numeric-loopback getaddrinfo ABI and guest memory tests.

No game, Steam DLL, host resolver, or real sockets are ever accessed here.
"""
import struct
import sys
import unittest
from pathlib import Path
from unicorn.x86_const import (
    UC_X86_REG_RSP,UC_X86_REG_RAX,UC_X86_REG_RCX,
    UC_X86_REG_RDX,UC_X86_REG_R8,UC_X86_REG_R9,
)
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"scripts"))
from mxbikes_winsock_startup_research import (
    OfflineWinsockResearch,OfflineWinsockRejected,
    IMAGE_BASE,GETADDRINFO_CALL_RVA,GETADDRINFO_RETURN_RVA,
    ADDRINFO_MOCK_BASE,ADDRINFO_MOCK_SIZE,ADDRINFO_HEAD,
    ADDRINFO_SOCKADDR,WIN64_ADDRINFO_SIZE,AF_INET_WINDOWS,
    IPV4_SOCKADDR_BYTES,
)

class Guest:
    NODE=0x770020000
    RESULT=0x770030000
    STACK=0x770040008
    def __init__(self, *, text=b"127.0.0.1"+bytes((0,)), service=0,
                 hints=0, result=RESULT, result_data=bytes(8),
                 return_va=IMAGE_BASE+GETADDRINFO_RETURN_RVA, stack=STACK):
        self.node=text
        self.result_data=result_data
        self.ret=return_va
        self.reg={
            UC_X86_REG_RSP:stack,
            UC_X86_REG_RCX:self.NODE,
            UC_X86_REG_RDX:service,
            UC_X86_REG_R8:hints,
            UC_X86_REG_R9:result,
            UC_X86_REG_RAX:0xBADD,
        }
        self.writes=[]
        self.maps=[]
    def reg_read(self,reg):return self.reg[reg]
    def reg_write(self,reg,value):self.reg[reg]=value
    def mem_read(self,addr,n):
        if addr==self.reg[UC_X86_REG_RSP] and n==8:
            return struct.pack("<Q",self.ret)
        if self.NODE<=addr<self.NODE+len(self.node) and n==1:
            return self.node[addr-self.NODE:addr-self.NODE+1]
        if addr==self.reg[UC_X86_REG_R9] and n==8:
            return self.result_data
        raise ValueError("unmapped fake memory")
    def mem_map(self,addr,length):
        if addr!=ADDRINFO_MOCK_BASE or length!=ADDRINFO_MOCK_SIZE:
            raise ValueError("invalid mock guest map")
        self.maps.append((addr,length))
    def mem_write(self,addr,data):
        self.writes.append((addr,bytes(data)))


def verified(_,ret,library,symbol,slots):
    if (slots.get("ok") and ret==IMAGE_BASE+GETADDRINFO_RETURN_RVA
        and library.lower()=="ws2_32.dll" and symbol=="getaddrinfo"):
        return hex(GETADDRINFO_CALL_RVA)
    return None


def valid_service():
    s=OfflineWinsockResearch()
    s.events=[{"wsa_startup":True}]
    s.pton_events=[{"numeric_ipv4":True}]
    s.nameinfo_events=[{"offline_numeric_fallback_only":True}]
    return s


class GetAddrInfoOriginalResearchTests(unittest.TestCase):
    def test_one_result_has_windows_x64_abi_and_loopback_sockaddr(self):
        guest=Guest()
        service=valid_service()
        self.assertTrue(service.handle_getaddrinfo(
            guest,None,{"ok":True},"WS2_32.dll","getaddrinfo",verified))
        self.assertEqual(guest.reg_read(UC_X86_REG_RAX),0)
        self.assertEqual(guest.maps,[(ADDRINFO_MOCK_BASE,ADDRINFO_MOCK_SIZE)])
        self.assertEqual(len(guest.writes),3)
        writes=dict(guest.writes)
        self.assertEqual(writes[guest.RESULT],struct.pack("<Q",ADDRINFO_HEAD))
        self.assertEqual(len(writes[ADDRINFO_HEAD]),WIN64_ADDRINFO_SIZE)
        self.assertEqual(struct.unpack("<iiiiQQQQ",writes[ADDRINFO_HEAD]),
                         (0,AF_INET_WINDOWS,1,6,16,0,ADDRINFO_SOCKADDR,0))
        self.assertEqual(len(writes[ADDRINFO_SOCKADDR]),IPV4_SOCKADDR_BYTES)
        self.assertEqual(writes[ADDRINFO_SOCKADDR],
                         bytes((2,0,0,0,127,0,0,1,0,0,0,0,0,0,0,0)))
        self.assertEqual(service.summary()["verified_original_guest_getaddrinfo_handled"],1)
        self.assertFalse(service.summary()["host_network_initialized"])
        self.assertFalse(service.summary()["supports_online_play"])
        with self.assertRaisesRegex(OfflineWinsockRejected,"sequence"):
            service.handle_getaddrinfo(
                guest,None,{"ok":True},"WS2_32.dll","getaddrinfo",verified)

    def test_reject_malformed_original_call_without_guest_writes(self):
        cases=[
            (Guest(service=123),{"ok":True}),
            (Guest(hints=0x77),{"ok":True}),
            (Guest(text=b"localhost"+bytes((0,))),{"ok":True}),
            (Guest(text=b"1.2.3.4"+bytes((0,))),{"ok":True}),
            (Guest(text=b"A"*64),{"ok":True}),
            (Guest(return_va=IMAGE_BASE+GETADDRINFO_RETURN_RVA+1),{"ok":True}),
            (Guest(stack=0x770040000),{"ok":True}),
            (Guest(result=0),{"ok":True}),
            (Guest(result=0x770030001),{"ok":True}),
            (Guest(result_data=b"X"*8),{"ok":True}),
            (Guest(),{}),
        ]
        for guest,slots in cases:
            service=valid_service()
            with self.assertRaises(OfflineWinsockRejected):
                service.handle_getaddrinfo(
                    guest,None,slots,"WS2_32.dll","getaddrinfo",verified)
            self.assertEqual(guest.reg_read(UC_X86_REG_RAX),0xBADD)
            self.assertEqual(guest.maps,[])
            self.assertEqual(guest.writes,[])
        no_prior=OfflineWinsockResearch()
        with self.assertRaisesRegex(OfflineWinsockRejected,"sequence"):
            no_prior.handle_getaddrinfo(
                Guest(),None,{"ok":True},"WS2_32.dll","getaddrinfo",verified)

    def test_other_import_never_handled(self):
        guest=Guest();service=valid_service()
        self.assertFalse(service.handle_getaddrinfo(
            guest,None,{"ok":True},"WS2_32.dll","gethostname",verified))
        self.assertEqual(guest.maps,[])
        self.assertEqual(guest.writes,[])

if __name__=="__main__":
    unittest.main()
