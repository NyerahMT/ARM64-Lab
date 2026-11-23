"""Second original getnameinfo numeric-host path after getaddrinfo.

No networking, original executable, or license information in these tests.
"""
import struct,sys,unittest
from pathlib import Path
from unicorn.x86_const import (
    UC_X86_REG_RSP,UC_X86_REG_RAX,UC_X86_REG_RCX,
    UC_X86_REG_RDX,UC_X86_REG_R8,UC_X86_REG_R9
)
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"scripts"))
from mxbikes_winsock_startup_research import (
    OfflineWinsockResearch,OfflineWinsockRejected,IMAGE_BASE,
    FOLLOWUP_GETNAMEINFO_CALL_RVA,FOLLOWUP_GETNAMEINFO_RETURN_RVA,
    NI_NUMERICHOST_WINDOWS,ADDRINFO_SOCKADDR,IPV4_SOCKADDR_BYTES,
    ORIGINAL_GNI_HOST_BUFFER_SIZE
)

class Guest:
    STACK=0x770000008
    HOST=0x770030000
    def __init__(self,*,flags=NI_NUMERICHOST_WINDOWS,
                 sa=ADDRINFO_SOCKADDR,sa_len=IPV4_SOCKADDR_BYTES,
                 node=HOST,node_len=ORIGINAL_GNI_HOST_BUFFER_SIZE,
                 ret=IMAGE_BASE+FOLLOWUP_GETNAMEINFO_RETURN_RVA,
                 addr=bytes((2,0,0,0,127,0,0,1,0,0,0,0,0,0,0,0))):
        self.flags=flags;self.ret=ret;self.addr=addr;self.writes=[]
        self.regs={
            UC_X86_REG_RSP:self.STACK,UC_X86_REG_RAX:0xBAD,
            UC_X86_REG_RCX:sa,UC_X86_REG_RDX:sa_len,
            UC_X86_REG_R8:node,UC_X86_REG_R9:node_len,
        }
    def reg_read(self,r):return self.regs[r]
    def reg_write(self,r,v):self.regs[r]=v
    def mem_read(self,p,n):
        if p==self.STACK and n==8:
            return struct.pack("<Q",self.ret)
        if p==self.STACK+0x28 and n==24:
            return struct.pack("<QQQ",0,0,self.flags)
        if p==ADDRINFO_SOCKADDR and n==16:
            return self.addr
        if p==self.HOST and n==10:
            return bytes(10)
        raise ValueError("unmapped guest memory")
    def mem_write(self,p,data):self.writes.append((p,bytes(data)))

def verified(_,ret,lib,symbol,slots):
    if (slots.get("ok") and lib.lower()=="ws2_32.dll" and
        symbol=="getnameinfo" and ret==IMAGE_BASE+FOLLOWUP_GETNAMEINFO_RETURN_RVA):
        return hex(FOLLOWUP_GETNAMEINFO_CALL_RVA)
    return None

def ready():
    s=OfflineWinsockResearch()
    s.events=[{"wsa":True}]
    s.pton_events=[{"pton":True}]
    s.nameinfo_events=[{"offline_numeric_fallback_only":True}]
    s.addrinfo_events=[{"single_synthetic_tcp_ipv4_result":True}]
    return s

class OriginalFollowupNameInfoTests(unittest.TestCase):
    def test_original_numeric_host_loopback_from_synthetic_addrinfo(self):
        cpu=Guest();service=ready()
        self.assertTrue(service.handle_followup_getnameinfo(
            cpu,None,{"ok":True},"WS2_32.dll","getnameinfo",verified))
        self.assertEqual(cpu.reg_read(UC_X86_REG_RAX),0)
        self.assertEqual(cpu.writes,[(cpu.HOST,b"127.0.0.1"+bytes((0,)))])
        self.assertEqual(service.summary()[
            "verified_original_guest_followup_getnameinfo_handled"],1)
        self.assertTrue(service.summary()["followup_getnameinfo_events"][0]["no_reverse_dns"])
        self.assertEqual(service.summary()["real_sockets_created"],0)
        with self.assertRaises(OfflineWinsockRejected):
            service.handle_followup_getnameinfo(
                cpu,None,{"ok":True},"WS2_32.dll","getnameinfo",verified)

    def test_reject_untrusted_winsock_metadata_before_guest_write(self):
        for cpu,slots in (
            (Guest(flags=0),{"ok":True}),
            (Guest(flags=0x08),{"ok":True}),
            (Guest(sa=ADDRINFO_SOCKADDR+8),{"ok":True}),
            (Guest(sa_len=28),{"ok":True}),
            (Guest(node_len=32),{"ok":True}),
            (Guest(node=0),{"ok":True}),
            (Guest(ret=IMAGE_BASE+FOLLOWUP_GETNAMEINFO_RETURN_RVA+1),{"ok":True}),
            (Guest(addr=bytes(16)),{"ok":True}),
            (Guest(),{}),
        ):
            service=ready()
            with self.assertRaises(OfflineWinsockRejected):
                service.handle_followup_getnameinfo(
                    cpu,None,slots,"WS2_32.dll","getnameinfo",verified)
            self.assertEqual(cpu.reg_read(UC_X86_REG_RAX),0xBAD)
            self.assertEqual(cpu.writes,[])

    def test_no_prior_getaddrinfo_rejected(self):
        service=OfflineWinsockResearch()
        cpu=Guest()
        with self.assertRaises(OfflineWinsockRejected):
            service.handle_followup_getnameinfo(
                cpu,None,{"ok":True},"WS2_32.dll","getnameinfo",verified)

if __name__=="__main__":
    unittest.main()
