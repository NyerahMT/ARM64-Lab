"""Second original inet_pton IPv4 import contract after numerical getnameinfo."""
import struct,sys,unittest
from pathlib import Path
from unicorn.x86_const import UC_X86_REG_RSP,UC_X86_REG_RAX,UC_X86_REG_RCX,UC_X86_REG_RDX,UC_X86_REG_R8
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"scripts"))
from mxbikes_winsock_startup_research import (
    OfflineWinsockResearch,OfflineWinsockRejected,
    IMAGE_BASE,FOLLOWUP_INET_PTON_CALL_RVA,FOLLOWUP_INET_PTON_RETURN_RVA,
    AF_INET_WINDOWS
)

class FakePE:
    def __init__(self,flags=0x80000000):
        self.sections=[(".data",0x2000,0x390000,0x2000,0,flags)]

class FakeGuest:
    RSP=0x750000008
    SOURCE=0x750001000
    DEST=IMAGE_BASE+0x390400
    def __init__(self,*,text=b"127.0.0.1"+bytes((0,)),family=AF_INET_WINDOWS,
                 dest=DEST,return_va=IMAGE_BASE+FOLLOWUP_INET_PTON_RETURN_RVA):
        self.text=text;self.ret=return_va;self.writes=[]
        self.regs={UC_X86_REG_RSP:self.RSP,UC_X86_REG_RCX:family,
                   UC_X86_REG_RDX:self.SOURCE,UC_X86_REG_R8:dest,
                   UC_X86_REG_RAX:0xBADD}
    def reg_read(self,r):return self.regs[r]
    def reg_write(self,r,v):self.regs[r]=v
    def mem_read(self,p,n):
        if p==self.RSP and n==8:return struct.pack("<Q",self.ret)
        if self.SOURCE<=p<self.SOURCE+len(self.text) and n==1:
            return self.text[p-self.SOURCE:p-self.SOURCE+1]
        if p==self.DEST and n==4:return bytes(4)
        raise ValueError("unmapped")
    def mem_write(self,p,data):self.writes.append((p,bytes(data)))

def verify(_,ret,lib,symbol,slots):
    if (slots.get("ok") and lib.lower()=="ws2_32.dll" and symbol=="inet_pton"
        and ret==IMAGE_BASE+FOLLOWUP_INET_PTON_RETURN_RVA):
        return hex(FOLLOWUP_INET_PTON_CALL_RVA)
    return None

def ready():
    s=OfflineWinsockResearch()
    s.pton_events=[{"first_pton":True}]
    s.nameinfo_events=[{"offline_numeric_fallback_only":True}]
    s.addrinfo_events=[{"loopback":True}]
    s.followup_nameinfo_events=[{"numeric":True}]
    return s

class FollowupPtonTests(unittest.TestCase):
    def test_exact_original_call_writes_four_guest_ipv4_bytes(self):
        cpu=FakeGuest();shim=ready()
        self.assertTrue(shim.handle_followup_inet_pton(
            cpu,FakePE(),{"ok":True},"WS2_32.dll","inet_pton",verify))
        self.assertEqual(cpu.writes,[(cpu.DEST,bytes((127,0,0,1)))])
        self.assertEqual(cpu.reg_read(UC_X86_REG_RAX),1)
        self.assertEqual(shim.summary()["verified_original_guest_followup_inet_pton_handled"],1)
        self.assertFalse(shim.summary()["host_network_initialized"])
        with self.assertRaisesRegex(OfflineWinsockRejected,"sequence"):
            shim.handle_followup_inet_pton(
                cpu,FakePE(),{"ok":True},"WS2_32.dll","inet_pton",verify)

    def test_unsafe_original_guest_addresses_and_calls_fail_closed(self):
        for cpu,pe,slots in (
            (FakeGuest(family=23),FakePE(),{"ok":True}),
            (FakeGuest(text=b"8.8.8.8"+bytes((0,))),FakePE(),{"ok":True}),
            (FakeGuest(text=b"X"*64),FakePE(),{"ok":True}),
            (FakeGuest(return_va=IMAGE_BASE+FOLLOWUP_INET_PTON_RETURN_RVA+1),FakePE(),{"ok":True}),
            (FakeGuest(dest=IMAGE_BASE+0x390500),FakePE(),{"ok":True}),
            (FakeGuest(),FakePE(0x20000000|0x80000000),{"ok":True}),
            (FakeGuest(),FakePE(0),{"ok":True}),
            (FakeGuest(),FakePE(),{}),
        ):
            shim=ready()
            with self.assertRaises(OfflineWinsockRejected):
                shim.handle_followup_inet_pton(
                    cpu,pe,slots,"WS2_32.dll","inet_pton",verify)
            self.assertEqual(cpu.writes,[])
            self.assertEqual(cpu.reg_read(UC_X86_REG_RAX),0xBADD)

    def test_requires_previous_nameinfo_and_addrinfo(self):
        cpu=FakeGuest();shim=OfflineWinsockResearch()
        with self.assertRaises(OfflineWinsockRejected):
            shim.handle_followup_inet_pton(
                cpu,FakePE(),{"ok":True},"WS2_32.dll","inet_pton",verify)

if __name__=="__main__":
    unittest.main()
