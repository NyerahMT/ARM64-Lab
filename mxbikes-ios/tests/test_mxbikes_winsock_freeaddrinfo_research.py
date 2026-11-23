"""Synthetic Windows guest addrinfo deallocation with exact original call."""
import struct,sys,unittest
from pathlib import Path
from unicorn.x86_const import UC_X86_REG_RSP,UC_X86_REG_RAX,UC_X86_REG_RCX
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"scripts"))
from mxbikes_winsock_startup_research import (
    OfflineWinsockResearch,OfflineWinsockRejected,
    IMAGE_BASE,AF_INET_WINDOWS,ADDRINFO_HEAD,ADDRINFO_SOCKADDR,
    ADDRINFO_MOCK_BASE,ADDRINFO_MOCK_SIZE,WIN64_ADDRINFO_SIZE,
    FREEADDRINFO_CALL_RVA,FREEADDRINFO_RETURN_RVA,
)
class Guest:
    RSP=0x770040008
    def __init__(self,head=ADDRINFO_HEAD,return_pc=IMAGE_BASE+FREEADDRINFO_RETURN_RVA,
                 mutated=False):
        self.regs={UC_X86_REG_RSP:self.RSP,UC_X86_REG_RCX:head,UC_X86_REG_RAX:0xAD}
        self.ret=return_pc
        self.unmaps=[]
        self.mutated=mutated
    def reg_read(self,r):return self.regs[r]
    def reg_write(self,r,v):self.regs[r]=v
    def mem_read(self,addr,n):
        if addr==self.RSP and n==8:return struct.pack("<Q",self.ret)
        if addr==ADDRINFO_HEAD and n==WIN64_ADDRINFO_SIZE:
            data=struct.pack("<iiiiQQQQ",0,AF_INET_WINDOWS,1,6,16,0,
                             ADDRINFO_SOCKADDR,0)
            return b"X"+data[1:] if self.mutated else data
        if addr==ADDRINFO_SOCKADDR and n==16:
            return bytes((2,0,0,0,127,0,0,1,0,0,0,0,0,0,0,0))
        raise ValueError("unmapped")
    def mem_unmap(self,addr,sz):self.unmaps.append((addr,sz))

def verified(_,ret,lib,sym,slots):
    if slots.get("ok") and lib.lower()=="ws2_32.dll" and sym=="freeaddrinfo" and ret==IMAGE_BASE+FREEADDRINFO_RETURN_RVA:
        return hex(FREEADDRINFO_CALL_RVA)
    return None

def ready():
    s=OfflineWinsockResearch()
    s.addrinfo_events=[{"original":True}]
    s.followup_pton_events=[{"original":True}]
    return s

class GuestFreeAddrInfoTests(unittest.TestCase):
    def test_exact_original_free_clears_our_synthetic_guest_page(self):
        u=Guest();s=ready()
        self.assertTrue(s.handle_freeaddrinfo(
            u,None,{"ok":True},"WS2_32.dll","freeaddrinfo",verified))
        self.assertEqual(u.unmaps,[(ADDRINFO_MOCK_BASE,ADDRINFO_MOCK_SIZE)])
        self.assertEqual(u.reg_read(UC_X86_REG_RAX),0xAD)
        self.assertEqual(s.summary()["verified_original_guest_freeaddrinfo_handled"],1)
        self.assertFalse(s.summary()["host_network_initialized"])
        with self.assertRaises(OfflineWinsockRejected):
            s.handle_freeaddrinfo(
                u,None,{"ok":True},"WS2_32.dll","freeaddrinfo",verified)

    def test_reject_bad_guest_pointer_wrong_call_and_corruption(self):
        for u,slots in (
            (Guest(head=0),{"ok":True}),
            (Guest(head=ADDRINFO_HEAD+8),{"ok":True}),
            (Guest(return_pc=IMAGE_BASE+FREEADDRINFO_RETURN_RVA+1),{"ok":True}),
            (Guest(mutated=True),{"ok":True}),
            (Guest(),{}),
        ):
            s=ready()
            with self.assertRaises(OfflineWinsockRejected):
                s.handle_freeaddrinfo(
                    u,None,slots,"WS2_32.dll","freeaddrinfo",verified)
            self.assertEqual(u.unmaps,[])
            self.assertEqual(u.reg_read(UC_X86_REG_RAX),0xAD)
        u=Guest();s=OfflineWinsockResearch()
        with self.assertRaises(OfflineWinsockRejected):
            s.handle_freeaddrinfo(
                u,None,{"ok":True},"WS2_32.dll","freeaddrinfo",verified)

if __name__=="__main__":unittest.main()
