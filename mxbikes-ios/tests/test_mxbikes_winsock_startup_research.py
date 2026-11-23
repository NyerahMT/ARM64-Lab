"""No commercial files: verify exact Win64 original WSAStartup import contract."""
import struct,sys,unittest
from pathlib import Path
from unicorn.x86_const import UC_X86_REG_RSP,UC_X86_REG_RAX,UC_X86_REG_RCX,UC_X86_REG_RDX
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"scripts"))
from mxbikes_winsock_startup_research import (
    OfflineWinsockResearch,OfflineWinsockRejected,
    offline_wsadata64,IMAGE_BASE,WSA_STARTUP_CALL_RVA,WSA_STARTUP_RETURN_RVA,
    WSA_REQUESTED_VERSION,WSADATA64_SIZE,WSADATA64_DESCRIPTION_OFFSET,
    WSADATA64_STATUS_OFFSET
)

class Guest:
    def __init__(self,version=WSA_REQUESTED_VERSION,ret=IMAGE_BASE+WSA_STARTUP_RETURN_RVA,
                 output=0x720001100,rsp=0x720000008,valid_buffer=True):
        self.regs={UC_X86_REG_RSP:rsp,UC_X86_REG_RCX:version,
                   UC_X86_REG_RDX:output,UC_X86_REG_RAX:0xBAD}
        self.ret=ret
        self.valid_buffer=valid_buffer
        self.memory_written=[]
    def reg_read(self,r):return self.regs[r]
    def reg_write(self,r,v):self.regs[r]=v
    def mem_read(self,address,length):
        if address==self.regs[UC_X86_REG_RSP] and length==8:
            return struct.pack("<Q",self.ret)
        if address==self.regs[UC_X86_REG_RDX] and length==WSADATA64_SIZE and self.valid_buffer:
            return b"X"*WSADATA64_SIZE
        raise ValueError("unmapped guest data")
    def mem_write(self,address,data):self.memory_written.append((address,bytes(data)))

def verified(pe,ret,lib,sym,slots):
    if (slots.get("verified") and ret==IMAGE_BASE+WSA_STARTUP_RETURN_RVA
        and lib.lower()=="ws2_32.dll" and sym=="#115"):
        return hex(WSA_STARTUP_CALL_RVA)
    return None

class WsaStartupResearchTests(unittest.TestCase):
    def test_win64_wsadata_structure_has_correct_offsets_and_size(self):
        data=offline_wsadata64()
        self.assertEqual(len(data),408)
        self.assertEqual(struct.unpack_from("<HHHHQ",data,0),(2,0x202,0,0,0))
        self.assertTrue(data[WSADATA64_DESCRIPTION_OFFSET:].startswith(b"MXB offline"))
        self.assertTrue(data[WSADATA64_STATUS_OFFSET:].startswith(b"Offline guest"))
        with self.assertRaises(OfflineWinsockRejected):offline_wsadata64(0x202)

    def test_exact_original_ordinal_writes_only_guest_record_and_returns_success(self):
        u=Guest();service=OfflineWinsockResearch()
        self.assertTrue(service.handle(u,None,{"verified":True},"WS2_32.dll","#115",verified))
        self.assertEqual(u.reg_read(UC_X86_REG_RAX),0)
        self.assertEqual(len(u.memory_written),1)
        self.assertEqual(u.memory_written[0][0],u.reg_read(UC_X86_REG_RDX))
        self.assertEqual(u.memory_written[0][1],offline_wsadata64())
        self.assertEqual(service.summary()["verified_original_guest_wsa_startup_handled"],1)
        self.assertFalse(service.summary()["host_network_initialized"])
        self.assertFalse(service.summary()["supports_online_play"])
        with self.assertRaises(OfflineWinsockRejected):
            service.handle(u,None,{"verified":True},"WS2_32.dll","#115",verified)

    def test_any_bad_abi_provenance_or_guest_memory_fails_untouched(self):
        cases=[
            (Guest(version=0x202),{"verified":True}),
            (Guest(version=0x10002),{"verified":True}),
            (Guest(ret=IMAGE_BASE+WSA_STARTUP_RETURN_RVA+1),{"verified":True}),
            (Guest(output=0),{"verified":True}),
            (Guest(output=0x720001101),{"verified":True}),
            (Guest(rsp=0x720000000),{"verified":True}),
            (Guest(valid_buffer=False),{"verified":True}),
            (Guest(),{}),
        ]
        for u,slots in cases:
            service=OfflineWinsockResearch()
            with self.assertRaises(OfflineWinsockRejected):
                service.handle(u,None,slots,"WS2_32.dll","#115",verified)
            self.assertEqual(u.reg_read(UC_X86_REG_RAX),0xBAD)
            self.assertEqual(u.memory_written,[])
            self.assertEqual(service.summary()["events"],[])

    def test_other_winsock_ordinal_never_handled(self):
        u=Guest();service=OfflineWinsockResearch()
        self.assertFalse(service.handle(u,None,{"verified":True},
                                        "WS2_32.dll","#116",verified))
        self.assertFalse(service.handle(u,None,{"verified":True},
                                        "KERNEL32.dll","#115",verified))
        self.assertEqual(u.memory_written,[])

if __name__=="__main__":unittest.main()
