"""No commercial files: verify exact Win64 original WSAStartup import contract."""
import struct,sys,unittest
from pathlib import Path
from unicorn.x86_const import UC_X86_REG_RSP,UC_X86_REG_RAX,UC_X86_REG_RCX,UC_X86_REG_RDX,UC_X86_REG_R8,UC_X86_REG_R9
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"scripts"))
from mxbikes_winsock_startup_research import (
    OfflineWinsockResearch,OfflineWinsockRejected,
    offline_wsadata64,IMAGE_BASE,WSA_STARTUP_CALL_RVA,WSA_STARTUP_RETURN_RVA,
    WSA_REQUESTED_VERSION,INET_PTON_CALL_RVA,INET_PTON_RETURN_RVA,
    GETNAMEINFO_CALL_RVA,GETNAMEINFO_RETURN_RVA,
    ORIGINAL_SOCKADDR_LENGTH,ORIGINAL_GNI_HOST_BUFFER_SIZE,
    AF_INET_WINDOWS,AF_INET6_WINDOWS,WSADATA64_SIZE,WSADATA64_DESCRIPTION_OFFSET,
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

class InetPtonOriginalResearchTests(unittest.TestCase):
    class IPGuest:
        SOURCE=0x750020000
        DEST=0x750030000
        RSP=0x750040008
        def __init__(self,text=b"127.0.0.1"+bytes((0,)),family=AF_INET_WINDOWS,
                     return_pc=IMAGE_BASE+INET_PTON_RETURN_RVA,output_mapped=True):
            self.text=text
            self.return_pc=return_pc
            self.output_mapped=output_mapped
            self.regs={UC_X86_REG_RSP:self.RSP,UC_X86_REG_RCX:family,
                       UC_X86_REG_RDX:self.SOURCE,UC_X86_REG_R8:self.DEST,
                       UC_X86_REG_RAX:0xBAD}
            self.writes=[]
        def reg_read(self,r):return self.regs[r]
        def reg_write(self,r,v):self.regs[r]=v
        def mem_read(self,addr,n):
            if addr==self.RSP and n==8:
                return struct.pack("<Q",self.return_pc)
            if n==1 and self.SOURCE<=addr<self.SOURCE+len(self.text):
                return self.text[addr-self.SOURCE:addr-self.SOURCE+1]
            if addr==self.DEST and n in (4,16) and self.output_mapped:
                return b"Z"*n
            raise ValueError("unmapped")
        def mem_write(self,addr,payload):self.writes.append((addr,bytes(payload)))
    @staticmethod
    def verify(_,ret,lib,sym,slots):
        if (slots.get("ok") and ret==IMAGE_BASE+INET_PTON_RETURN_RVA and
            lib.lower()=="ws2_32.dll" and sym=="inet_pton"):
            return hex(INET_PTON_CALL_RVA)
        return None
    @staticmethod
    def initialized(): 
        service=OfflineWinsockResearch()
        service.events=[{"synthetic_wsa_startup":True}]
        return service

    def test_ipv4_conversion_is_network_order_and_no_socket_created(self):
        u=self.IPGuest();service=self.initialized()
        self.assertTrue(service.handle_inet_pton(
            u,None,{"ok":True},"WS2_32.dll","inet_pton",self.verify))
        self.assertEqual(u.reg_read(UC_X86_REG_RAX),1)
        self.assertEqual(u.writes,[(u.DEST,bytes((127,0,0,1)))])
        self.assertEqual(service.summary()["verified_original_guest_inet_pton_handled"],1)
        self.assertTrue(service.summary()["inet_pton_events"][0]["is_loopback"])
        self.assertEqual(service.summary()["real_sockets_created"],0)

    def test_ipv6_writes_sixteen_bytes(self):
        u=self.IPGuest(text=b"::1"+bytes((0,)),family=AF_INET6_WINDOWS)
        service=self.initialized()
        self.assertTrue(service.handle_inet_pton(
            u,None,{"ok":True},"WS2_32.dll","inet_pton",self.verify))
        self.assertEqual(u.writes,[(u.DEST,bytes((0,)*15+(1,)))])
        self.assertEqual(service.summary()["inet_pton_events"][0]["ip_version"],6)

    def test_invalid_literal_returns_zero_without_memory_writes(self):
        u=self.IPGuest(text=b"not.an.ip"+bytes((0,)))
        service=self.initialized()
        self.assertTrue(service.handle_inet_pton(
            u,None,{"ok":True},"WS2_32.dll","inet_pton",self.verify))
        self.assertEqual(u.reg_read(UC_X86_REG_RAX),0)
        self.assertEqual(u.writes,[])

    def test_mismatched_abi_memory_and_provenance_fail_closed(self):
        cases=[
            (self.IPGuest(family=999),{"ok":True}),
            (self.IPGuest(return_pc=IMAGE_BASE+INET_PTON_RETURN_RVA+1),{"ok":True}),
            (self.IPGuest(output_mapped=False),{"ok":True}),
            (self.IPGuest(text=b"A"*64),{"ok":True}),
            (self.IPGuest(),{}),
        ]
        for u,slots in cases:
            service=self.initialized()
            with self.assertRaises(OfflineWinsockRejected):
                service.handle_inet_pton(u,None,slots,
                                         "WS2_32.dll","inet_pton",self.verify)
            self.assertEqual(u.reg_read(UC_X86_REG_RAX),0xBAD)
            self.assertEqual(u.writes,[])
        u=self.IPGuest()
        service=OfflineWinsockResearch()
        with self.assertRaises(OfflineWinsockRejected):
            service.handle_inet_pton(u,None,{"ok":True},
                                     "WS2_32.dll","inet_pton",self.verify)

class GetNameInfoOriginalResearchTests(unittest.TestCase):
    class SockGuest:
        RSP=0x770000008
        SOCK=0x770001000
        HOST=0x770003000
        def __init__(self,flags=0,family=AF_INET_WINDOWS,host_size=1025):
            self.flags=flags
            self.binary=struct.pack("<HH",family,0)+bytes((127,0,0,1))+bytes(8)
            self.regs={
                UC_X86_REG_RSP:self.RSP,
                UC_X86_REG_RAX:0xBAD,
                UC_X86_REG_RCX:self.SOCK,
                UC_X86_REG_RDX:ORIGINAL_SOCKADDR_LENGTH,
                UC_X86_REG_R8:self.HOST,
                UC_X86_REG_R9:host_size,
            }
            self.writes=[]
        def reg_read(self,r):return self.regs[r]
        def reg_write(self,r,v):self.regs[r]=v
        def mem_read(self,addr,n):
            if addr==self.RSP and n==8:
                return struct.pack("<Q",IMAGE_BASE+GETNAMEINFO_RETURN_RVA)
            if addr==self.RSP+0x28 and n==24:
                return struct.pack("<QQQ",0,0,self.flags)
            if addr==self.SOCK and n==16:
                return self.binary
            if addr==self.HOST and n<=16:
                return b"X"*n
            raise ValueError("unmapped")
        def mem_write(self,addr,payload):self.writes.append((addr,bytes(payload)))
    @staticmethod
    def verified(_,ret,lib,sym,slots):
        if (slots.get("ok") and ret==IMAGE_BASE+GETNAMEINFO_RETURN_RVA
            and lib.lower()=="ws2_32.dll" and sym=="getnameinfo"):
            return hex(GETNAMEINFO_CALL_RVA)
        return None
    @staticmethod
    def ready():
        service=OfflineWinsockResearch()
        service.events=[{"wsa":True}]
        service.pton_events=[{"pton":True}]
        return service

    def test_original_ipv4_numeric_fallback_only(self):
        u=self.SockGuest();service=self.ready()
        self.assertTrue(service.handle_getnameinfo(
            u,None,{"ok":True},"WS2_32.dll","getnameinfo",self.verified))
        self.assertEqual(u.reg_read(UC_X86_REG_RAX),0)
        self.assertEqual(u.writes,[(u.HOST,b"127.0.0.1"+bytes((0,)))])
        self.assertTrue(service.summary()["getnameinfo_events"][0]["offline_numeric_fallback_only"])
        self.assertFalse(service.summary()["getnameinfo_events"][0]["reverse_dns_performed"])
        self.assertEqual(service.summary()["real_sockets_created"],0)
        with self.assertRaises(OfflineWinsockRejected):
            service.handle_getnameinfo(
                u,None,{"ok":True},"WS2_32.dll","getnameinfo",self.verified)

    def test_changed_flags_size_family_or_import_fail_closed(self):
        tests=[
            (self.SockGuest(flags=8),{"ok":True}),
            (self.SockGuest(family=AF_INET6_WINDOWS),{"ok":True}),
            (self.SockGuest(host_size=16),{"ok":True}),
            (self.SockGuest(),{}),
        ]
        for guest,slots in tests:
            service=self.ready()
            with self.assertRaises(OfflineWinsockRejected):
                service.handle_getnameinfo(
                    guest,None,slots,"WS2_32.dll","getnameinfo",self.verified)
            self.assertEqual(guest.writes,[])
            self.assertEqual(guest.reg_read(UC_X86_REG_RAX),0xBAD)
        not_ready=OfflineWinsockResearch()
        with self.assertRaises(OfflineWinsockRejected):
            not_ready.handle_getnameinfo(
                self.SockGuest(),None,{"ok":True},
                "WS2_32.dll","getnameinfo",self.verified)

if __name__=="__main__":unittest.main()
