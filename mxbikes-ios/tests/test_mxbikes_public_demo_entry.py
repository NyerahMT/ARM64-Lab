"""Source-only tests for the bounded demo loader; no publisher code is used."""
import hashlib
from pathlib import Path
import struct
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"scripts"))
import mxbikes_public_demo_entry as runner

BASE=0x140000000
ENTRY=0x1000
DATA=0x2000
IAT=0x2100


class FixturePE:
    opt=0
    def __init__(self, code, symbol="GetCurrentProcessId", library="KERNEL32.dll"):
        self.b=bytes(0x400)+code+bytes(0x400-len(code))+bytes(0x400)
        self.sections=[(".text",0x400,ENTRY,0x400,0x400,0x60000000),
                       (".data",0x400,DATA,0x400,0x800,0xc0000000)]
        self.slots=[(IAT,library,symbol)]
        self.symbol=symbol
        self.library=library

    def u32(self,off):
        return {56:0x3000,60:0x400}[off]

    def directory(self,n):
        return (0,0)

    def inventory(self):
        return {"image_base":hex(BASE),"entry_rva":hex(ENTRY),
                "imports":{self.library:[self.symbol]}}

    def read_rva(self,rva,size):
        for _,_,start,raw,off,_ in self.sections:
            if start<=rva and rva+size<=start+raw:
                return self.b[off+rva-start:off+rva-start+size]
        raise ValueError("fixture unmapped")


def rip_op(op,offset,target):
    return op+struct.pack("<i",target-(ENTRY+offset+len(op)+4))


def call_code(prefix=b"",suffix=b""):
    head=b"\x48\x83\xec\x28"+prefix
    call=rip_op(b"\xff\x15",len(head),IAT)
    return head+call+suffix+b"\x48\x83\xc4\x28\xc3"


class LoaderTests(unittest.TestCase):
    def execute(self,pe,limit=100):
        with patch.object(runner,"DEMO_SHA",hashlib.sha256(pe.b).hexdigest()), \
             patch.object(runner,"import_slots",return_value=pe.slots):
            return runner.execute(pe,limit)

    def test_supported_original_call_returns(self):
        # Compare the emulated process ID against the documented fixture
        # value. Wrong return branches to UD2 rather than the normal RET.
        result=self.execute(FixturePE(call_code(
            suffix=b"\x3d\x34\x12\x00\x00\x74\x02\x0f\x0b")))
        self.assertEqual(result["stop"]["status"],"entry_returned")
        self.assertEqual(result["serviced_environment_calls"],
                         {"KERNEL32.dll!GetCurrentProcessId":1})

    def test_unsupported_call_never_returns(self):
        result=self.execute(FixturePE(call_code(),symbol="GetModuleHandleW"))
        self.assertEqual(result["stop"]["status"],"unsupported_import")
        self.assertEqual(result["serviced_environment_calls"],{})

    def test_clock_output_must_be_writable(self):
        # RCX points into executable text, so even a legitimate import is
        # rejected rather than allowing an emulator host write to RX bytes.
        prefix=rip_op(b"\x48\x8d\x0d",4,ENTRY)
        result=self.execute(FixturePE(call_code(prefix),symbol="QueryPerformanceCounter"))
        self.assertEqual(result["stop"]["status"],"rejected_environment_output")

    def test_clock_output_written(self):
        prefix=rip_op(b"\x48\x8d\x0d",4,DATA)
        # Test QPC's BOOL success and the output's low 32 bits in guest code.
        after_call=4+len(prefix)+6
        # cmp eax,1; jne trap; cmp dword ptr [rip+disp32],1234567890;
        # je success; ud2; success: add rsp,0x28; ret
        cmp_offset=after_call+5
        cmp_mem=b"\x81\x3d"+struct.pack("<i",DATA-(ENTRY+cmp_offset+10))+struct.pack("<I",1234567890)
        suffix=b"\x83\xf8\x01\x75\x0c"+cmp_mem+b"\x74\x02\x0f\x0b"
        result=self.execute(FixturePE(call_code(prefix,suffix),symbol="QueryPerformanceCounter"))
        self.assertEqual(result["stop"]["status"],"entry_returned")

    def test_unverified_tail_import_rejected(self):
        result=self.execute(FixturePE(rip_op(b"\xff\x25",0,IAT)))
        self.assertEqual(result["stop"]["status"],"unverified_environment_import_callsite")

    def test_memory_fault_has_instruction_address(self):
        result=self.execute(FixturePE(b"\x31\xc0\x48\x8b\x00\xc3"))
        self.assertEqual(result["stop"]["status"],"guest_emulation_fault")
        self.assertEqual(result["memory_fault"]["address"],"0x0")
        self.assertEqual(result["memory_fault"]["instruction_rva"],"0x1002")

    def test_budget_stops_original_loop(self):
        result=self.execute(FixturePE(b"\xeb\xfe"),limit=10)
        self.assertEqual(result["stop"]["status"],"execution_budget_or_timeout")
        self.assertEqual(result["original_x64_instruction_executions"],10)

    def test_sha_required(self):
        with self.assertRaisesRegex(ValueError,"SHA_mismatch"):
            runner.execute(FixturePE(b"\xc3"))

    def test_no_steam_fixture_allowed(self):
        with self.assertRaisesRegex(ValueError,"unexpected_Steam_import"):
            self.execute(FixturePE(call_code(),library="steam_api64.dll",symbol="SteamAPI_Init"))


if __name__=="__main__":
    unittest.main()
