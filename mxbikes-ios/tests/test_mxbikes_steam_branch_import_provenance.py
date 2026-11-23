"""Verified original imported CALL source (no game bytes, no Steam DLL)."""
import struct
import sys
import unittest
from pathlib import Path

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"scripts"))
from mxbikes_startup_fast_blocks import BASE, verified_import_return

CALL_RVA=0x1000
IAT_SLOT=0x3000
LIB="KERNEL32.dll"
API="RtlCaptureContext"

class FakePE:
    def __init__(self,raw):
        self.raw=raw
    def read_rva(self,rva,length):
        if rva!=CALL_RVA or length!=6:
            raise ValueError("unmapped synthetic source")
        return self.raw

class ImportReturnProvenanceTests(unittest.TestCase):
    def test_exact_rip_relative_imported_call_is_certified(self):
        raw=bytes((0xff,0x15))+struct.pack("<i",IAT_SLOT-(CALL_RVA+6))
        self.assertEqual(
            verified_import_return(FakePE(raw), BASE+CALL_RVA+6,
                                   LIB,API,{IAT_SLOT:(LIB.lower(),API)}),
            hex(CALL_RVA))

    def test_wrong_import_opcode_stack_pc_and_slot_fail(self):
        raw=bytes((0xff,0x15))+struct.pack("<i",IAT_SLOT-(CALL_RVA+6))
        slots={IAT_SLOT:(LIB.lower(),API)}
        cases=[
            (FakePE(bytes((0x90,))+raw[1:]),BASE+CALL_RVA+6,slots),
            (FakePE(raw),BASE+CALL_RVA+7,slots),
            (FakePE(raw),BASE+CALL_RVA+6,{}),
            (FakePE(raw),BASE+CALL_RVA+6,{IAT_SLOT:("steam_api64.dll",API)}),
            (FakePE(raw),0,slots),
        ]
        for pe,ret,iat in cases:
            self.assertIsNone(verified_import_return(pe,ret,LIB,API,iat))

if __name__=="__main__":
    unittest.main()
