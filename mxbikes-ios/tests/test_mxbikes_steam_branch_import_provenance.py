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

    def test_original_direct_call_to_rip_import_thunk(self):
        thunk_rva=0x2100
        caller=bytes((0xe8,))+struct.pack("<i",thunk_rva-(CALL_RVA+5))
        thunk=bytes((0xff,0x25))+struct.pack("<i",IAT_SLOT-(thunk_rva+6))
        class FakeThunkPE:
            def __init__(self,call,thunk):self.call=call;self.thunk=thunk
            def read_rva(self,rva,n):
                if rva==CALL_RVA and n==5:return self.call
                if rva==thunk_rva and n==6:return self.thunk
                raise ValueError("unmapped")
        pe=FakeThunkPE(caller,thunk)
        self.assertEqual(verified_import_return(pe,BASE+CALL_RVA+5,
                             LIB,API,{IAT_SLOT:(LIB.lower(),API)}),hex(CALL_RVA))
        bad=FakeThunkPE(caller,bytes((0x90,))+thunk[1:])
        self.assertIsNone(verified_import_return(bad,BASE+CALL_RVA+5,
                             LIB,API,{IAT_SLOT:(LIB.lower(),API)}))
        self.assertIsNone(verified_import_return(pe,BASE+CALL_RVA+5,
                             LIB,API,{IAT_SLOT:("steam_api64.dll",API)}))
        # An attacker-supplied jump target with the wrong opcode must not
        # authorize any imported function or pointer.
        self.assertIsNone(verified_import_return(
             FakeThunkPE(bytes((0xe8,))+struct.pack("<i",0x20),thunk),
             BASE+CALL_RVA+5,LIB,API,{IAT_SLOT:(LIB.lower(),API)}))

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
