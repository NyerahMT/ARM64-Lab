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

    def test_original_lazy_malloc_wrapper_call_provenance(self):
        caller_rva=0x2dcdc9
        wrapper_rva=0x2bd710
        malloc_slot=0x3211f8
        cache_slot=0x3d9ac8
        call=bytes((0xe8,))+struct.pack("<i",wrapper_rva-(caller_rva+5))
        body=(bytes((0x48,0x8b,0x05))+
              struct.pack("<i",cache_slot-(wrapper_rva+7))+
              bytes((0x48,0x85,0xc0,0x74,0x03,0x48,0xff,0xe0,
                     0x48,0xff,0x25))+
              struct.pack("<i",malloc_slot-(wrapper_rva+22)))
        self.assertEqual(len(body),22)
        class LazyPE:
            def __init__(self, wrapper):self.wrapper=wrapper
            def read_rva(self,rva,n):
                if rva==caller_rva and n==5:return call
                if rva==wrapper_rva and n==6:return self.wrapper[:6]
                if rva==wrapper_rva and n==22:return self.wrapper
                raise ValueError("synthetic original PE not mapped")
        slots={malloc_slot:("msvcr90.dll","malloc")}
        self.assertEqual(verified_import_return(
            LazyPE(body),BASE+caller_rva+5,"MSVCR90.dll","malloc",slots),
            hex(caller_rva))
        for wrong_body,wrong_slots in (
            (bytes((0x90,))+body[1:],slots),
            (body[:-1]+bytes((0x01,)),slots),
            (body,{malloc_slot:("msvcr90.dll","free")}),
            (body,{}),
        ):
            self.assertIsNone(verified_import_return(
                LazyPE(wrong_body),BASE+caller_rva+5,
                "MSVCR90.dll","malloc",wrong_slots))
        self.assertIsNone(verified_import_return(
            LazyPE(body),BASE+caller_rva+5,"KERNEL32.dll","malloc",slots))

    def test_later_original_malloc_caller_uses_same_verified_lazy_import(self):
        caller=0x2ad4b9
        thunk=0x2bd710
        iat=0x3211f8
        cache=0x3d9ac8
        call=bytes((0xe8,))+struct.pack("<i",thunk-caller-5)
        lazy=(bytes((0x48,0x8b,0x05))+
              struct.pack("<i",cache-thunk-7)+
              bytes((0x48,0x85,0xc0,0x74,0x03,0x48,0xff,0xe0,
                     0x48,0xff,0x25))+
              struct.pack("<i",iat-thunk-22))
        class PE:
            def __init__(self,body=lazy,call_bytes=call):
                self.body=body
                self.call=call_bytes
            def read_rva(self,rva,n):
                if rva==caller and n==5:return self.call
                if rva==thunk and n in (6,22):return self.body[:n]
                raise ValueError("unmapped")
        slots={iat:("msvcr90.dll","malloc")}
        self.assertEqual(
            verified_import_return(PE(),BASE+caller+5,"MSVCR90.dll","malloc",slots),
            hex(caller))
        self.assertIsNone(
            verified_import_return(PE(lazy[:-1]+bytes((0,))),
                                   BASE+caller+5,"MSVCR90.dll","malloc",slots))
        self.assertIsNone(
            verified_import_return(PE(),BASE+caller+5,
                                   "MSVCR90.dll","malloc",{iat:("msvcr90.dll","free")}))
        corrupted=bytes((0xe8,))+struct.pack("<i",thunk-caller-4)
        self.assertIsNone(
            verified_import_return(PE(call_bytes=corrupted),
                                   BASE+caller+5,"MSVCR90.dll","malloc",slots))

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
