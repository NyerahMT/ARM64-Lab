"""Synthetic import-thunk recovery and fail-closed startup call graph tests."""
import struct
import sys
from pathlib import Path
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from mxbikes_startup_chain_coverage import SHA
from mxbikes_startup_thunk_edges import (
    resolve_import_dependencies, graph_context, render,
)

MAIN=0x136710
CRT=0x2ab02c
ENTRY=0x2ab31c
THUNK=0x2ab72c
DIRECT_SLOT=0x360100
THUNK_SLOT=0x360200
TAIL=0x2ab730


def call_mem(pc, slot):
    return b"\xff\x15"+struct.pack("<i",slot-(pc+6))


def jmp_mem(pc, slot):
    return b"\xff\x25"+struct.pack("<i",slot-(pc+6))


class SyntheticPE:
    def __init__(self):
        self.code = {}
        # Original main calls through the IAT directly, and then returns.
        self.code[MAIN] = call_mem(MAIN, DIRECT_SLOT)+b"\xc3"
        self.code[CRT] = b"\xe8"+struct.pack("<i",THUNK-(CRT+5))+b"\xc3"
        self.code[ENTRY] = b"\xc3"
        self.code[THUNK] = jmp_mem(THUNK, THUNK_SLOT)
    def read_rva(self, address, size):
        for start, payload in self.code.items():
            if start <= address < start+len(payload):
                relative=address-start
                return payload[relative:relative+size]+b"\x90"*max(0,size-(len(payload)-relative))
        raise ValueError("No executable memory at requested RVA")


def fixture():
    intervals = [(MAIN,MAIN+7),(CRT,CRT+6),(ENTRY,ENTRY+1)]
    return {
        "input_sha256":SHA,
        "original_file_verified":True,
        "statistics":{"unique_unwind_intervals":3},
        "interval_map":[
            {"rva":hex(a),"end_rva":hex(b),"status":"decoded_linear"}
            for a,b in sorted(intervals)
        ],
        "direct_call_graph":{
            hex(CRT):[hex(THUNK)],
            hex(MAIN):[],
            hex(ENTRY):[hex(CRT)],
        },
    }


class OriginalThunkEdgeTests(unittest.TestCase):
    def test_classifies_real_iat_call_and_import_jump(self):
        report=resolve_import_dependencies(
            SyntheticPE(), fixture(), [
                (DIRECT_SLOT,"KERNEL32.dll","GetModuleFileNameA"),
                (THUNK_SLOT,"MSVCR90.dll","_amsg_exit"),
            ])
        self.assertEqual(report["identified_import_thunks"],1)
        self.assertEqual(report["identified_direct_iat_callsites"],1)
        self.assertEqual(report["unique_named_import_dependencies"],2)
        self.assertTrue(all(
            not e["native_runtime_service_implemented"]
            for e in report["direct_iat_callsites"]))
        self.assertEqual(report["original_import_thunks"][0]["called_target_rva"],hex(THUNK))
        self.assertEqual(report["original_import_thunks"][0]["import_symbol"],"_amsg_exit")
        self.assertEqual(report["direct_iat_callsites"][0]["import_symbol"],"GetModuleFileNameA")
        self.assertIn("MSVCR90.dll".lower(),render(report))
        self.assertFalse(any(x.get("dynamically_executed")
                             for x in report["original_import_thunks"]))

    def test_unknown_iat_stays_unresolved(self):
        report=resolve_import_dependencies(SyntheticPE(),fixture(),[])
        self.assertEqual(report["identified_import_thunks"],0)
        self.assertEqual(report["identified_direct_iat_callsites"],0)
        self.assertEqual(report["original_import_thunks"][0]["kind"],"unknown_memory_jump")
        self.assertEqual(len(report["unknown_memory_callsites"]),1)

    def test_fails_closed_on_incorrect_original_hash_or_duplicate_import(self):
        bad=fixture()
        bad["input_sha256"]="00"*32
        with self.assertRaises(ValueError):
            graph_context(bad)
        with self.assertRaises(ValueError):
            resolve_import_dependencies(SyntheticPE(),fixture(),[
                (DIRECT_SLOT,"KERNEL32.dll","GetModuleFileNameA"),
                (DIRECT_SLOT,"KERNEL32.dll","GetModuleFileNameA")])

    def test_static_thunk_is_never_reclassified_native(self):
        report=resolve_import_dependencies(
            SyntheticPE(),fixture(),[(THUNK_SLOT,"MSVCR90.dll","_amsg_exit")])
        target=report["original_import_thunks"][0]
        self.assertEqual(target["kind"],"import_thunk")
        self.assertFalse(target["verified_native_function"])
        self.assertTrue(any("not" in limit.lower()
                            for limit in report["limitations"]))


if __name__=="__main__":
    unittest.main()
