"""Synthetic static-only post-Steam CFG tests: no launcher or authorization stubs."""
import json
from pathlib import Path
import struct
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]/"scripts"))
from mxbikes_post_steam_static_successors import map_possible_successors, MAX_IMPORTS

CALL=0x1000
RETURN=0x1006
STEAM_SLOT=0x3000
NEXT_SLOT=0x3008

def rip_call(pc,slot):
    return b"\xff\x15"+struct.pack("<i",slot-(pc+6))

def direct_call(pc,target):
    return b"\xe8"+struct.pack("<i",target-(pc+5))

class FakePE:
    def __init__(self, *, corrupt=False, loop=False):
        code = (rip_call(CALL,STEAM_SLOT) +
                b"\x84\xc0" +             # test al,al
                b"\x75\x08" +             # jne 0x1012
                direct_call(0x100a,0x2000) +
                b"\xc3\x90\x90" +
                rip_call(0x1012,NEXT_SLOT) +
                b"\xc3")
        if corrupt:
            code = b"\x90"+code[1:]
        if loop:
            code = code[:6]+b"\xeb\xfe"+code[8:]
        self.memory={0x80:struct.pack("<III",CALL,CALL+len(code),0),
                     CALL:code}
    def directory(self,which):
        if which!=3:raise ValueError("Unexpected PE directory")
        return 0x80,12
    def read_rva(self,rva,size):
        for begin,data in self.memory.items():
            if begin<=rva and rva+size<=begin+len(data):
                return data[rva-begin:rva-begin+size]
        raise ValueError("Attempt to read beyond original code")

def analyze(pe=None,imports=None):
    return map_possible_successors(
        pe or FakePE(),
        imports if imports is not None else [
            (STEAM_SLOT,"steam_api64.dll","SteamAPI_RestartAppIfNecessary"),
            (NEXT_SLOT,"MSVCR90.dll","fopen"),
        ],
        base=0x140000000,call_rva=CALL,return_rva=RETURN,
        expected_slot=STEAM_SLOT,
        expected_symbol=("steam_api64.dll","SteamAPI_RestartAppIfNecessary")
    )

class PostSteamStaticTests(unittest.TestCase):
    def test_batch_both_possible_branches_and_call_targets(self):
        report=analyze()
        self.assertFalse(report["incomplete"])
        self.assertTrue(report["assumes_steam_call_returned"])
        self.assertTrue(report["conditional_paths_have_not_executed"])
        self.assertFalse(report["game_engine_executed"])
        self.assertFalse(report["steam_authentication_or_client_supplied"])
        self.assertEqual(report["static_callsite_count"],2)
        self.assertEqual(report["static_named_import_count"],1)
        self.assertEqual(report["static_direct_original_call_count"],1)
        self.assertEqual(report["static_branch_count"],1)
        self.assertEqual(report["possible_branches"][0]["taken_rva"],"0x1012")
        kinds={x["kind"] for x in report["possible_calls"]}
        self.assertEqual(kinds,{"named_import","direct_original_call"})
        self.assertIn("0x2000",[c.get("target_rva")
                      for c in report["possible_calls"]])
        # Addresses, imports and mnemonic counts only: no original machine code.
        blob=json.dumps(report)
        self.assertNotIn("machine_bytes",blob)
        self.assertNotIn("op_str",blob)

    def test_drift_or_unrecognized_steam_import_fails_closed(self):
        with self.assertRaises(ValueError):
            analyze(FakePE(corrupt=True))
        with self.assertRaises(ValueError):
            analyze(imports=[(STEAM_SLOT,"steam_api64.dll","SteamAPI_Init")])
        with self.assertRaises(ValueError):
            analyze(imports=[
                (STEAM_SLOT,"steam_api64.dll","SteamAPI_RestartAppIfNecessary"),
                (STEAM_SLOT,"steam_api64.dll","SteamAPI_RestartAppIfNecessary"),
            ])
        with self.assertRaises(ValueError):
            analyze(imports=[(i,"test.dll","x") for i in range(MAX_IMPORTS+1)])

    def test_self_loop_is_bounded_without_assuming_return(self):
        report=analyze(FakePE(loop=True))
        self.assertEqual(report["static_branch_count"],1)
        self.assertEqual(report["static_callsite_count"],0)
        self.assertLessEqual(report["static_successor_instructions"],1)
        self.assertFalse(report["native_aarch64_successor_verified"])

    def test_unknown_named_import_remains_unresolved(self):
        report=analyze(imports=[
            (STEAM_SLOT,"steam_api64.dll","SteamAPI_RestartAppIfNecessary")
        ])
        kinds={r["kind"] for r in report["possible_calls"]}
        self.assertIn("unresolved_indirect_memory_call",kinds)
        self.assertEqual(report["static_named_import_count"],0)

if __name__=="__main__":
    unittest.main()
