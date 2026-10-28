"""Synthetic original Win64 nested call-return chain classification tests."""
import struct
import sys
import unittest
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"scripts"))
from mxbikes_game_nested_return_batch import explore

PARENT=0x1000
PARENT_RET=0x1005
MAIN=0x1100
MAIN_RET=0x1105
CHILD=0x4000
STEAM_SLOT=0x5000

def direct(pc,dest):
    return b"\xe8"+struct.pack("<i",dest-pc-5)

def imported(pc,iat):
    return b"\xff\x15"+struct.pack("<i",iat-pc-6)

class PE:
    def __init__(self, *,bad_target=False, without_child=False):
        parent=(direct(PARENT,0x2001 if bad_target else 0x2000)+
                b"\x85\xc0"+       # test eax,eax
                b"\x74\x09"+       # je 0x1012
                direct(0x1009,CHILD)+
                b"\xc3"+b"\x90"*3+
                imported(0x1012,STEAM_SLOT)+b"\xc3")
        main=direct(MAIN,0x3000)+direct(MAIN_RET,CHILD)+b"\xc3"
        self.pages={PARENT:parent, MAIN:main}
        spans=[(PARENT,PARENT+len(parent),0),(MAIN,MAIN+len(main),0)]
        if not without_child:
            self.pages[CHILD]=b"\x31\xc0\xc3"
            spans.append((CHILD,CHILD+3,0))
        self.pages[0x80]=b"".join(struct.pack("<III",*s) for s in spans)
        self.directory_size=12*len(spans)
    def directory(self,entry):
        if entry!=3:raise ValueError("Wrong directory")
        return 0x80,self.directory_size
    def read_rva(self,addr,count):
        for base,data in self.pages.items():
            if base<=addr and addr+count<=base+len(data):
                return data[addr-base:addr-base+count]
        raise ValueError("Unmapped guest bytes")

STAGES=(
    ("initializer_parent",PARENT,PARENT_RET,0x2000),
    ("outer_main",MAIN,MAIN_RET,0x3000),
)
IMPORTS=[(STEAM_SLOT,"steam_api64.dll","SteamAPI_Init")]

class NestedOriginalReturnsTests(unittest.TestCase):
    def test_batch_two_nested_callers_prioritizes_real_direct_child(self):
        result=explore(PE(),IMPORTS,stages=STAGES)
        self.assertEqual(result["unique_direct_original_callee_targets"],1)
        self.assertEqual(result["best_game_candidate_rvas"],["0x4000"])
        self.assertEqual(result["ranked_unique_original_callees"][0]["priority"],10)
        p=result["two_game_return_stages"]["initializer_parent"]
        self.assertEqual(p["possible_main_calls"],2)
        self.assertEqual(len(p["original_main_steam_calls"]),1)
        self.assertEqual(result["two_game_return_stages"]["outer_main"]["possible_main_calls"],1)
        self.assertTrue(result["all_caller_return_paths_are_hypothetical"])
        self.assertTrue(result["original_native_runtime_currently_stops_at_steam"])
        self.assertFalse(result["original_engine_started_on_arm64"])
        self.assertFalse(result["native_steamworks_result_forged"])

    def test_original_callsite_target_drift_is_rejected(self):
        with self.assertRaises(ValueError):
            explore(PE(bad_target=True),IMPORTS,stages=STAGES)

    def test_unknown_child_stays_unproven(self):
        outcome=explore(PE(without_child=True),IMPORTS,stages=STAGES)
        self.assertEqual(outcome["best_game_candidate_rvas"],[])
        self.assertFalse(outcome["ranked_unique_original_callees"][0]["verified_original_function_return"])

    def test_stage_uniqueness_and_boundedness(self):
        with self.assertRaises(ValueError):
            explore(PE(),IMPORTS,stages=STAGES+STAGES[:1])
        with self.assertRaises(ValueError):
            explore(PE(),IMPORTS,stages=())

if __name__=="__main__":
    unittest.main()
