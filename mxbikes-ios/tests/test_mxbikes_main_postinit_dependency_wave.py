"""Synthetic original game-main post-init dependency wave regressions.

Only metadata and synthetic bytes; no Steam invocation or original binary in
local tests. An initializer's return is HYPOTHETICAL throughout the scan.
"""
import struct,sys,unittest
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"scripts"))
from mxbikes_main_postinit_dependency_wave import map_main_return

CALL=0x1000
RET=0x1005
INIT=0x2000
CHILD=0x2020
STEAM_IAT=0x3010

def direct_call(pc,target):
    return b"\xe8"+struct.pack("<i",target-(pc+5))
def imported_call(pc,slot):
    return b"\xff\x15"+struct.pack("<i",slot-(pc+6))

class FakePE:
    def __init__(self, *,wrong_init=False,unknown_callee=False,branch_loop=False,unwindless_thunk=False):
        # Conditional path after a *hypothetical* internal initializer return.
        # 0x1005 test eax,eax; 0x1007 jne 0x1012; 0x1009 call CHILD;
        # 0x100e ret; padding 0x100f..1011; 0x1012 import CALL; 0x1018 ret.
        code=(direct_call(CALL,INIT+1 if wrong_init else INIT)+
             b"\x85\xc0"+
             (b"\xeb\xfe" if branch_loop else b"\x75\x09")+
             direct_call(0x1009,CHILD)+b"\xc3"+b"\x90"*3+
             imported_call(0x1012,STEAM_IAT)+b"\xc3")
        data={CALL:code}
        if not unknown_callee:
            data[CHILD]=b"\x31\xc0\xc3"
        if unwindless_thunk:
            data[CHILD]=b"\xff\x25"+struct.pack("<i",STEAM_IAT-(CHILD+6))
        intervals=[(CALL,CALL+len(code),0)]
        if not unknown_callee:
            intervals.append((CHILD,CHILD+3,0))
        data[0x80]=b"".join(struct.pack("<III",*item) for item in intervals)
        self.content=data
        self.pdata_size=12*len(intervals)
    def directory(self,index):
        assert index==3
        return 0x80,self.pdata_size
    def read_rva(self,pc,n):
        for a,data in self.content.items():
            if a<=pc and pc+n<=a+len(data):
                return data[pc-a:pc-a+n]
        raise ValueError("Unmapped synthetic RVA")

def inspect(pe,imports=None):
    return map_main_return(pe,
        [(STEAM_IAT,"steam_api64.dll","SteamAPI_Init")]
        if imports is None else imports,
        base=0x140000000,call_rva=CALL,return_rva=RET,init_target=INIT)

class MainPostInitWaveTests(unittest.TestCase):
    def test_branch_paths_and_direct_callee_audited_in_batch(self):
        result=inspect(FakePE())
        self.assertFalse(result["scan_budget_truncated"])
        self.assertEqual(result["possible_main_calls"],2)
        self.assertEqual(result["direct_original_callee_candidates_total"],1)
        self.assertEqual(result["direct_original_callee_candidates_inspected"],1)
        self.assertEqual(result["direct_original_callee_no_steam_import_rvas"],["0x2020"])
        self.assertEqual(len(result["original_main_steam_calls"]),1)
        self.assertEqual(result["original_main_steam_calls"][0]["site_rva"],"0x1012")
        self.assertEqual(result["original_callee_dependency_audit"][0]["original_instruction_count"],2)
        self.assertFalse(result["original_callee_dependency_audit"][0]["transitive_steam_independence_proven"])
        self.assertFalse(result["game_init_returned_in_native_runtime"])
        self.assertFalse(result["startup_code_after_init_executed"])
        self.assertFalse(result["engine_init_or_renderer_confirmed"])

    def test_missing_pdata_entry_kept_explicitly_unresolved(self):
        result=inspect(FakePE(unknown_callee=True))
        self.assertEqual(result["direct_original_callee_candidates_total"],1)
        self.assertEqual(result["direct_original_callee_no_steam_import_count"],0)
        self.assertEqual(result["original_callee_dependency_audit"][0]["status"],
                         "outside_original_unwind")

    def test_unwindless_import_thunk_is_classified_not_promoted_to_engine(self):
        outcome=inspect(FakePE(unknown_callee=True,unwindless_thunk=True))
        candidate=outcome["original_callee_dependency_audit"][0]
        self.assertEqual(candidate["status"],"named_original_import_thunk_prefix")
        self.assertEqual(candidate["import_library"],"steam_api64.dll")
        self.assertEqual(candidate["import_symbol"],"SteamAPI_Init")
        self.assertTrue(candidate["steam_import_thunk"])
        self.assertFalse(candidate["complete_function_verified"])
        self.assertFalse(candidate["engine_identity_proven"])
        self.assertEqual(outcome["direct_original_callee_no_steam_import_count"],0)

    def test_original_init_call_drift_fails_closed(self):
        with self.assertRaises(ValueError):
            inspect(FakePE(wrong_init=True))
        with self.assertRaises(ValueError):
            inspect(FakePE(),[(STEAM_IAT,"steam_api64.dll","SteamAPI_Init"),
                              (STEAM_IAT,"steam_api64.dll","SteamAPI_Init")])

    def test_loop_scan_remains_bounded_and_does_not_invent_engine(self):
        result=inspect(FakePE(branch_loop=True))
        self.assertLessEqual(result["possible_main_instruction_sites"],3)
        self.assertEqual(result["possible_main_calls"],0)
        self.assertEqual(result["direct_original_callee_candidates_total"],0)
        self.assertFalse(result["native_arm64_game_port_booted"])

if __name__=="__main__":
    unittest.main()
