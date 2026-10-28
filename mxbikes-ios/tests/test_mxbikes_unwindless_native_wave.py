"""Synthetic bounded native proof of original direct-CALL targets without .pdata."""
from pathlib import Path
import sys
import unittest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"scripts"))
import mxbikes_unwindless_native_wave as wave
import mxbikes_cfg_full_native_wave as cfg
from mxbikes_whole_game_map import INPUT_SHA

ENTRY=0x220000
CALLER=0x200000
BODY=bytes.fromhex("8bc1c3")

def entry(rva,*,refs=1,first=True):
    return {"rva":hex(rva),"unwind_protected":False,
            "direct_call_references":refs,
            "static_first_block_verified":first,
            "first_control":"ret"}

def original_map():
    return {
        "input_sha256":INPUT_SHA,"original_file_verified":True,
        "interval_map":[{"rva":hex(CALLER),"end_rva":hex(CALLER+32)}],
        "unwindless_direct_call_candidates":[
            entry(ENTRY),entry(ENTRY+0x100),entry(CALLER+8),
            entry(ENTRY+0x200,first=False)]
    }

class FakePE:
    def read_rva(self,rva,size):
        offset=rva-ENTRY
        if offset<0 or offset+size>len(BODY)+64:raise ValueError("unmapped")
        return (BODY+b"\xcc"*64)[offset:offset+size]

class UnwindlessNativeEvidenceTests(unittest.TestCase):
    def test_exact_direct_call_entries_and_foreign_unwind_rejected(self):
        picked,reasons,left,roots=wave.select_targets(original_map(),[],limit=8)
        self.assertEqual(picked,[ENTRY,ENTRY+0x100])
        self.assertEqual(left,0)
        self.assertIn(ENTRY,roots)
        self.assertEqual(reasons["original_unwind_owns_target"],1)
        self.assertEqual(reasons["no_verified_original_direct_call_first_block"],1)
        with self.assertRaises(ValueError):
            wave.select_targets({**original_map(),"input_sha256":"invalid"},[])

    def test_repeated_and_already_verified_evidence(self):
        data=original_map()
        data["unwindless_direct_call_candidates"].append(entry(ENTRY))
        with self.assertRaises(ValueError):wave.select_targets(data,[])
        data["unwindless_direct_call_candidates"].pop()
        prior=[{"original_rva":hex(ENTRY),"full_function_behavior_verified":True,
                "win64_guest_call_abi_verified":True}]
        picked,reasons,_,_=wave.select_targets(data,prior)
        self.assertNotIn(ENTRY,picked)
        self.assertEqual(reasons["already_native_verified"],1)

    def test_unwindless_actual_full_original_and_native_returns(self):
        pe=FakePE()
        plan,why=cfg.recover_cfg(pe,ENTRY,{ENTRY,ENTRY+0x100},require_branch=False)
        self.assertIsNone(why,why)
        refs=[]
        for case in range(cfg.CASES):
            result,error=cfg.x64_reference(pe,plan,case)
            self.assertIsNone(error,error)
            refs.append(result)
        cfg.compile_batch([plan],{ENTRY:refs})
        self.assertTrue(plan["complete_original_reachable_cfg"])

    def test_original_external_call_never_becomes_complete_leaf(self):
        class CallPE:
            def read_rva(self,rva,size):
                body=bytes.fromhex("e800000000c3")+b"\xcc"*64
                offset=rva-ENTRY
                if offset<0 or offset+size>len(body):raise ValueError
                return body[offset:offset+size]
        plan,why=cfg.recover_cfg(CallPE(),ENTRY,{ENTRY},require_branch=False)
        self.assertIsNone(plan)
        self.assertEqual(why,"original_call_requires_verified_runtime_link")

if __name__=="__main__":
    unittest.main()
