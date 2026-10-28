"""Startup leaf wave tests: never promote a direct-call or imported function."""
from pathlib import Path
import sys
import unittest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"scripts"))
import mxbikes_boot_leaf_native_wave as wave
import mxbikes_cfg_full_native_wave as native

ENTRY=0x220000
def source():
    return {
        "schema":1,
        "steam_authorization_bypassed":False,
        "topological_native_translation_batches":[{
            "original_function_entry_rvas":[hex(ENTRY)],
            "original_function_count":1,
            "original_call_cycle":False,
            "blockers":{
                "Steamworks_external":0,"Windows_CRT_external":0,
                "unknown_indirect_CALL":0,"out_of_walk_direct_callees":0,
            },
        }],
        "foundational_no_call_no_import_translation_batch_indices":[0],
        "per_original_function":{hex(ENTRY):{
            "status":"original_linear_call_edges_classified_not_native_proof",
            "direct_original_CALL_count":0,
            "named_imports":[],"unknown_or_indirect_CALL_count":0,
        }},
    }

class FakePE:
    def read_rva(self,rva,count):
        blob=bytes.fromhex("8bc1c3")+b"\xcc"*32
        if not ENTRY<=rva<=ENTRY+len(blob)-count:
            raise ValueError("Unmapped original test PE RVA")
        return blob[rva-ENTRY:rva-ENTRY+count]

class StartupNativeLeafTests(unittest.TestCase):
    def test_selects_only_supported_orig_straight_line_no_call(self):
        chosen,skip=wave.eligible_original_entries(source())
        self.assertEqual(chosen,[ENTRY])
        self.assertEqual(skip,0)
        x=source()
        x["topological_native_translation_batches"][0]["blockers"]["Steamworks_external"]=1
        with self.assertRaises(ValueError):wave.eligible_original_entries(x)
        x=source()
        x["per_original_function"][hex(ENTRY)]["direct_original_CALL_count"]=1
        with self.assertRaises(ValueError):wave.eligible_original_entries(x)
        x=source()
        x["steam_authorization_bypassed"]=True
        with self.assertRaises(ValueError):wave.eligible_original_entries(x)

    def test_straight_line_original_function_reached_ret_and_executed_on_real_arm64(self):
        pe=FakePE()
        # Existing multi-CFG test path rejected no-branch sources by design;
        # new proof wave permits complete no-CALL original leaf CFGs.
        blocked,reason=native.recover_cfg(pe,ENTRY,{ENTRY})
        self.assertIsNone(blocked)
        self.assertEqual(reason,"no_branch_uses_new_cfg_translator")
        plan,why=native.recover_cfg(pe,ENTRY,{ENTRY},require_branch=False)
        self.assertIsNone(why)
        self.assertEqual(plan["return_count"],1)
        self.assertEqual(plan["total_reached_instructions"],2)
        refs=[]
        for k in range(native.CASES):
            ref,error=native.x64_reference(pe,plan,k)
            self.assertIsNone(error)
            refs.append(ref)
        native.compile_batch([plan],{ENTRY:refs})

if __name__=="__main__":
    unittest.main()
