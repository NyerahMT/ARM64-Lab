"""Original x64 dynamic startup function priority, never native verification."""
from collections import Counter
from pathlib import Path
import sys
import unittest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"scripts"))
from mxbikes_dynamic_startup_wave import prioritize_original_startup

class DynamicNativeStartupPriorities(unittest.TestCase):
    def make(self,unwind,all_hits,main_hits,**kwargs):
        return prioritize_original_startup(
            unwind,all_hits,main_hits,main_rva=0x1100,
            entry_rva=0x2100,crt_rva=0x2000,**kwargs)

    def test_owner_uses_real_unwind_boundaries_and_unowned_is_explicit(self):
        report=self.make(
            {0x1100:0x1120,0x1200:0x1240,0x2000:0x2040,0x2100:0x2120},
            Counter({0x1100:2,0x1106:6,0x1210:110,0x2012:50,0x3001:9}),
            Counter({0x1100:2,0x1106:6,0x1210:110,0x3001:9}))
        self.assertEqual(report["total_original_x64_instruction_hits"],177)
        self.assertEqual(report["observed_original_instructions_after_main_entry"],127)
        self.assertEqual(report["distinct_observed_pdata_function_intervals"],3)
        self.assertEqual(report["distinct_observed_after_main_pdata_intervals"],2)
        self.assertEqual(report["unowned_original_pc_trace"]["total_hits"],9)
        self.assertEqual(report["unowned_original_pc_trace"]["unique_unowned_pc_rvas"],1)
        self.assertEqual(report["prioritized_original_functions"][0]["original_function_entry_rva"],"0x1100")
        self.assertTrue(report["roots"]["game_main"]["original_function_observed"])
        self.assertFalse(report["roots"]["pe_entry"]["original_function_observed"])
        for candidate in report["prioritized_original_functions"]:
            self.assertTrue(candidate["candidate_only_no_native_proof"])
        self.assertFalse(report["original_game_booted_on_native_arm64"])
        self.assertFalse(report["steamworks_authorization_implemented"])

    def test_loop_hits_are_capped_against_broad_postmain_function_coverage(self):
        report=self.make(
            {0x1100:0x1190,0x1200:0x1300},
            Counter({0x1100:1000000,**{0x1200+i:1 for i in range(20)}}),
            Counter({0x1100:1000000,**{0x1200+i:1 for i in range(20)}}))
        self.assertEqual(report["prioritized_original_functions"][0]["original_function_entry_rva"],"0x1200")
        self.assertEqual(report["queue_entries_total"],2)

    def test_reject_invented_original_locations_and_false_postmain_hits(self):
        for full,after in [
            ({0x1100:1},{0x1100:2}),
            ({0x1100:1},{0x1200:1}),
            ({0x1100:0},{}),
            ({-1:4},{})]:
            with self.subTest(full=full,after=after):
                with self.assertRaises(ValueError):
                    self.make({0x1100:0x1120},full,after)
        with self.assertRaises(ValueError):
            self.make({0x1100:0x1200,0x1180:0x1300},{0x1100:1},{})
        with self.assertRaises(ValueError):
            self.make({0x1100:0x1120},{0x1100:1},{},top=2000)

    def test_output_cap_and_phase_labels_never_promote_candidates(self):
        report=self.make({0x1100:0x1110,0x1200:0x1210,0x2100:0x2110},
            {0x1100:1,0x1200:2,0x2100:3},{0x1100:1,0x1200:2},top=1)
        self.assertTrue(report["queue_truncated"])
        self.assertEqual(report["queue_entries_emitted"],1)
        self.assertEqual(report["queue_entries_total"],3)
        self.assertEqual(report["prioritized_original_functions"][0]["phase"],"game_main_observed")

if __name__=="__main__":
    unittest.main()
