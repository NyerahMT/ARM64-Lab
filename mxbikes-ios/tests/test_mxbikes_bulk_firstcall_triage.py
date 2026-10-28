"""Synthetic broad original x64 first-CALL survey regression tests."""
import sys
from pathlib import Path
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from mxbikes_bulk_firstcall_triage import analyze, select_parents, MAX_BULK_PARENTS
from test_mxbikes_parent_call_frontier import (
    SyntheticPE, PARENT, CALLEE, mapping, verified,
)
from mxbikes_win64_unwind_frame import INPUT_SHA

class BulkFirstCallTriageTests(unittest.TestCase):
    def test_scans_unconverted_parent_batches_with_original_x64_only(self):
        report = analyze(SyntheticPE(), mapping(), verified())
        self.assertEqual(report["prioritized_parent_sampled"], 1)
        self.assertEqual(report["parents_with_verified_unwind_prologue"], 1)
        self.assertEqual(report["original_x64_fixtures_executed"], 4)
        self.assertEqual(report["distinct_original_x64_first_direct_call_edges"], 1)
        self.assertEqual(report["first_direct_call_edges_to_previously_native_verified_leaves"], 1)
        self.assertEqual(report["new_native_verified_functions"], 0)
        self.assertTrue(report["highest_priority_first_call_parents"][0][
            "first_calls_observed"][0]["original_x64_path_only"])

    def test_finds_original_edge_without_any_native_verified_target(self):
        report = analyze(SyntheticPE(), mapping(), [])
        self.assertEqual(report["parent_entries_reaching_mapped_direct_first_call"], 1)
        self.assertEqual(report["first_direct_call_edges_to_previously_native_verified_leaves"], 0)
        self.assertEqual(report["new_native_verified_functions"], 0)

    def test_fails_closed_on_unwind_blocked_parents(self):
        bad_pe = SyntheticPE(xdata=bytes([0x21, 5, 2, 0, 5, 0x32, 1, 0x30]))
        report = analyze(bad_pe, mapping(), verified())
        self.assertEqual(report["original_x64_fixtures_executed"], 0)
        self.assertEqual(report["new_native_verified_functions"], 0)
        self.assertEqual(report["distinct_original_x64_first_direct_call_edges"], 0)

    def test_all_original_parent_rows_prioritized_with_bounded_sample(self):
        data = mapping()
        data["direct_call_graph"] = {
            hex(PARENT + i * 0x1000): [hex(CALLEE)] for i in range(35)
        }
        rows = select_parents(data, limit=35)
        self.assertEqual(len(rows), 35)
        self.assertEqual(len({v[0] for v in rows}), 35)
        self.assertEqual(len(select_parents(data, limit=19)), 19)
        with self.assertRaises(ValueError):
            select_parents(data, limit=MAX_BULK_PARENTS + 1)
        with self.assertRaises(ValueError):
            select_parents(data, limit=0)

    def test_rejects_untrusted_original_sha_and_invalid_fixture_counts(self):
        data = mapping()
        data["input_sha256"] = "nope"
        with self.assertRaises(ValueError):
            analyze(SyntheticPE(), data, verified())
        with self.assertRaises(ValueError):
            analyze(SyntheticPE(), mapping(), verified(), cases_per_parent=99)
        with self.assertRaises(ValueError):
            analyze(SyntheticPE(), mapping(), verified(), cases_per_parent=0)

if __name__ == "__main__":
    unittest.main()
