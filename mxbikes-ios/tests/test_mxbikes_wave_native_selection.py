"""No original game bytes: wave-driven native validation scheduling tests."""
from collections import Counter
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from mxbikes_wave_native_selection import SHA, ordered_call_targets, summarize_native_execution


def fixture():
    return {"schema": 1, "original_sha256": SHA, "code_batches": [
        {"batch_id": "wave-001",
         "original_entries": ["0x133e80", "0x136120"], "native_dispatch_ready": False},
        {"batch_id": "wave-002",
         "original_entries": ["0x200000", "0x200080"], "native_dispatch_ready": False},
    ]}


class NativeWaveSelectionTests(unittest.TestCase):
    def test_schedules_multiple_batches_before_global_fallback(self):
        counts = Counter({0x136120: 4, 0x200080: 10, 0x133e80: 3, 0x777777: 99})
        order = ordered_call_targets(counts, fixture())
        self.assertEqual([(x[0], x[2]) for x in order], [
            (0x136120, "wave-001"), (0x133e80, "wave-001"),
            (0x200080, "wave-002"), (0x777777, None)])
        self.assertEqual(len(order), len(counts))

    def test_differential_summary_does_not_promote_untranslated_wave(self):
        waves = fixture()
        selected = [
            {"rva": 0x136120, "wave_batch_id": "wave-001"},
            {"rva": 0x200080, "wave_batch_id": "wave-002"},
            {"rva": 0x777777, "wave_batch_id": None},
        ]
        result = summarize_native_execution(waves, selected)
        self.assertTrue(result["private_native_batch_differential_passed"])
        self.assertEqual(result["native_validated_in_scheduled_waves"], 2)
        self.assertEqual(result["native_validated_global_fallback"], 1)
        self.assertEqual(result["waves_fully_native_verified"], 0)
        self.assertEqual(result["waves"][0]["remaining_entries_not_native_verified"], 1)
        self.assertFalse(result["full_startup_native_executed"])

    def test_rejects_mismatched_sha_and_duplicate_scheduled_addresses(self):
        data = fixture()
        data["original_sha256"] = "not-the-executable"
        with self.assertRaises(ValueError):
            ordered_call_targets(Counter({0x136120: 1}), data)
        data = fixture()
        data["code_batches"][1]["original_entries"].append("0x136120")
        with self.assertRaises(ValueError):
            ordered_call_targets(Counter({0x136120: 1}), data)

    def test_rejects_falsely_native_ready_and_invalid_counts(self):
        data = fixture()
        data["code_batches"][0]["native_dispatch_ready"] = True
        with self.assertRaises(ValueError):
            ordered_call_targets(Counter({0x136120: 1}), data)
        with self.assertRaises(ValueError):
            ordered_call_targets(Counter({0x136120: 0}))

    def test_same_global_order_without_wave_plan(self):
        counts = Counter({0x111111: 2, 0x333333: 5, 0x222222: 1})
        order = ordered_call_targets(counts)
        self.assertEqual([x[0] for x in order], [0x333333, 0x111111, 0x222222])


if __name__ == "__main__":
    unittest.main()
