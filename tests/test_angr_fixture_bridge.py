"""Synthetic symbolic CRT test-double witness validation."""
import unittest
from tools.angr_fixture_bridge import normalize_symbolic_models


def report(models):
    return {
        "imports_are_symbolic_stubs": True,
        "original_runtime_apis_executed": False,
        "candidate_models": models,
    }


def candidate(imports, values):
    names = [name for name in imports if name not in ("_lock", "_unlock")]
    return {
        "imports_called": imports,
        "modeled_return_values": [
            {"service": name, "chosen_synthetic_return": hex(v)}
            for name, v in zip(names, values)
        ],
    }


class FixtureBridgeTests(unittest.TestCase):
    def test_two_paths_and_duplicate_suppression(self):
        early = candidate(["_decode_pointer", "_onexit"], [(1 << 64)-1, 0])
        longer = candidate([
            "_decode_pointer", "_lock", "_decode_pointer",
            "_decode_pointer", "_encode_pointer", "__dllonexit",
            "_encode_pointer", "_encode_pointer", "_unlock",
        ], [123, 456, 789, 1, 0, 2, 3])
        result = normalize_symbolic_models(report([early, longer, early]))
        self.assertEqual(len(result), 2)
        self.assertEqual(result[0]["import_count"], 2)
        self.assertEqual(result[1]["import_count"], 9)
        self.assertEqual(len(result[1]["testdouble_return_values"]), 7)
        self.assertTrue(all(not x["verified_arm64_equivalence"] for x in result))

    def test_reject_wrong_import_order(self):
        bad = candidate(["_decode_pointer", "_onexit"], [1, 2])
        bad["modeled_return_values"].reverse()
        with self.assertRaises(ValueError):
            normalize_symbolic_models(report([bad]))

    def test_reject_unknown_services_and_invalid_values(self):
        for name in ("UnknownWin32", "callrax", ""):
            with self.subTest(name=name):
                with self.assertRaises(ValueError):
                    normalize_symbolic_models(report([candidate([name], [2])]))
        bad = candidate(["_decode_pointer"], [(1 << 64)])
        with self.assertRaises(ValueError):
            normalize_symbolic_models(report([bad]))
        bad = candidate(["_decode_pointer"], [2])
        bad["modeled_return_values"][0]["chosen_synthetic_return"] = "7"
        with self.assertRaises(ValueError):
            normalize_symbolic_models(report([bad]))

    def test_reject_unverified_report_and_mismatched_count(self):
        with self.assertRaises(ValueError):
            normalize_symbolic_models(report([]))
        with self.assertRaises(ValueError):
            normalize_symbolic_models({
                "imports_are_symbolic_stubs": False,
                "original_runtime_apis_executed": False,
                "candidate_models": [candidate(["_decode_pointer"], [1])],
            })
        wrong = candidate(["_decode_pointer", "_decode_pointer"], [2])
        with self.assertRaises(ValueError):
            normalize_symbolic_models(report([wrong]))


if __name__ == "__main__":
    unittest.main()
