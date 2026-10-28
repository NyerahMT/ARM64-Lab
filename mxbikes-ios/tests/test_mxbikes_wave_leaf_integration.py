"""Synthetic fixture integration: original leaf discovery obeys the wave scheduler.

Uses fake PE bytes only; neither the real game executable nor extracted assets.
"""
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import mxbikes_verified_leaf_autolink as leaf
from mxbikes_wave_native_selection import SHA


class TestExecutable:
    b = b"synthetic-closed-leaf-fixture"

    def read_rva(self, offset, width):
        code = {
            0x200000: b"\xc3",
            0x200020: b"\x90\xc3",
            0x300000: b"\xc3",
        }.get(offset)
        if code is None or width > len(code):
            raise ValueError("Unmapped synthetic original instruction interval")
        return code[:width]


def mapping():
    return {
        "input_sha256": SHA, "original_file_verified": True,
        "direct_call_graph": {
            "0x136710": ["0x300000", "0x200000", "0x200020"],
            "0x136120": ["0x300000"],
            "0x2ab02c": ["0x300000"],
        },
        "interval_map": [
            {"rva": "0x200000", "status": "decoded_linear", "bytes": 1},
            {"rva": "0x200020", "status": "decoded_linear", "bytes": 2},
            {"rva": "0x300000", "status": "decoded_linear", "bytes": 1},
        ],
    }


def waves():
    return {
        "schema": 1, "original_sha256": SHA,
        "code_batches": [
            {"batch_id": "wave-001",
             "original_entries": ["0x200020", "0x200000"],
             "native_dispatch_ready": False},
        ],
    }


class OriginalLeafWaveIntegrationTests(unittest.TestCase):
    def test_real_discover_path_prefers_multiple_wave_leaves_over_global_popularity(self):
        expected = type("FakeDigest", (), {"hexdigest": lambda self: SHA})()
        with patch.object(leaf, "PE", return_value=TestExecutable()), patch.object(
                leaf.hashlib, "sha256", return_value=expected):
            used_map, candidates, types, reachable = leaf.discover(
                "private-synthetic-exe", mapping(), waves())
        self.assertEqual(used_map, mapping())
        self.assertEqual([x["rva"] for x in candidates],
                         [0x200000, 0x200020, 0x300000])
        self.assertEqual([x["wave_batch_id"] for x in candidates],
                         ["wave-001", "wave-001", None])
        self.assertEqual(types["ret"], 2)
        self.assertEqual(types["nop_ret"], 1)
        self.assertEqual(reachable, 3)

    def test_middle_of_known_function_never_counts_as_independent_leaf(self):
        # The interior byte 0xc3 looks exactly like a complete RET, but is
        # actually covered by a larger PE unwind interval.
        class OverlappingSynthetic:
            b = b"synthetic-original-interior"
            def read_rva(self, address, width):
                if address == 0x200001 and width == 1:
                    return b"\xc3"
                if address == 0x300000 and width == 1:
                    return b"\xc3"
                raise ValueError("Unmapped")
        fixture = {
            "input_sha256": SHA, "original_file_verified": True,
            "direct_call_graph": {
                "0x136710": ["0x200001", "0x300000"],
            },
            "interval_map": [
                {"rva": "0x200000", "end_rva": "0x200100",
                 "status": "decoded_linear", "bytes": 256},
            ],
        }
        expected = type("FakeDigest", (), {"hexdigest": lambda self: SHA})()
        with patch.object(leaf, "PE", return_value=OverlappingSynthetic()), patch.object(
                leaf.hashlib, "sha256", return_value=expected):
            _, candidates, _, _ = leaf.discover("synthetic", fixture)
        self.assertEqual([c["rva"] for c in candidates], [0x300000])

    def test_rejects_stale_map_even_when_fake_game_hash_matches(self):
        stale = mapping()
        stale["input_sha256"] = "bad"
        expected = type("FakeDigest", (), {"hexdigest": lambda self: SHA})()
        with patch.object(leaf, "PE", return_value=TestExecutable()), patch.object(
                leaf.hashlib, "sha256", return_value=expected):
            with self.assertRaisesRegex(RuntimeError, "map does not match"):
                leaf.discover("private-synthetic-exe", stale, waves())


if __name__ == "__main__":
    unittest.main()
