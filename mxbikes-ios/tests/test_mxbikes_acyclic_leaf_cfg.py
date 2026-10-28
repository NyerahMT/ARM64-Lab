"""Synthetic, byte-level verification of the full-body forward-only translator."""
import unittest
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from mxbikes_acyclic_leaf_cfg import decode, emit_native

BRANCH = bytes.fromhex("85c9 7406 b801000000 c3 b802000000 c3")


class AcyclicNativeCFGTests(unittest.TestCase):
    def test_two_real_branches_and_two_return_exits(self):
        plan = decode(BRANCH, 0x200000)
        self.assertIsNotNone(plan)
        self.assertEqual(plan["branches"], 1)
        self.assertEqual(plan["returns"], 2)
        self.assertEqual(plan["instructions"], 6)
        source = emit_native(plan)
        self.assertIn("guest_pc=(s->zf)?10U:4U;", source)
        self.assertIn("s->rsp+=8U;s->rip=return_va;return MX_NATIVE_LINK_OK;", source)
        self.assertEqual(source.count("mx_cfg_transfer"), 1)

    def test_near_conditional_and_64bit_register_test(self):
        code = bytes.fromhex("4885c9 0f8406000000 b801000000 c3 b802000000 c3")
        plan = decode(code, 0x200000)
        self.assertIsNotNone(plan)
        self.assertEqual(plan["branches"], 1)
        self.assertIn("UINT64_MAX", emit_native(plan))

    def test_unconditional_forward_branch_must_preserve_full_coverage(self):
        self.assertIsNotNone(decode(bytes.fromhex("90 eb00 c3"), 0x300000))
        self.assertIsNone(decode(bytes.fromhex("eb01 90 c3"), 0x300000))

    def test_backward_and_unmapped_control_edges_rejected(self):
        for body in (
            bytes.fromhex("90 ebfd c3"),
            bytes.fromhex("eb01 b801000000 c3"),
            bytes.fromhex("0f8401000000 c3"),
            bytes.fromhex("7401 c3"),
        ):
            with self.subTest(body=body.hex()):
                self.assertIsNone(decode(body, 0x200000))

    def test_unsafe_memory_or_system_opcodes_rejected(self):
        for body in (
            bytes.fromhex("8b01 c3"),
            bytes.fromhex("0f05 c3"),
            bytes.fromhex("f30f1efa c3"),
            bytes.fromhex("c20000"),
        ):
            with self.subTest(body=body.hex()):
                self.assertIsNone(decode(body, 0x200000))

    def test_single_block_does_not_duplicate_existing_simple_leaf_dispatch(self):
        self.assertIsNone(decode(bytes.fromhex("31c0 c3"), 0x200000))
        self.assertIsNone(decode(bytes.fromhex("b800000000 c3"), 0x200000))

    def test_unsupported_large_original_interval_rejected(self):
        self.assertIsNone(decode(b"\x90" * 97 + b"\xc3", 0x200000))

    def test_wrong_native_plan_rejected(self):
        with self.assertRaises(ValueError):
            emit_native({"kind": "unverified", "ops": []})


if __name__ == "__main__":
    unittest.main()
