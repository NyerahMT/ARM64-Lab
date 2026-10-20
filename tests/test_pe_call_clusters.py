"""Synthetic coverage for bounded x64 dependency cluster discovery."""
import struct
import unittest

from tools.pe_call_clusters import scan, strongly_connected, unwind_functions


class FakePE:
    def __init__(self, chunks):
        self.chunks = dict(chunks)
        self.rows = [(r, r + len(blob), 0) for r, blob in sorted(chunks.items())]
        self.pdata = b"".join(struct.pack("<III", *r) for r in self.rows)

    def directory(self, index):
        if index != 3:
            return 0, 0
        return 0x4000, len(self.pdata)

    def read_rva(self, rva, size):
        if rva == 0x4000 and size == len(self.pdata):
            return self.pdata
        for start, data in self.chunks.items():
            if start <= rva and rva + size <= start + len(data):
                return data[rva - start:rva - start + size]
        raise ValueError("outside synthetic fixture")


class ClusterTests(unittest.TestCase):
    def setUp(self):
        self.pe = FakePE({
            0x1000: bytes.fromhex("e80b000000c3"),
            0x1010: bytes.fromhex("31c0c3"),
            0x1020: bytes.fromhex("ff150a000000c3"),
            0x1040: bytes.fromhex("e8dbffffffc3"),
            0x1100: bytes.fromhex("e80b000000c3"),
            0x1110: bytes.fromhex("e8ebffffffc3"),
        })

    def test_direct_dependencies_and_leaf(self):
        result = scan(self.pe, [0x1000])
        self.assertEqual(result["function_count"], 2)
        nodes = {x["rva"]: x for x in result["nodes"]}
        self.assertEqual(nodes["0x1000"]["calls"], ["0x1010"])
        self.assertEqual(nodes["0x1010"]["instruction_count"], 2)
        self.assertTrue(all(x["ready_for_translation"] for x in result["translation_batches"]))

    def test_iat_dependency_and_missing_name(self):
        result = scan(self.pe, [0x1040], imports={0x1030: "kernel32.dll::Synthetic"})
        nodes = {x["rva"]: x for x in result["nodes"]}
        self.assertEqual(nodes["0x1020"]["imports"][0]["name"],
                         "kernel32.dll::Synthetic")
        self.assertEqual(nodes["0x1020"]["imports"][0]["slot_rva"], "0x1030")
        self.assertTrue(any(x["external_blockers"] for x in result["translation_batches"]))

    def test_recursion_is_one_cycle(self):
        result = scan(self.pe, [0x1100])
        self.assertEqual(result["function_count"], 2)
        self.assertEqual(len(result["translation_batches"]), 1)
        self.assertEqual(result["translation_batches"][0]["members"],
                         ["0x1100", "0x1110"])

    def test_limits_and_unknowns_are_explicit(self):
        one = scan(self.pe, [0x1000], max_depth=0)
        self.assertEqual(one["function_count"], 1)
        self.assertEqual(one["nodes"][0]["unresolved"][0]["kind"], "depth_limit")
        two = scan(self.pe, [0x1000], max_nodes=1)
        self.assertEqual(two["truncated_frontier"], ["0x1010"])
        three = scan(self.pe, [0x1111])
        self.assertEqual(three["nodes"][0]["status"], "missing_exact_unwind_entry")
        four = scan(self.pe, [0x1000], max_bytes=5)
        self.assertEqual(four["nodes"][0]["status"], "too_large")

    def test_invalid_depth_and_overlap(self):
        with self.assertRaises(ValueError):
            scan(self.pe, [0x1000], max_depth=9)
        with self.assertRaises(ValueError):
            scan(self.pe, [], max_nodes=0)
        broken = FakePE({0x1000: bytes.fromhex("c3")})
        broken.pdata = (struct.pack("<III", 0x1000, 0x1010, 0) +
                        struct.pack("<III", 0x1008, 0x1018, 0))
        with self.assertRaises(ValueError):
            unwind_functions(broken)


if __name__ == "__main__":
    unittest.main()
