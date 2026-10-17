"""Synthetic PE32+ unwind-interval tests for x64 boundary profiler."""
import pathlib
import struct
import tempfile
import unittest
from unittest.mock import patch
from tools import x64_functions


class StubPE:
    sections = [(".text", 0x400, 0x1000, 0x400, 0, 0x60000020)]
    def __init__(self, path):
        self.mem = bytearray(0x400)
        self.mem[0x10:0x14] = bytes.fromhex("31c0c390")  # xor eax,eax; ret; nop
        self.mem[0x20:0x23] = bytes.fromhex("31c0c3")
        self.pdata = struct.pack("<III", 0x1010, 0x1013, 0x2000) + struct.pack("<III", 0x1020, 0x1023, 0x2000)
    def inventory(self):
        return {"sha256": "synthetic", "image_base": "0x140000000", "entry_rva": "0x1010"}
    def directory(self, index):
        return (0x3000, len(self.pdata)) if index == 3 else (0, 0)
    def read_rva(self, address, size):
        if address == 0x3000:
            return self.pdata[:size]
        offset = address - 0x1000
        if 0 <= offset and offset + size <= len(self.mem):
            return self.mem[offset:offset+size]
        raise ValueError("unmapped")


class FunctionRecordTests(unittest.TestCase):
    @unittest.skipUnless(x64_functions.Cs, "capstone required")
    def test_two_real_interval_shapes(self):
        with patch.object(x64_functions, "PE", StubPE):
            report = x64_functions.analyze(pathlib.Path("synthetic.exe"))
        self.assertEqual(report["unique_unwind_intervals"], 2)
        self.assertEqual(report["fully_decoded_intervals"], 2)
        self.assertEqual(report["categories"]["straight_line_return"], 2)
        self.assertEqual(report["short_candidate_count"], 2)
        self.assertTrue(all(item["straight_line"] for item in report["short_candidate_examples"]))


if __name__ == "__main__":
    unittest.main()
