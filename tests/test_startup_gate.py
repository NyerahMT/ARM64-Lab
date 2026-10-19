"""Synthetic-only regression tests for startup gate inspection."""
import struct
import unittest
from tools.startup_gate import inspect_entry


class FakePE:
    opt = 0
    def __init__(self, entry=0x1000, valid=True):
        self.entry = entry
        self.code = (bytes.fromhex("4883ec28e8") +
                     struct.pack("<i", 0x1100 - (entry + 9)) +
                     bytes.fromhex("4883c428e9") +
                     struct.pack("<i", 0x1200 - (entry + 18)))
        if not valid:
            self.code = b"X" + self.code[1:]
    def u32(self, off):
        return self.entry
    def directory(self, index):
        return (0x2000, 24)
    def read_rva(self, rva, size):
        if rva == self.entry and size == 18:
            return self.code
        if rva == 0x2000 and size == 24:
            return (struct.pack("<III", 0x1100, 0x1180, 0x3000) +
                    struct.pack("<III", 0x1200, 0x1400, 0x3100))
        if rva in (0x1100, 0x1200) and size == 1:
            return b"\x90"
        raise ValueError("unmapped")


class StartupGateTests(unittest.TestCase):
    def test_verified_wrapper(self):
        result = inspect_entry(FakePE())
        self.assertEqual(result["first_call_rva"], "0x1100")
        self.assertEqual(result["tail_jump_rva"], "0x1200")
        self.assertEqual(result["first_call_unwind"][0]["size"], 128)
        self.assertFalse(result["native_arm64_executed"])
        profile = result["first_callee_instruction_profile"]
        self.assertEqual(profile["decoded_instruction_count"], 128)
        self.assertTrue(profile["fully_decoded"])
        self.assertEqual(profile["mnemonic_counts"], {"nop": 128})
        self.assertEqual(profile["conditional_branch_count"], 0)

    def test_missing_unwind_range_fails_closed(self):
        class MissingUnwind(FakePE):
            def directory(self, index):
                return (0, 0)
        with self.assertRaisesRegex(ValueError, "unique unwind interval"):
            inspect_entry(MissingUnwind())

    def test_incomplete_decode_fails_closed(self):
        class CorruptCallee(FakePE):
            def read_rva(self, rva, size):
                if rva == 0x1100 and size == 128:
                    return b"\\x90" * 127 + b"\\x0f"
                return super().read_rva(rva, size)
        with self.assertRaisesRegex(ValueError, "cannot be decoded completely"):
            inspect_entry(CorruptCallee())

    def test_unrecognized_entry_fails_closed(self):
        with self.assertRaisesRegex(ValueError, "not the supported"):
            inspect_entry(FakePE(valid=False))


if __name__ == "__main__":
    unittest.main()
