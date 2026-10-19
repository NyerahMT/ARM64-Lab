"""Synthetic-only regression tests for startup gate inspection."""
import struct
import unittest
from tools.startup_gate import inspect_entry, static_cfg_blocks


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
        if rva == 0x1100 and size == 128:
            return b'\x90' * 128
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
        with self.assertRaisesRegex(ValueError, "Missing or invalid unwind directory"):
            inspect_entry(MissingUnwind())

    def test_incomplete_decode_fails_closed(self):
        class CorruptCallee(FakePE):
            def read_rva(self, rva, size):
                if rva == 0x1100 and size == 128:
                    return b"\\x90" * 127 + b"\\x0f"
                return super().read_rva(rva, size)
        with self.assertRaisesRegex(ValueError, "cannot be decoded completely"):
            inspect_entry(CorruptCallee())

    def test_direct_branch_block_boundaries(self):
        from capstone import Cs, CS_ARCH_X86, CS_MODE_64
        # Synthetic: TEST EAX,EAX; JE +2; XOR EAX,EAX; RET
        decoder=Cs(CS_ARCH_X86,CS_MODE_64)
        decoder.detail=True
        ins=list(decoder.disasm(bytes.fromhex("85c0740231c0c3"),0x3000))
        graph=static_cfg_blocks(ins)
        self.assertEqual(graph["block_count"],3)
        self.assertEqual(graph["direct_edges"],3)
        self.assertEqual([b["start_rva"] for b in graph["blocks"]],
                         ["0x3000","0x3004","0x3006"])
        self.assertEqual(graph["blocks"][0]["outgoing"],
                         [{"type":"taken","to":"0x3006"},
                          {"type":"fallthrough","to":"0x3004"}])

    def test_indirect_branch_rejected(self):
        from capstone import Cs, CS_ARCH_X86, CS_MODE_64
        md=Cs(CS_ARCH_X86,CS_MODE_64)
        md.detail=True
        with self.assertRaisesRegex(ValueError,"Indirect"):
            static_cfg_blocks(list(md.disasm(bytes.fromhex("ffe0"),0x2000)))

    def test_unrecognized_entry_fails_closed(self):
        with self.assertRaisesRegex(ValueError, "not the supported"):
            inspect_entry(FakePE(valid=False))


if __name__ == "__main__":
    unittest.main()
