"""Synthetic-only tests of original-game translation bottleneck grouping."""
import unittest
from pathlib import Path
import sys

from capstone import Cs, CS_ARCH_X86, CS_MODE_64
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"scripts"))
from mxbikes_native_family_inventory import analyze, classify_instructions
from mxbikes_whole_game_map import INPUT_SHA

BODIES={
    0x1000:bytes.fromhex("31c0c3"),              # existing simple leaf
    0x2000:bytes.fromhex("488b01c3"),            # guest memory load
    0x3000:bytes.fromhex("83c001c3"),            # unsupported arithmetic
    0x4000:bytes.fromhex("5058c3"),              # guest stack push/pop
    0x5000:bytes.fromhex("e800000000c3"),        # direct nested call
    0x6000:bytes.fromhex("488d41f8c3"),          # existing LEA leaf
}


class SyntheticOriginal:
    def read_rva(self, rva, length):
        value=BODIES.get(rva)
        if value is None or len(value)!=length:
            raise ValueError("Invalid synthetic original interval read")
        return value


def fixture():
    return {
        "input_sha256":INPUT_SHA, "original_file_verified":True,
        "interval_map":[
            {"rva":hex(rva),"end_rva":hex(rva+len(blob)),
             "status":"decoded_linear", "bytes":len(blob),
             "instructions":len(list(Cs(CS_ARCH_X86,CS_MODE_64).disasm(blob,rva))),
             "depth_from_known_roots": 1 if rva==0x2000 else None}
            for rva,blob in BODIES.items()
        ],
        "direct_call_graph":{"0x136710":[hex(rva) for rva in BODIES]},
    }


class GroupedBlockerTests(unittest.TestCase):
    def test_counts_and_family_separation(self):
        output=analyze(SyntheticOriginal(),fixture())
        mapping={f["family"]:f for f in output["families"]}
        self.assertEqual(output["small_decoded_intervals_scanned"],6)
        self.assertEqual(mapping["already_supported_shape"]["unwind_intervals"],2)
        self.assertEqual(mapping["guest_memory"]["unwind_intervals"],1)
        self.assertEqual(mapping["register_arithmetic"]["unwind_intervals"],1)
        self.assertEqual(mapping["stack_state"]["unwind_intervals"],1)
        self.assertEqual(mapping["nested_direct_calls"]["unwind_intervals"],1)
        self.assertEqual(mapping["guest_memory"]["startup_root_reachable_intervals"],1)
        self.assertFalse(output["private_original_code_exported"])
        self.assertTrue(output["known_structural_shapes_are_not_native_proofs"])

    def test_rejects_unpinned_original_map(self):
        bad=fixture()
        bad["input_sha256"]="not the owned executable"
        with self.assertRaises(ValueError):
            analyze(SyntheticOriginal(),bad)

    def test_no_raw_executable_bytes_emitted(self):
        import json
        output=analyze(SyntheticOriginal(),fixture())
        encoded=json.dumps(output)
        self.assertNotIn("488b01c3",encoded)
        self.assertNotIn("e800000000c3",encoded)
        self.assertNotIn("synthetic original",encoded)


if __name__=="__main__":
    unittest.main()
