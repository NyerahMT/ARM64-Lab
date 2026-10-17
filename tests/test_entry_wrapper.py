"""Synthetic x64 entry-wrapper control-flow tests. No game binaries."""
import unittest
from tools.entry_wrapper import synthetic_wrapper,decode_entry_wrapper,emulate_stubbed_wrapper


class EntryWrapperTests(unittest.TestCase):
    def test_synthetic_entry_executes_all_four_real_instructions(self):
        blob=synthetic_wrapper()
        result=emulate_stubbed_wrapper(blob,0x300)
        self.assertEqual(result["original_entry_instructions_executed"],4)
        self.assertTrue(result["x64_stack_balanced"])
        self.assertTrue(result["x64_tail_transfer_reached"])
        self.assertEqual(result["trace_rvas"],[
            "0x300","0x304","0x500","0x309","0x30d"
        ])

    def test_truncated_wrapper_rejected(self):
        with self.assertRaises(ValueError):
            decode_entry_wrapper(synthetic_wrapper()[:-1],0x300)

    def test_wrong_prologue_rejected(self):
        bad=bytes.fromhex("4883ec20")+synthetic_wrapper()[4:]
        with self.assertRaises(ValueError):
            decode_entry_wrapper(bad,0x300)


if __name__=="__main__":
    unittest.main()
