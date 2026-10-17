"""Synthetic Win64 four-instruction entry wrapper lifting tests."""
import unittest
from tools.entry_wrapper import synthetic_wrapper
from tools.x64_entry_lift import lift_entry_to_c


class EntryLiftTests(unittest.TestCase):
    def test_synthetic_lift_models_target_addresses_and_stack(self):
        src=lift_entry_to_c(synthetic_wrapper(),0x300)
        self.assertIn("s->guest_rsp -= 40ULL;",src)
        self.assertIn("s->guest_rsp -= 8ULL;",src)
        self.assertIn("s->call_target_rva = 0x500ULL;",src)
        self.assertIn("s->tail_target_rva = 0x700ULL;",src)
        self.assertIn("s->tail_count += 1ULL;",src)

    def test_unexpected_entry_rejected(self):
        with self.assertRaises(ValueError):
            lift_entry_to_c(b"\x90"*18,0x300)


if __name__=="__main__":
    unittest.main()
