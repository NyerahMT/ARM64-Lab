"""Synthetic grouped two-branch ARM64 differential wiring, no game asset."""
from pathlib import Path
import sys
import unittest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"scripts"))
import mxbikes_main_callee_branch_pair_native as native
import mxbikes_main_joined_callee_native as joined
import mxbikes_main_callee_second_jge_native as second
import mxbikes_main_callee_third_jle_native as third

class BothCalleeSuccessorsTests(unittest.TestCase):
    def test_second_byte_mutations_cover_native_unresolved_and_native_return(self):
        self.assertEqual(native.next_byte(3),0x51)
        self.assertEqual(native.next_byte(7),0x51)
        self.assertEqual(native.next_byte(2),0)
        self.assertEqual(native.NEXT_CHAR_NOT_ZERO,0x136176)
        self.assertEqual(native.HIGH_ASCII_TARGET,0x136178)

    def test_grouped_real_native_caller_keeps_stack_and_frontier_guards(self):
        base=third.extend_third_jle(second.extend_joined_source(
            joined.SOURCE,joined.BASE+0xd14cce))
        statuses=["returned"]*5+["frontier"]*11
        src=native.extend_native_pair(base,[0]*16,statuses,[18]*5+[27]*11)
        self.assertIn("return native_branch_pair(s,m);",src)
        self.assertIn("if(!next_char)",src)
        self.assertIn("r.calls_completed!=5U)",src)
        self.assertIn("s.instructions!=expected_steps[i]",src)
        self.assertIn("return mx_game_main_callee_finish_empty(s,m,&callee_layout);",src)
        with self.assertRaises(ValueError):
            native.extend_native_pair(joined.SOURCE,[0]*16,statuses,[18]*16)
        with self.assertRaises(ValueError):
            native.extend_native_pair(base,[0]*15,statuses,[18]*16)

if __name__=="__main__":
    unittest.main()
