"""Original argument table write must be real native memory, not branch mocks."""
import sys,unittest
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"scripts"))
import mxbikes_main_callee_arg_group_native as module
import mxbikes_main_callee_quote_jne_native as quote
import mxbikes_main_callee_followup_native as followup
import mxbikes_main_callee_branch_pair_native as pair
import mxbikes_main_callee_third_jle_native as third
import mxbikes_main_callee_second_jge_native as second
import mxbikes_main_joined_callee_native as joined

class ArgumentGroupTests(unittest.TestCase):
    def test_opcode_families_and_memory_comparison_wiring(self):
        src=third.extend_third_jle(second.extend_joined_source(
            joined.SOURCE,joined.BASE+0xd14cce))
        src=pair.extend_native_pair(src,[0]*16,["returned"]*11+["frontier"]*5,
                                    [18]*11+[35]*5)
        src=followup.extend_joined_native_followup(src)
        src=quote.extend_quote_native(src)
        native=module.extend_native_argument_blocks(src,[0]*16,[3]*16,[18]*16)
        self.assertIn("static int native_arg_store(",native)
        self.assertIn("static int native_arg_quotepair(",native)
        self.assertIn("expected_arg_slot_after[i]",native)
        self.assertIn("current_branch.r10=(uint32_t)(idx+1U)",native)
        self.assertIn("s->rip=UINT64_C("+str(joined.BASE+module.STORE_TAKEN)+")",native)
        with self.assertRaises(ValueError):
            module.extend_native_argument_blocks(joined.SOURCE,[0]*16,[0]*16,[0]*16)
        with self.assertRaises(ValueError):
            module.extend_native_argument_blocks(src,[0]*15,[0]*16,[0]*16)

if __name__=="__main__":
    unittest.main()
