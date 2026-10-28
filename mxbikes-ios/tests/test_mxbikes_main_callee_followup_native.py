"""Native real callee parser backedge/control merge synthetic test."""
from pathlib import Path
import unittest,sys
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"scripts"))
import mxbikes_main_callee_followup_native as followup
import mxbikes_main_callee_branch_pair_native as pair
import mxbikes_main_callee_third_jle_native as third
import mxbikes_main_callee_second_jge_native as second
import mxbikes_main_joined_callee_native as joined

class NativeFollowupTests(unittest.TestCase):
    def test_preserves_original_joined_call_and_resolves_two_parser_entries(self):
        src=third.extend_third_jle(second.extend_joined_source(
            joined.SOURCE,joined.BASE+0xd14cce))
        src=pair.extend_native_pair(src,[0]*16,["returned"]*5+["frontier"]*11,
                                    [18]*5+[27]*11)
        result=followup.extend_joined_native_followup(src)
        self.assertIn("static int native_followup",result)
        self.assertIn("return native_followup(s,m);",result)
        self.assertIn(str(joined.BASE+followup.SHARED),result)
        self.assertIn("r.calls_completed!=5U)",result)
        with self.assertRaises(ValueError):
            followup.extend_joined_native_followup(joined.SOURCE)

if __name__=="__main__":
    unittest.main()
