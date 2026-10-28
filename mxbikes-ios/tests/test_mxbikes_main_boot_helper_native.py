"""Boot-first cumulative original filename helper x64->ARM64 wiring."""
from pathlib import Path
import sys,unittest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"scripts"))
import mxbikes_main_boot_helper_native as boot
import mxbikes_main_joined_callee_native as joined
import mxbikes_main_postreturn_filename_native as post
class BootHelperTests(unittest.TestCase):
 def test_linked_original_win64_helper_prologue_and_stack_validation(self):
    base=joined.SOURCE
    # Isolate the existing source patcher from the original commercial PE.
    cases=[(None,{"rip":joined.BASE+joined.AFTER_CALL},18,"returned")]*12
    cases +=[(None,{"rip":joined.BASE+0x1361b9},25,"frontier")]*4
    old=post.filename.verify_next_import
    oldhelper=boot.helper.verify_helper
    try:
        post.filename.verify_next_import=lambda pe:0x1111
        boot.helper.verify_helper=lambda pe:({},type("Control",(),{"address":boot.FRONTIER})(),joined.BASE+0x3968a0)
        upgraded=post.append_postreturn(None,base,cases)
        result=boot.append_helper(None,upgraded,cases)
        self.assertIn("mx_native_link_call_prologue_frontier(",result)
        self.assertIn("mx_game_path_helper_first_block(",result)
        self.assertIn("genuine_helper_frontiers!=12U",result)
        self.assertIn("real_path_layout",result)
        self.assertIn("s.rsp!=target_rsp",result)
        with self.assertRaises(ValueError):
            boot.append_helper(None,upgraded,cases[:10])
    finally:
        post.filename.verify_next_import=old
        boot.helper.verify_helper=oldhelper
if __name__=="__main__":unittest.main()
