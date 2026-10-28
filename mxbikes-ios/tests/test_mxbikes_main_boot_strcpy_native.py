"""Original SHA-pinned startup strcpy and post-copy JMP wiring guard."""
from pathlib import Path
import sys,unittest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"scripts"))
import mxbikes_main_boot_strcpy_native as stage
import mxbikes_main_boot_helper_native as helper
import mxbikes_main_postreturn_filename_native as post
import mxbikes_main_joined_callee_native as joined
class CumulativeStrcpyStage(unittest.TestCase):
 def test_native_join_and_original_identity_fail_closed(self):
    cases=[(None,{"rip":joined.BASE+joined.AFTER_CALL},18,"returned")]*12
    cases +=[(None,{"rip":joined.BASE+0x1361b9},35,"frontier")]*4
    old1=post.filename.verify_next_import
    old2=helper.helper.verify_helper
    old3=stage.crt.original_thunk
    old4=stage.postcopy.verify_source
    old5=joined.inspect_original
    try:
        post.filename.verify_next_import=lambda pe:1
        helper.helper.verify_helper=lambda pe:({},type("Control",(),{"address":helper.FRONTIER})(),joined.BASE+0x3968a0)
        stage.crt.original_thunk=lambda pe:(0x2000,joined.BASE+0x3968a0)
        stage.postcopy.verify_source=lambda pe:({},type("Control",(),{"address":0x15b7bf})(),joined.BASE+0x3968a0)
        joined.inspect_original=lambda pe:({
          "cookie_va":joined.BASE+0x2000,"arg0_va":joined.BASE+0x3000,
          "arg1_va":joined.BASE+0x4000,"show_va":joined.BASE+0x5000,
          "callee_global0":joined.BASE+0x6000,
          "callee_global1":joined.BASE+0x7000},None,None)
        src=post.append_postreturn(None,joined.SOURCE,cases)
        src=helper.append_helper(None,src,cases)
        advanced=stage.append_strcpy(None,src,cases)
        for name in ("mx_game_crt_strcpy_import_call(",
            "mx_game_path_after_strcpy(", "genuine_copy_frontiers!=12U",
            "guest_copy_destination[4096U]",
            "mx_cfg_region regions[PAGE_COUNT+3U]"):
            self.assertIn(name,advanced)
        with self.assertRaises(ValueError):
            stage.append_strcpy(None,src,cases[1:])
    finally:
        post.filename.verify_next_import=old1
        helper.helper.verify_helper=old2
        stage.crt.original_thunk=old3
        stage.postcopy.verify_source=old4
        joined.inspect_original=old5
if __name__=="__main__":unittest.main()
