"""The real three-character filename scanner remains linked and bounded."""
import unittest,sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"scripts"))
import mxbikes_main_boot_filename_loop_native as stage
import mxbikes_main_boot_first_jcc_native as prior
import mxbikes_main_boot_strcpy_native as copy
import mxbikes_main_boot_helper_native as helper
import mxbikes_main_postreturn_filename_native as post
import mxbikes_main_joined_callee_native as joined

class FilenameLoopTests(unittest.TestCase):
 def test_grouped_native_original_branch_and_backedges(self):
    fixtures=[(None,{"rip":joined.BASE+joined.AFTER_CALL},18,"returned")]*12
    fixtures +=[(None,{"rip":joined.BASE+0x1361e0},20,"frontier")]*4
    patches=[
      (post.filename,"verify_next_import",lambda pe:1),
      (helper.helper,"verify_helper",lambda pe:({},type("Stop",(),{"address":helper.FRONTIER})(),joined.BASE+0x3968a0)),
      (copy.crt,"original_thunk",lambda pe:(2,joined.BASE+0x3968a0)),
      (copy.postcopy,"verify_source",lambda pe:({},type("Stop",(),{"address":0x15b7bf})(),joined.BASE+0x3968a0)),
      (joined,"inspect_original",lambda pe:({
        "cookie_va":joined.BASE+0x2000,"arg0_va":joined.BASE+0x3000,
        "arg1_va":joined.BASE+0x4000,"show_va":joined.BASE+0x5000,
        "callee_global0":joined.BASE+0x6000,
        "callee_global1":joined.BASE+0x7000},None,None)),
      (prior.scan,"verify_branch",lambda pe:4),
      (stage.separator,"validate_original",lambda pe:None),
      (stage.normal,"validate_source",lambda pe:None)]
    saved=[(obj,name,getattr(obj,name)) for obj,name,_ in patches]
    try:
      for obj,name,value in patches:setattr(obj,name,value)
      src=post.append_postreturn(None,joined.SOURCE,fixtures)
      src=helper.append_helper(None,src,fixtures)
      src=copy.append_strcpy(None,src,fixtures)
      src=prior.append_branch(None,src,fixtures)
      native=stage.append_loop(None,src,fixtures)
      for fragment in ("mx_game_path_separator_branch(",
            "mx_game_slash_loop(", "mx_game_filename_loop_iteration(",
            "genuine_path_separator_frontiers!=12U",
            "s.instructions!=before_scan+36U"):
         self.assertIn(fragment,native)
      with self.assertRaises(ValueError):
         stage.append_loop(None,src,fixtures[1:])
    finally:
      for obj,name,value in saved:setattr(obj,name,value)
if __name__=="__main__":unittest.main()
