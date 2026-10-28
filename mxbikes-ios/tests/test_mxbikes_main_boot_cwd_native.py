"""Full original filename parser/RET and bounded CWD import native link."""
import sys,unittest
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"scripts"))
import mxbikes_main_boot_cwd_native as full
import mxbikes_main_boot_filename_loop_native as loop
import mxbikes_main_boot_first_jcc_native as branch
import mxbikes_main_boot_strcpy_native as copy
import mxbikes_main_boot_helper_native as helper
import mxbikes_main_postreturn_filename_native as post
import mxbikes_main_joined_callee_native as joined

class CompleteFilenameCwd(unittest.TestCase):
 def test_native_parser_and_virtual_directory_contract(self):
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
      (branch.scan,"verify_branch",lambda pe:4),
      (loop.separator,"validate_original",lambda pe:None),
      (loop.normal,"validate_source",lambda pe:None),
      (full,"verify_cwd_original",lambda pe:0x301000)]
    old=[(m,n,getattr(m,n)) for m,n,_ in patches]
    try:
      for m,n,v in patches:setattr(m,n,v)
      src=post.append_postreturn(None,joined.SOURCE,fixtures)
      src=helper.append_helper(None,src,fixtures)
      src=copy.append_strcpy(None,src,fixtures)
      src=branch.append_branch(None,src,fixtures)
      src=loop.append_loop(None,src,fixtures)
      end=full.append_cwd(None,src,fixtures)
      for expected in ("mx_game_filename_scan_to_nul(",
         "mx_game_filename_finish_separator(",
         "mx_game_filename_helper_return(",
         "mx_game_setcwd_import_call(",
         "genuine_directory_returns!=12U",
         "s.instructions!=before_full_scan+314U"):
        self.assertIn(expected,end)
      with self.assertRaises(ValueError):
        full.append_cwd(None,src,fixtures[1:])
    finally:
      for m,n,v in old:setattr(m,n,v)
if __name__=="__main__":unittest.main()
