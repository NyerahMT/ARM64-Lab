"""Postparser startup progression must honor original x64 WinAPI identity."""
import sys,unittest
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"scripts"))
import mxbikes_main_postreturn_filename_native as post
import mxbikes_main_joined_callee_native as joined
class NativeBootPostImport(unittest.TestCase):
 def test_original_return_fixture_count_fail_closed(self):
    source=joined.SOURCE.replace('#include "mx_native_guest_linker.h"',
       '#include "mx_native_guest_linker.h"')
    cases=[(None,{"rip":joined.BASE+joined.AFTER_CALL},
             18,"returned")]*12+[(None,{"rip":0},20,"frontier")]*4
    source=source.replace(" unsigned taken=0,fallthrough=0;",
        " unsigned taken=0,fallthrough=0;")
    class DummyPE:pass
    prev=post.filename.verify_next_import
    try:
        post.filename.verify_next_import=lambda pe:0x11111111
        converted=post.append_postreturn(DummyPE(),source,cases)
        self.assertIn("genuine_module_filename_calls",converted)
        self.assertIn("mx_game_main_filename_import_call",converted)
        self.assertIn("mx_game_module_filename.h",converted)
        self.assertIn("genuine_module_filename_calls!=12U",converted)
        with self.assertRaises(ValueError):
            post.append_postreturn(DummyPE(),source,cases[1:])
    finally:
        post.filename.verify_next_import=prev
if __name__=="__main__":unittest.main()
