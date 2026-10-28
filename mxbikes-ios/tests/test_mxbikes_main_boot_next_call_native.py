"""Next original game main MOV/LEA call arguments, fail closed."""
import sys,unittest
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"scripts"))
import mxbikes_main_boot_next_call_native as nxt
import mxbikes_main_joined_callee_native as joined

class PostCwdNativeTests(unittest.TestCase):
 def test_global_va_and_immediate_next_call(self):
    self.assertEqual(nxt.ENTRY,0x136772)
    self.assertEqual(nxt.CALLSITE,0x13677f)
    self.assertEqual(nxt.NEXT,0x133e80)
    self.assertEqual(nxt.GLOBAL_RVA,0x136778+0xd14678)
    self.assertEqual(nxt.CONSTANT_RVA,0x13677f+0xd146a1)
 def test_native_args_stop_without_fabricated_return(self):
    # Exercise the source patcher without game bytes; it MUST require
    # the exact previous authenticated directory boundary and 12 RETs.
    from mxbikes_main_boot_cwd_native import DIR
    self.assertEqual(len(DIR),11)
    src="""static int main_to_callee(mx_crt_cluster_state*s,mx_cfg_memory*m,
mx_native_link_registry*r) {}
void smoke(void){
 mx_cfg_region regions[PAGE_COUNT+3U];
 mx_cfg_memory mem={regions,PAGE_COUNT+3U};
 unsigned genuine_directory_returns=0U;
      genuine_directory_returns++;
 if(genuine_directory_returns!=12U)return 221;
}"""
    class Stub:pass
    saved_cwd=nxt.parent.verify_cwd_original
    saved_next=nxt.original_x64_next
    saved_layout=nxt.joined.inspect_original
    saved_thunk=nxt.parent.crt.original_thunk
    try:
      nxt.parent.verify_cwd_original=lambda pe:1
      nxt.original_x64_next=lambda pe,post_parser_dword=None:post_parser_dword
      nxt.joined.inspect_original=lambda pe:({
       "cookie_va":joined.BASE+0x2000,"arg0_va":joined.BASE+0x3000,
       "arg1_va":joined.BASE+0x4000,"show_va":joined.BASE+0x5000,
       "callee_global0":joined.BASE+0x6000,
       "callee_global1":joined.BASE+nxt.GLOBAL_RVA},None,None)
      fixtures=[(None,{"rip":joined.BASE+joined.AFTER_CALL,
                     "callee_global1":0x1234},0,"returned")]*12
      # The real parser can write a different global for each input case.
      # Supply 16 original-reference cases, with 12 returns and 4 frontiers.
      other=(None,{"rip":joined.BASE+0x1361ad,
                   "callee_global1":0},0,"frontier")
      fixtures=fixtures+[other]*4
      extended=nxt.append_next(Stub(),src,fixtures)
      self.assertIn("mx_game_main_after_cwd_prepare",extended)
      self.assertIn("next_call_frontiers!=12U",extended)
      self.assertIn("original_next_dword[i]",extended)
      self.assertIn("4660U",extended)
      self.assertNotIn("guest_postcwd_page",extended)
      with self.assertRaises(ValueError):
          nxt.append_next(Stub(),src,fixtures[:-1])
      varied=fixtures[:11]+[(None,{"rip":joined.BASE+joined.AFTER_CALL,
                                 "callee_global1":0x9999},0,"returned")]+fixtures[12:]
      changed=nxt.append_next(Stub(),src,varied)
      self.assertIn("39321U",changed)
      self.assertIn("original_next_dword[i]",changed)
    finally:
      nxt.parent.verify_cwd_original=saved_cwd
      nxt.original_x64_next=saved_next
      nxt.joined.inspect_original=saved_layout
      nxt.parent.crt.original_thunk=saved_thunk
if __name__=="__main__":unittest.main()
