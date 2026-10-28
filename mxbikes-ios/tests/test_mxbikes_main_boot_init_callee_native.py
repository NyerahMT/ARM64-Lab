"""Safe native initializer first-block generator with twelve original fixtures."""
import sys,unittest
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"scripts"))
import mxbikes_main_boot_init_callee_native as nxt
import mxbikes_main_joined_callee_native as joined

class BatchedInitializerTests(unittest.TestCase):
 def test_authentic_guest_call_prefix_and_all_store_targets(self):
    self.assertEqual(nxt.ENTRY,0x133e80)
    self.assertEqual(nxt.FIRST_NESTED,0x133ef6)
    self.assertEqual(len(nxt.ORIGINAL),20)
    self.assertEqual(len(nxt.STORES),12)
    self.assertEqual(sum(t[1]==8 for t in nxt.STORES),2)
 def test_grouped_generator_requires_full_original_input_and_stops_before_call(self):
    source="""static int main_to_callee(mx_crt_cluster_state*s,mx_cfg_memory*m,
mx_native_link_registry*r) {}
void smoke(void){
 mx_cfg_region regions[PAGE_COUNT+3U];
 mx_cfg_memory mem={regions,PAGE_COUNT+3U};
 unsigned next_call_frontiers=0U;
      next_call_frontiers++;
 if(next_call_frontiers!=12U)return 224;
}"""
    class Stub:pass
    old_verify=nxt.verify_original
    old_run=nxt.original_callee_reference
    old_layout=nxt.joined.inspect_original
    try:
      nxt.verify_original=lambda pe:"0x1234"
      def fake(pe,dword,rsi):
          return {"rsp":123,"rax":456,"rsi":0,"rcx":dword,"rdx":789,
                  "call_slot":111,"saved_rsi":rsi,"stack_cookie":222,
                  "stores":[dword]+[0]*11}
      nxt.original_callee_reference=fake
      nxt.joined.inspect_original=lambda pe:({
          "cookie_va":joined.BASE+0x3928a0,
          "arg0_va":joined.BASE+0x300000,
          "arg1_va":joined.BASE+0x400000,
          "show_va":joined.BASE+0xe4adf0,
          "callee_global0":joined.BASE+0x3968a0,
          "callee_global1":joined.BASE+0xe4adf0},None,None)
      rows=[(None,{"rip":joined.BASE+joined.AFTER_CALL,
                   "callee_global1":1+i%2,"rsi":100+i},0,"returned")
            for i in range(12)]
      rows += [(None,{"rip":joined.BASE+0x136152,
                       "callee_global1":0,"rsi":0},0,"frontier")]*4
      out=nxt.extend(Stub(),source,rows)
      self.assertIn("native_original_init_callee",out)
      self.assertIn("PAGE_COUNT+5U",out)
      self.assertIn("native_init_frontiers!=12U",out)
      self.assertIn("return MX_NATIVE_LINK_FRONTIER_REACHED;",out)
      self.assertIn("original_init_expected[i]",out)
      with self.assertRaises(ValueError):
          nxt.extend(Stub(),source,rows[:-1])
      with self.assertRaises(ValueError):
          nxt.extend(Stub(),source,rows[:11]+rows[12:]+[rows[12]])
    finally:
      nxt.verify_original=old_verify
      nxt.original_callee_reference=old_run
      nxt.joined.inspect_original=old_layout

if __name__=="__main__":unittest.main()
