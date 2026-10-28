"""Authentic original nested call-frame/compare instruction batch guards."""
import sys,unittest
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"scripts"))
import mxbikes_init_nested_jle_native as child
import mxbikes_main_joined_callee_native as joined

class NestedNativeJleTests(unittest.TestCase):
 def test_exact_original_first_control_shape(self):
    self.assertEqual(child.CALL,0x133ef6)
    self.assertEqual(child.CHILD,0x133640)
    self.assertEqual(child.BRANCH,0x133668)
    self.assertEqual(child.CMP_GLOBAL,0x565e54)
    self.assertEqual(len(child.FIRST_INSTRUCTIONS),8)
 def test_native_generator_keeps_all_twelve_real_comparisons_and_fails_closed(self):
    src="""static int main_to_callee(mx_crt_cluster_state*s,mx_cfg_memory*m,
mx_native_link_registry*r) {}
void smoke(void){
 unsigned native_init_frontiers=0U;
      native_init_frontiers++;
 if(native_init_frontiers!=12U)return 239;
}"""
    original_branch=child.original_branch
    original_ref=child.original_x64_to_branch
    try:
      child.original_branch=lambda pe:(0x133695,0x13366a)
      def fake(pe,dword,rbx,rsi,taken,fall):
          return {"rsp":512,"rip":joined.BASE+(taken if dword<=1 else fall),
                  "rax":1024,"rbx":1,"r11":768,
                  "call_slot":2048,"saved_rbx":rbx,"cookie":4096,
                  "comparison":dword,"zf":int(dword==1),"sf":int(dword==0),
                  "cf":int(dword==0)}
      child.original_x64_to_branch=fake
      values=(0,1,2,0x80000000,0,1,2,0,1,2,1,0)
      rows=[(None,{"rip":joined.BASE+joined.AFTER_CALL,
                   "callee_global1":dword,"rbx":0x1234,
                   "rsi":0x5678},0,"returned") for dword in values]
      rows += [(None,{"rip":joined.BASE+0x136152,
                       "callee_global1":0,"rbx":0,"rsi":0},0,"frontier")]*4
      output=child.extend(object(),src,rows)
      self.assertIn("native_original_nested_jle",output)
      self.assertIn("original_nested_expected[i]",output)
      self.assertIn("native_nested_frontiers!=12U",output)
      self.assertIn("const uint32_t difference=compared-1U",output)
      self.assertIn("((int64_t)(int32_t)compared)<=1",output)
      self.assertIn("MX_NATIVE_LINK_FRONTIER_REACHED",output)
      with self.assertRaises(ValueError):
          child.extend(object(),src,rows[:-1])
      with self.assertRaises(ValueError):
          child.extend(object(),src,rows[:11]+rows[12:])
    finally:
      child.original_branch=original_branch
      child.original_x64_to_branch=original_ref

if __name__=="__main__":
    unittest.main()
