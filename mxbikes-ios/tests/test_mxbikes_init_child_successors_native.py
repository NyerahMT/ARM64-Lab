"""Original signed branch successor native source integration regressions."""
import sys,unittest
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"scripts"))
import mxbikes_init_child_successors_native as subject
import mxbikes_main_joined_callee_native as joined

class Tests(unittest.TestCase):
 def test_original_branch_shapes_and_guest_stack_offsets(self):
    self.assertEqual(subject.TAKEN_FORMS[0],("xor","eax, eax"))
    self.assertEqual(len(subject.TAKEN_FORMS),3)
    self.assertEqual(len(subject.FALL_FORMS),13)
    self.assertEqual(subject.SAVE_OFFSETS,(8,16,24,-16,-24,-32,-40))
    self.assertEqual((subject.TAKEN,subject.FALL),(0x133c9a,0x13366e))
    self.assertEqual((subject.TAKEN_CONTROL,subject.FALL_CONTROL),
                     (0x133ca7,0x1336b2))
 def test_batch_generated_from_original_reference_oracles(self):
    src="""static int main_to_callee(mx_crt_cluster_state*s,mx_cfg_memory*m,
mx_native_link_registry*r){}
unsigned smoke(void) {
 unsigned native_nested_frontiers=0U;
      native_nested_frontiers++;
 if(native_nested_frontiers!=12U)return 246;
}"""
    saved_val=subject.validate_original
    saved_ref=subject.original_reference
    try:
        subject.validate_original=lambda pe:(
           0x133691+0x4330ef,0x133698+0xd17788,
           0x13369f+0x432be1,0x1336a6+0x432cea
        )
        def oracle(pe,dword,rbx,rsi,rdi):
            is_taken=dword<=1
            return {"rip":subject.BASE+(subject.TAKEN_CONTROL if is_taken else subject.FALL_CONTROL),
             "rsp":0x710000100,"rax":0 if is_taken else 512,
             "rbx":1,"rcx":0x310,"rdi":rdi if is_taken else 0x7478742e676f6c,
             "rsi":rsi,"r11":0x710000200,
             "rbp":0,"r12":0,"r13":0,"r14":0,"r15":0,
             "zf":1 if is_taken else 0,"sf":0,"cf":0,
             "saved_stores":[0]*7,
             "comparison_dword":dword,
             "instructions":3 if is_taken else 13,
             "branch_rva":subject.TAKEN if is_taken else subject.FALL}
        subject.original_reference=oracle
        rows=[(None,{"callee_global1":dword,"rbx":13,"rsi":15,"rdi":17,
                      "rip":subject.BASE+joined.AFTER_CALL},None,"returned")
              for dword in (0,1,2,3,0,1,2,3,0,1,2,3)]
        rows += [(None,{"callee_global1":0,"rbx":0,"rsi":0,"rdi":0,
                        "rip":subject.BASE+0x136120},None,"partial")]*4
        out=subject.extend(None,src,rows)
        self.assertIn("native_original_child_successor",out)
        self.assertIn("original_successor_synthetic",out)
        self.assertIn("original_successor_expected[CASES][24]",out)
        self.assertIn("native_successor_frontiers!=12U",out)
        self.assertIn("for(unsigned j=0U;j<7U;j++)",out)
        self.assertIn("const int synthetic_mismatch=verify_original_successor(",out)
        with self.assertRaises(ValueError):
            subject.extend(None,src,rows[:-1])
    finally:
        subject.validate_original=saved_val
        subject.original_reference=saved_ref
 def test_generated_native_fail_closed_without_bogus_returns(self):
    self.assertEqual(len(subject.KEYS),24)
    self.assertIn("stack_-40",subject.KEYS)
    self.assertIn("comparison_dword",subject.KEYS)
    self.assertEqual(set(x<=1 for x in subject.SYNTHETIC_CASES),{False,True})

if __name__=="__main__":
    unittest.main()
