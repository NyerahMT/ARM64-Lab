"""Bound original next initializer CALLEE/CALL semantic identity tests."""
import sys,unittest
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"scripts"))
import mxbikes_next_outer_init_native as subject

class NativeNextInitializer(unittest.TestCase):
    def test_authenticated_first_block(self):
        self.assertEqual(subject.ENTRY,0x130580)
        self.assertEqual(subject.CALL,0x133f03)
        self.assertEqual(subject.BOUNDARY,0x1305a9)
        self.assertEqual(subject.NESTED,0x2aaebc)
        self.assertEqual(len(subject.FORMS),7)
        self.assertEqual(subject.FORMS[0],("push","r12"))
        self.assertEqual(subject.FORMS[-1],("lea","rcx, [rip + 0x212897]"))
        self.assertEqual(len(subject.REF_KEYS),14)
    def test_fail_closed_native_generation_anchors(self):
        stub="""static int main_to_callee(mx_crt_cluster_state*s,mx_cfg_memory*m,
mx_native_link_registry*r){}
void dummy(void){
 unsigned original_child_returns=0U;
         original_child_returns++;
       if(mismatch)return 205+mismatch;
 if(original_child_returns!=9U)return 211;
}"""
        raw=subject.original_reference
        verify=subject.verify_original
        try:
            subject.verify_original=lambda pe:(0x3422f0,0x342e40)
            def fake(pe,dword,rbx,rsi,rdi):
                if 1<dword<0x80000000:return None
                rsp=0x710001000
                return dict(zip(subject.REF_KEYS,
                     [subject.BASE+subject.BOUNDARY,rsp,1,rbx,
                      subject.BASE+0x342e40,subject.BASE+0x3422f0,
                      rsi,rdi,0,subject.BASE+subject.AFTER_CALL,123,0,0,0]))
            subject.original_reference=fake
            rows=[]
            for dword in (0,1,2,0x80000000)*3:
                rows.append((None,{"callee_global1":dword,"rbx":10,
                              "rsi":11,"rdi":12,"rip":subject.BASE+0x136746},
                             None,"returned"))
            rows.extend((None,{"callee_global1":0,"rbx":0,"rsi":0,
                                "rdi":0,"rip":0},None,"other") for _ in range(4))
            generated=subject.extend(None,stub,rows)
            self.assertIn("native_original_next_initializer",generated)
            self.assertIn("original_next_init_expected",generated)
            self.assertIn("original_next_init_synthetic",generated)
            self.assertIn("next_initializer_frontiers!=9U",generated)
            self.assertIn("return 161;",generated)
            self.assertIn("return 162;",generated)
            self.assertIn("s->instructions+=8U",generated)
            with self.assertRaises(ValueError):
                subject.extend(None,stub,rows[:-1])
        finally:
            subject.original_reference=raw
            subject.verify_original=verify

if __name__=="__main__":
    unittest.main()
