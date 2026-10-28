"""Original signed-byte JLE and native guest linker strict fixture tests."""
import sys
import unittest
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"scripts"))
import mxbikes_main_callee_third_jle_native as third

class JoinedThirdJLETests(unittest.TestCase):
    def test_exact_third_original_branch_shape(self):
        body=bytes.fromhex("90 3c20 7e04")
        class Fake:
            def read_rva(self,rva,size):
                if rva!=third.START or size!=5:raise ValueError
                return body
        self.assertEqual(third.verify_third_branch(Fake()),3)
        class Bad:
            def read_rva(self,rva,size):
                return bytes.fromhex("90 3c20 7f04")
        with self.assertRaises(ValueError):third.verify_third_branch(Bad())

    def test_two_signed_branch_destinations_and_failure_if_linker_changed(self):
        from mxbikes_main_callee_second_jge_native import extend_joined_source
        from mxbikes_main_joined_callee_native import SOURCE,BASE
        src=extend_joined_source(SOURCE,BASE+0xd14cce)
        adapted=third.extend_third_jle(src)
        self.assertIn("s.instructions!=(f->in_byte==0U?18U:23U)",adapted)
        self.assertIn("const uint8_t jle=",adapted)
        self.assertIn("const uint8_t of=",adapted)
        with self.assertRaises(ValueError):third.extend_third_jle(SOURCE)

if __name__=="__main__":
    unittest.main()
