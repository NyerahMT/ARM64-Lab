import unittest
from tools.x64_cfg_lift import translate_cfg,UnsupportedCFG

class CFGTests(unittest.TestCase):
    def test_synthetic_branch_and_ret(self):
        # test rdx,rdx; je +3; mov eax,7; add rsp,24; ret
        code=bytes.fromhex("4885d27405b8070000004883c418c3")
        # test is 3 bytes, je +5 jumps across five-byte mov
        src,meta=translate_cfg(code,0x1200)
        self.assertEqual(meta["conditional_branches"],1)
        self.assertIn("goto L_120a",src)
        self.assertIn("mx_cfg_transfer",src)
    def test_bad_jump_target_rejected(self):
        with self.assertRaises(UnsupportedCFG):
            translate_cfg(bytes.fromhex("4885d2740177c3"),0x1000)
    def test_unknown_opcode_rejected(self):
        with self.assertRaises(UnsupportedCFG):
            translate_cfg(bytes.fromhex("9090c3"),0x1000)
    def test_ret_without_branch_rejected(self):
        with self.assertRaises(UnsupportedCFG):
            translate_cfg(bytes.fromhex("b801000000c3"),0x1000)

if __name__=="__main__":unittest.main()
