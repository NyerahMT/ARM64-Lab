import unittest
from tools.x64_import_lift import (
    lift_import_sequence, synthetic_import_sequence, UnsupportedWin64Code
)

IAT={0x1300:("KERNEL32.dll","Sleep"),0x1308:("KERNEL32.dll","GetTickCount")}

class ImportLiftTests(unittest.TestCase):
    def test_two_real_opcode_import_calls(self):
        src,meta=lift_import_sequence(synthetic_import_sequence(),0x1000,IAT)
        self.assertEqual(meta["instructions"],6)
        self.assertEqual([q["symbol"] for q in meta["imports"]],["Sleep","GetTickCount"])
        self.assertIn("state->rsp -= 40ULL;",src)
        self.assertIn("state->rsp += 40ULL;",src)
        self.assertIn("mx_dispatch_supported_win64_import",src)
        self.assertIn("return 1;",src)
    def test_fail_if_import_not_in_iat(self):
        with self.assertRaises(UnsupportedWin64Code):
            lift_import_sequence(synthetic_import_sequence(),0x1000,{})
    def test_reject_bad_stack(self):
        bad=synthetic_import_sequence().replace(b"\x48\x83\xec\x28",b"\x48\x83\xec\x20",1)
        with self.assertRaises(UnsupportedWin64Code):
            lift_import_sequence(bad,0x1000,IAT)
    def test_reject_extra_unknown_opcode(self):
        with self.assertRaises(UnsupportedWin64Code):
            lift_import_sequence(b"\x90"+synthetic_import_sequence(),0x1000,IAT)
    def test_reject_nonterminating_code(self):
        with self.assertRaises(UnsupportedWin64Code):
            lift_import_sequence(synthetic_import_sequence()[:-1],0x1000,IAT)

if __name__=="__main__": unittest.main()
