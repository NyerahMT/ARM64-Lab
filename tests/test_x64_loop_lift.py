"""Synthetic integer loop control-flow and arithmetic flag verification."""
import unittest
from tools.x64_loop_lift import translate_integer_loop,UnsupportedLoop

CODE=bytes.fromhex("b800000000b90000000001c8ffc139d17cf8c3")

class LoopTests(unittest.TestCase):
    def test_backward_signed_less_than(self):
        src,meta=translate_integer_loop(CODE,0x1000)
        self.assertEqual(meta["back_edges"],1)
        self.assertEqual(meta["instructions"],7)
        self.assertIn("s->sf != s->of",src)
        self.assertIn("goto L_100a",src)
        self.assertIn("mx_cfg_transfer",src)
        self.assertIn("UINT64_C(4294967295)",src)
    def test_reject_missing_ret(self):
        with self.assertRaises(UnsupportedLoop):
            translate_integer_loop(CODE[:-1],0x1000)
    def test_reject_jump_into_middle_of_instruction(self):
        bad=CODE[:17]+bytes.fromhex("7cf9c3")
        with self.assertRaises(UnsupportedLoop):
            translate_integer_loop(bad,0x1000)
    def test_reject_unsupported_opcode(self):
        with self.assertRaises(UnsupportedLoop):
            translate_integer_loop(b"\x90"+CODE,0x1000)
    def test_bounded_execution(self):
        with self.assertRaises(UnsupportedLoop):
            translate_integer_loop(CODE,0x1000,max_steps=0)
    def test_reject_non_loop(self):
        with self.assertRaises(UnsupportedLoop):
            translate_integer_loop(bytes.fromhex("4885d27405b8070000004883c418c3"),0x1000)

if __name__=="__main__":unittest.main()
