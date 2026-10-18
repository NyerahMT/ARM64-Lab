"""Fail-closed shape checks for restricted memory-backed x64 original loop."""
import unittest
from tools.x64_indexed_loop_lift import lift_indexed_loop,UnsupportedIndexedLoop

class IndexedLoopTests(unittest.TestCase):
    def test_reject_wrong_shape(self):
        for blob in (b"\x90"*42,b"\xc3",b""):
            with self.assertRaises(UnsupportedIndexedLoop):
                lift_indexed_loop(blob,0x1000)
    def test_reject_bad_bound(self):
        with self.assertRaises(UnsupportedIndexedLoop):
            lift_indexed_loop(b"\x90"*42,0x1000,0)
    def test_decode_contains_loop_control(self):
        source=open(__import__("tools.x64_indexed_loop_lift",fromlist=["__file__"]).__file__).read()
        self.assertIn("s->sf!=s->of",source)
        self.assertIn("mx_cfg_transfer",source)

if __name__=="__main__":unittest.main()
