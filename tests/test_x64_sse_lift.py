"""Synthetic, independent x86-64 SSE subset lifter regression tests."""
import unittest
from tools.x64_sse_lift import lift, UnsupportedInstruction


class SSESubsetLifterTest(unittest.TestCase):
    def test_scalar_load_store(self):
        # movss xmm0, [rdx] ; movss [rcx], xmm0 ; ret
        source, count = lift(bytes.fromhex("f30f1002f30f1101c3"), 0x1000)
        self.assertEqual(count, 3)
        self.assertIn("xmm0[0] = _as_bits(a[0])", source)
        self.assertIn("dst[0] = _as_float(xmm0[0])", source)

    def test_rejects_unhandled_instruction(self):
        with self.assertRaises(UnsupportedInstruction):
            lift(bytes.fromhex("90c3"), 0x1000)


if __name__ == "__main__":
    unittest.main()
