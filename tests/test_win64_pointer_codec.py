"""Synthetic process-local pointer token tests (not Microsoft compatibility)."""
import unittest
from tools.win64_pointer_codec import encode_pointer, decode_pointer


class PointerCodecTests(unittest.TestCase):
    def test_reversible_64_bit_values(self):
        for pointer in (0, 1, 0x140000000, 0xFFFFFFFFFFFFFFFF,
                        0x123456789ABCDEF0, 0x720000000):
            self.assertEqual(decode_pointer(encode_pointer(pointer)), pointer)

    def test_distinct_keys_produce_distinct_tokens(self):
        self.assertNotEqual(encode_pointer(0, 1), encode_pointer(0, 2))

    def test_invalid_input_rejected(self):
        with self.assertRaises(ValueError):
            encode_pointer(-1)
        with self.assertRaises(ValueError):
            decode_pointer(1 << 64)


if __name__ == "__main__":
    unittest.main()
