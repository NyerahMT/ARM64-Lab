import struct
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
from mxb_demo_win64_environment import startup_info_a, thread_environment, checked_write


class EnvironmentTests(unittest.TestCase):
    def test_startup_info(self):
        data = startup_info_a()
        self.assertEqual(len(data), 104)
        self.assertEqual(struct.unpack_from('<I', data)[0], 104)
        self.assertEqual(data[4:], bytes(100))

    def test_teb_layout(self):
        data = thread_environment(0x730000000, 0x700100000, 0x700000000, 0x1234, 0x5678)
        self.assertEqual(len(data), 4096)
        for off, val in ((0, 2**64-1), (8, 0x700100000), (16, 0x700000000),
                         (48, 0x730000000), (64, 0x1234), (72, 0x5678), (96, 0)):
            self.assertEqual(struct.unpack_from('<Q', data, off)[0], val)

    def test_invalid_teb(self):
        for args in ((0x730000001, 200, 100, 1, 2), (4096, 100, 200, 1, 2),
                     (4096, 200, 100, 0, 2), (0, 200, 100, 1, 2)):
            with self.subTest(args=args), self.assertRaises(ValueError):
                thread_environment(*args)

    def test_exact_boundary_write(self):
        writes = []
        checked_write(lambda p, d: writes.append((p, d)), [(1000, 1104)], 1000, startup_info_a())
        self.assertEqual(writes, [(1000, startup_info_a())])

    def test_rejected_writes_have_no_effect(self):
        writes = []
        for ptr, data in ((0, b'x'), (1001, startup_info_a()), (900, b'x'),
                          (1000, b''), (2**64-2, b'123')):
            with self.subTest(ptr=ptr), self.assertRaises(ValueError):
                checked_write(lambda p, d: writes.append((p, d)), [(1000, 1104)], ptr, data)
        self.assertEqual(writes, [])


if __name__ == '__main__':
    unittest.main()
