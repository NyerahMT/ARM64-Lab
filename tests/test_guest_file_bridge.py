"""Tests for read-only guest CRT file bridge using synthetic data only."""
import unittest

from tools.guest_file_bridge import (
    GuestFileBridge, GuestFileError, HANDLE_START, MAX_READ_BYTES,
)


class GuestFileBridgeTests(unittest.TestCase):
    def setUp(self):
        self.bridge = GuestFileBridge({"fake_asset.dll": b"ABCDE12345"})

    def test_open_and_real_bytes(self):
        h = self.bridge.fopen("FAKE_asset.DLL", "rb")
        self.assertEqual(h, HANDLE_START)
        payload, n = self.bridge.fread(h, 2, 3)
        self.assertEqual((payload, n), (b"ABCDE1", 3))
        self.assertEqual(self.bridge.ftell(h), 6)
        self.assertEqual(self.bridge.fseek(h, -3, 1), 0)
        self.assertEqual(self.bridge.fgetc(h), ord("D"))
        self.assertEqual(self.bridge.fseek(h, -1, 2), 0)
        self.assertEqual(self.bridge.fgetc(h), ord("5"))
        self.assertEqual(self.bridge.fgetc(h), -1)
        self.assertEqual(self.bridge.feof(h), 1)
        self.bridge.rewind(h)
        self.assertEqual(self.bridge.feof(h), 0)
        self.assertEqual(self.bridge.fgetc(h), ord("A"))
        self.assertEqual(self.bridge.fclose(h), 0)
        with self.assertRaises(GuestFileError):
            self.bridge.ftell(h)

    def test_partial_member_read_advances_past_partial_object(self):
        h = self.bridge.fopen("fake_asset.dll", "rb")
        payload, members = self.bridge.fread(h, 4, 3)
        self.assertEqual(payload, b"ABCDE12345")
        self.assertEqual(members, 2)
        self.assertEqual(self.bridge.feof(h), 1)

    def test_independent_handles(self):
        one = self.bridge.fopen("fake_asset.dll", "rb")
        two = self.bridge.fopen("fake_asset.dll", "rb")
        self.assertNotEqual(one, two)
        self.assertEqual(self.bridge.fgetc(one), ord("A"))
        self.assertEqual(self.bridge.fgetc(two), ord("A"))

    def test_refuse_unsafe_or_unavailable_assets(self):
        for name in ("../fake_asset.dll", "C:\\\\foo\\\\fake_asset.dll",
                     "other.dll", "/etc/passwd", "a/fake_asset.dll"):
            with self.subTest(name=name), self.assertRaises(GuestFileError):
                self.bridge.fopen(name, "rb")
        with self.assertRaises(GuestFileError):
            self.bridge.fopen("fake_asset.dll", "wb")

    def test_refuse_oversized_reads_and_invalid_seek(self):
        h = self.bridge.fopen("fake_asset.dll", "rb")
        with self.assertRaises(GuestFileError):
            self.bridge.fread(h, MAX_READ_BYTES, 2)
        with self.assertRaises(GuestFileError):
            self.bridge.fread(h, -1, 1)
        self.assertEqual(self.bridge.fseek(h, -1000, 0), -1)
        self.assertEqual(self.bridge.ftell(h), 0)
        with self.assertRaises(GuestFileError):
            self.bridge.fseek(h, 0, 3)

    def test_refuse_pretend_file_struct_access(self):
        h = self.bridge.fopen("fake_asset.dll", "rb")
        self.assertGreater(h, 0x100000000)
        self.assertEqual(self.bridge.diagnostics()["handles_still_open"], 1)


if __name__ == "__main__":
    unittest.main()
