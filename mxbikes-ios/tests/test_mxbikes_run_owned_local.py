"""Source-only validation of offline ORIGINAL-GAME runner: no commercial bytes."""
import importlib.util
import io
import json
from pathlib import Path
import tempfile
import unittest
import zipfile

SOURCE = Path(__file__).resolve().parents[1] / "scripts" / "mxbikes_run_owned_local.py"
spec = importlib.util.spec_from_file_location("mxb_owned_local", SOURCE)
subject = importlib.util.module_from_spec(spec)
spec.loader.exec_module(subject)


def ziptest(path, rows):
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, payload in rows:
            zf.writestr(name, payload)


class LocalOwnedRunnerTests(unittest.TestCase):
    def test_archive_member_lookup_nested_case_and_fixed_destination(self):
        with tempfile.TemporaryDirectory() as folder:
            p = Path(folder)
            archive = p / "owned.zip"
            ziptest(archive, [("Install/Contents/MXBikes.EXE", b"synthetic-exe"),
                              ("Windows/steam_api64.dll", b"synthetic-dll")])
            with zipfile.ZipFile(archive) as z:
                a = subject.archive_member(z, "mxbikes.exe", subject.MAX_EXE)
                b = subject.archive_member(z, "steam_api64.dll", subject.MAX_DLL)
                self.assertEqual(a.file_size, len(b"synthetic-exe"))
                self.assertEqual(b.file_size, len(b"synthetic-dll"))
                subject.bounded_extract(z, a, p / "safe.exe")
                self.assertEqual((p / "safe.exe").read_bytes(), b"synthetic-exe")

    def test_reject_duplicate_steam_dll_and_archive_traversal(self):
        with tempfile.TemporaryDirectory() as folder:
            p = Path(folder)
            archive = p / "owned.zip"
            ziptest(archive, [("A/steam_api64.dll", b"one"),
                              ("B/steam_api64.dll", b"two")])
            with zipfile.ZipFile(archive) as z, self.assertRaises(subject.InputRejected):
                subject.archive_member(z, "steam_api64.dll", subject.MAX_DLL)
            ziptest(archive, [("../mxbikes.exe", b"wrong")])
            with zipfile.ZipFile(archive) as z, self.assertRaises(subject.InputRejected):
                subject.archive_member(z, "mxbikes.exe", subject.MAX_EXE)

    def test_no_fabricated_sha_success_and_no_same_file_pair(self):
        with tempfile.TemporaryDirectory() as folder:
            p = Path(folder)
            exe, dll = p / "mxbikes.exe", p / "steam_api64.dll"
            exe.write_bytes(b"not-actual-proprietary-game")
            dll.write_bytes(b"not-a-real-DLL")
            with self.assertRaisesRegex(subject.InputRejected, "sha256"):
                subject.validate_owned_pair(exe, dll)
            with self.assertRaisesRegex(subject.InputRejected, "cannot_match"):
                subject.validate_owned_pair(exe, exe)

    def test_public_checkout_output_is_not_permitted(self):
        with self.assertRaises(subject.InputRejected):
            subject.public_safe_output(subject.PUBLIC_REPO_ROOT / "game-report")
        with tempfile.TemporaryDirectory() as folder:
            self.assertEqual(subject.public_safe_output(Path(folder)), Path(folder).resolve())

    def test_validate_only_never_imports_guest_runtime(self):
        with tempfile.TemporaryDirectory() as folder:
            p = Path(folder)
            archive = p / "owned.zip"
            ziptest(archive, [("mxbikes.exe", b"not-original"),
                              ("steam_api64.dll", b"not-original")])
            (p / "extract").mkdir()
            with self.assertRaisesRegex(subject.InputRejected, "sha256"):
                subject.extract_owned_archive(archive, p / "extract")

if __name__ == "__main__":
    unittest.main()
