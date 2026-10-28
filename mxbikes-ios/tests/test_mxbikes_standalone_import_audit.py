"""Pure metadata tests. Never use the original commercial MX Bikes bytes."""
import importlib.util
from pathlib import Path
import tempfile
import unittest

FILE = Path(__file__).resolve().parents[1] / "scripts" / "mxbikes_standalone_import_audit.py"
spec = importlib.util.spec_from_file_location("mxb_standalone", FILE)
subject = importlib.util.module_from_spec(spec)
spec.loader.exec_module(subject)


def sample(imports):
    return {
        "sha256": "f" * 64,
        "architecture": "x86-64 PE32+",
        "imports": imports,
        "entry_rva": "0x1000",
        "image_base": "0x140000000",
        "size_bytes": 1234,
        "exception_record_count": 30
    }


class StandaloneMetadataTests(unittest.TestCase):
    def test_source_inventory_with_steam_import(self):
        x = subject.classify_inventory(sample({
            "steam_api64.dll": ["SteamAPI_Init", "SteamAPI_Shutdown"],
            "OPENGL32.dll": ["glDrawElements", "glTexImage2D"],
            "USER32.dll": ["CreateWindowExA"]
        }))
        self.assertEqual(x["steam_symbol_count"], 2)
        self.assertFalse(x["no_static_steam_imports_observed"])
        self.assertEqual(len(x["graphics_symbols"]["opengl32.dll"]), 2)
        self.assertFalse(x["native_ios_engine_executed"])

    def test_steamless_imports_do_not_imply_license_or_working_ios(self):
        x = subject.classify_inventory(sample({
            "KERNEL32.dll": ["GetTickCount"],
            "OPENGL32.dll": ["glDrawElements", "wglMakeCurrent"],
            "DINPUT8.dll": ["DirectInput8Create"]
        }))
        self.assertTrue(x["no_static_steam_imports_observed"])
        self.assertTrue(x["no_steam_import_is_not_proof_of_standalone_license_or_runtime"])
        self.assertFalse(x["publisher_permission_verified"])
        self.assertFalse(x["native_ios_engine_executed"])

    def test_unknown_arch_and_invalid_import_entries_fail(self):
        with self.assertRaises(ValueError):
            subject.classify_inventory({"architecture": "arm64", "imports": {}})
        with self.assertRaises(ValueError):
            subject.classify_inventory(sample({"x.dll": "not-list"}))

    def test_output_must_be_outside_the_public_repository(self):
        with self.assertRaisesRegex(ValueError, "outside_public"):
            subject.audit(subject.ROOT / "fake.exe", subject.ROOT / "report")

    def test_missing_candidate_never_generates_report(self):
        with tempfile.TemporaryDirectory() as td:
            out = Path(td) / "report"
            with self.assertRaisesRegex(ValueError, "missing_or_oversized"):
                subject.audit(Path(td) / "missing.exe", out)
            self.assertFalse(out.exists())


if __name__ == "__main__":
    unittest.main()
