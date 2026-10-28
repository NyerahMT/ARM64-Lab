"""Synthetic-only regressions for multi-root MX Bikes dependency planning."""
import json
from pathlib import Path
import sys
import tempfile
import unittest
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from mxbikes_dependency_wave_planner import SHA, plan, run


def fixture():
    graph = {
        "0x136710": ["0x136120", "0x133e80", "0x201000"],
        "0x133e80": ["0x200000", "0x200080"],
        "0x136120": ["0x200080"],
        "0x2ab02c": ["0x200000"],
        "0x2ab31c": ["0x2ab02c"],
    }
    positions = [0x133e80, 0x136120, 0x136710, 0x200000, 0x200080,
                 0x2ab02c, 0x2ab31c]
    mapping = {
        "input_sha256": SHA, "original_file_verified": True,
        "interval_map": [{"rva": hex(x), "end_rva": hex(x + 0x40),
                          "status": "decoded_linear"} for x in positions],
        "direct_call_graph": graph,
    }
    imports = {
        "original_sha256": SHA,
        "input_kind": "SHA-pinned PE import table plus static original x64 instructions",
        "original_import_thunks": [{"kind": "import_thunk",
                                    "called_target_rva": "0x201000",
                                    "import_dll": "msvcr90.dll", "import_symbol": "fopen"}],
        "direct_iat_callsites": [{"source_rva": "0x133e84",
                                 "import_dll": "kernel32.dll",
                                 "import_symbol": "SetCurrentDirectoryA"}],
    }
    services = {"original_sha256": SHA, "services": [
        {"dll": "msvcr90.dll", "symbol": "fopen", "family": "file_io", "status": "missing"},
        {"dll": "kernel32.dll", "symbol": "SetCurrentDirectoryA",
         "family": "path_and_directory", "status": "test_guest_model"},
    ], "families": [
        {"family": "file_io", "batch_name": "guest_crt_file_io",
         "missing_symbols": ["fopen"], "next_work": "Guest filesystem"},
        {"family": "path_and_directory", "batch_name": "virtual_windows_paths",
         "missing_symbols": [], "next_work": "Virtual cwd"},
    ]}
    native = {"source_original_sha256": SHA,
              "source": "SHA-verified original MX Bikes whole executable static PE map",
              "native_dispatch_table": [{"original_rva": "0x136120",
                                         "native_symbol": "mx_verified_00136120"}]}
    return mapping, imports, services, native


class DependencyWaveTests(unittest.TestCase):
    def test_groups_function_edges_not_one_call_at_a_time(self):
        result = plan(*fixture(), depth=3, batch_size=16)
        nodes = [n for b in result["code_batches"] for n in b["original_entries"]]
        self.assertIn("0x133e80", nodes)
        self.assertIn("0x200000", nodes)
        self.assertIn("0x200080", nodes)
        self.assertNotIn("0x201000", nodes)
        self.assertNotIn("0x136120", nodes)
        self.assertEqual(len(nodes), len(set(nodes)))
        self.assertIn("msvcr90.dll::fopen", result["missing_services_referenced_in_examined_nodes"])
        self.assertEqual(result["native_verified_nodes_skipped"], 1)
        self.assertTrue(any(len(b["original_entries"]) > 1 for b in result["code_batches"]))
        self.assertFalse(any(b["native_dispatch_ready"] for b in result["code_batches"]))

    def test_fail_closed_on_input_and_service_mismatch(self):
        m, i, s, n = fixture()
        i["original_sha256"] = "wrong"
        with self.assertRaises(ValueError):
            plan(m, i, s, n)
        m, i, s, n = fixture()
        s["services"] = []
        with self.assertRaisesRegex(ValueError, "Unclassified"):
            plan(m, i, s, n)
        with self.assertRaises(ValueError):
            plan(*fixture(), batch_size=1000)

    def test_reproducible_metadata_artifacts(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            inputs = []
            for idx, value in enumerate(fixture()):
                p = root / f"{idx}.json"
                p.write_text(json.dumps(value))
                inputs.append(p)
            out = root / "out"
            result = run(*inputs, out)
            self.assertEqual(result, json.loads((out / "startup-dependency-batches.json").read_text()))
            md = (out / "startup-dependency-batches.md").read_text()
            self.assertIn("multi-root dependency batches", md)
            self.assertIn("not converted ARM64", md)
            self.assertNotIn("game executable bytes", md)


if __name__ == "__main__":
    unittest.main()
