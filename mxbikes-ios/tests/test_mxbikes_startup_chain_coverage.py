"""Synthetic-only regression tests for static reachability coverage reporting."""
from pathlib import Path
import json
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from mxbikes_startup_chain_coverage import analyze, render, run, SHA


def fixture():
    positions = [
        (0x136120, 0x136160),
        (0x136710, 0x136740),
        (0x200000, 0x200030),
        (0x2ab02c, 0x2ab200),
        (0x2ab31c, 0x2ab370),
    ]
    return {
        "input_sha256": SHA,
        "original_file_verified": True,
        "statistics": {
            "unique_unwind_intervals": 100,
            "fully_linear_decoded_intervals": 80,
            "direct_call_targets_without_unwind_records": 22,
            "direct_call_targets_found": 75,
            "direct_call_graph_sources": 45,
        },
        "interval_map": [
            {"rva": hex(a), "end_rva": hex(b),
             "status": "decoded_linear", "indirect_calls": 0,
             "import_thunk_calls": 0, "indirect_jumps": 0}
            for a,b in positions
        ],
        "direct_call_graph": {
            "0x136710": ["0x136120", "0x200000", "0x201000"],
            "0x136120": ["0x200000"],
            "0x200000": [],
            "0x2ab02c": ["0x200000"],
            "0x2ab31c": ["0x2ab02c"],
        }
    }


def verified(rva):
    return {
        "original_rva": hex(rva),
        "native_symbol": f"mx_verified_{rva:08x}",
        "full_function_behavior_verified": True,
        "win64_guest_call_abi_verified": True,
        "differential_test_run_url":
            "https://github.com/NyerahMT/ReflexBuildInput/actions/runs/12345",
        "proof_scope": "synthetic test fixture only",
        "code_presence": "ephemeral_ci_elf_only",
    }


class StartupChainCoverageTests(unittest.TestCase):
    def test_graph_counts_and_same_run_verification_are_separate(self):
        result=analyze(fixture(),[verified(0x200000),verified(0x201000)])
        combined=result["combined"]
        self.assertEqual(combined["potentially_reachable_static_nodes"],6)
        self.assertEqual(combined["verified_native_leaves_from_same_run"],2)
        self.assertEqual(combined["verified_leaves_potentially_reachable"],2)
        self.assertEqual(combined["unverified_potentially_reachable_nodes"],4)
        self.assertEqual(result["roots"]["game_main"]["bounded_potentially_reachable_nodes"],4)
        self.assertEqual(result["roots"]["crt_startup"]["bounded_potentially_reachable_nodes"],2)
        self.assertEqual(result["roots"]["pe_entry"]["bounded_potentially_reachable_nodes"],3)
        self.assertEqual(result["whole_image"]["unwind_described_intervals"],100)
        self.assertFalse(result["whole_image"]["whole_game_function_total_known"])
        self.assertEqual(
            result["prioritized_next_static_dependencies"][0]["min_static_depth"],1)
        self.assertIn("completion percentage",render(result))

    def test_unverified_functions_do_not_become_native_through_static_decode(self):
        result=analyze(fixture(),[])
        self.assertEqual(result["combined"]["verified_native_leaves_from_same_run"],0)
        self.assertEqual(result["combined"]["unverified_potentially_reachable_nodes"],6)
        self.assertFalse(result["combined"]["complete_native_game_startup_verified"])

    def test_depth_limit_preserves_bounded_unknowns(self):
        result=analyze(fixture(),[verified(0x200000)],depth=1)
        self.assertEqual(result["roots"]["game_main"]["bounded_potentially_reachable_nodes"],4)
        self.assertEqual(result["roots"]["pe_entry"]["bounded_potentially_reachable_nodes"],2)
        self.assertFalse(result["combined"]["original_iOS_game_boot_verified"])

    def test_fail_closed_on_bad_sha_duplicate_or_uncorroborated_symbols(self):
        bad=fixture()
        bad["input_sha256"]="f"*64
        with self.assertRaises(ValueError):
            analyze(bad,[])
        with self.assertRaises(ValueError):
            analyze(fixture(),[verified(0x200000),verified(0x200000)])
        bad_symbol=verified(0x200000)
        bad_symbol["differential_test_run_url"]="https://example.com/fake-proof"
        with self.assertRaises(ValueError):
            analyze(fixture(),[bad_symbol])
        bad_symbol=verified(0x200000)
        bad_symbol["full_function_behavior_verified"]=False
        with self.assertRaises(ValueError):
            analyze(fixture(),[bad_symbol])

    def test_original_unwindless_proof_symbols_require_direct_call_entry_evidence(self):
        mapping=fixture()
        mapping["unwindless_direct_call_candidates"]=[{
            "rva":"0x201000","unwind_protected":False,
            "static_first_block_verified":True,"direct_call_references":2
        }]
        entry=verified(0x201000)
        entry["native_symbol"]="mx_unwindless_native_00201000"
        entry["original_direct_CALL_entry_without_pdata"]=True
        result=analyze(mapping,[entry])
        self.assertEqual(result["combined"]["verified_leaves_potentially_reachable"],1)
        mapping["unwindless_direct_call_candidates"]=[]
        with self.assertRaises(ValueError):
            analyze(mapping,[entry])
        entry["original_direct_CALL_entry_without_pdata"]=False
        with self.assertRaises(ValueError):
            analyze(fixture(),[entry])
        entry["original_direct_CALL_entry_without_pdata"]=True
        entry["native_symbol"]="mx_unwindless_native_00999999"
        with self.assertRaises(ValueError):
            analyze(mapping,[entry])

    def test_known_native_prefixes_do_not_count_as_verified_full_leaves(self):
        known = {
            "pinned_original_sha256": SHA,
            "entries": [{
                "original_rva": "0x136120",
                "proof_kind": "bounded_native_branch",
                "scope": "original main partial callee in synthetic fixture",
                "evidence_run":
                  "https://github.com/NyerahMT/ReflexBuildInput/actions/runs/12345",
            }],
        }
        result = analyze(fixture(), [], known_proofs=known)
        self.assertEqual(
            result["combined"]["known_bounded_startup_proofs_in_static_reach"], 1)
        self.assertEqual(
            result["combined"]["verified_native_leaves_from_same_run"], 0)
        target = next(x for x in result["prioritized_next_static_dependencies"]
                      if x["target_rva"] == "0x136120")
        self.assertTrue(target["already_bounded_tested"])
        self.assertIn("do not relift", target["next_action"])
        known["pinned_original_sha256"] = "bad-digest"
        with self.assertRaises(ValueError):
            analyze(fixture(), [], known_proofs=known)

    def test_original_import_thunks_are_external_blockers_not_native_functions(self):
        sample={
            "original_sha256": SHA,
            "input_kind": "SHA-pinned PE import table plus static original x64 instructions",
            "original_import_thunks": [{
                "called_target_rva": "0x201000",
                "kind": "import_thunk",
                "import_dll": "msvcr90.dll",
                "import_symbol": "_amsg_exit",
                "iat_slot_rva": "0x360200",
            }],
            "direct_iat_callsites": [{
                "source_rva": "0x136710",
                "iat_slot_rva": "0x360100",
                "import_dll": "kernel32.dll",
                "import_symbol": "GetModuleFileNameA",
            }]
        }
        result=analyze(fixture(),[],import_graph=sample)
        self.assertEqual(
            result["combined"]["recognized_named_import_thunks_in_root_graph"],1)
        self.assertEqual(
            result["combined"]["recognized_direct_iat_callsites_in_root_graph"],1)
        self.assertEqual(
            result["combined"]["verified_native_leaves_from_same_run"],0)
        self.assertFalse(result["combined"]["import_thunk_is_native_callable_function"])
        target=next(x for x in result["prioritized_next_static_dependencies"]
                    if x["target_rva"]=="0x201000")
        self.assertEqual(target["import_thunk"]["symbol"],"_amsg_exit")
        self.assertIn("do not translate this thunk",target["next_action"])
        sample["original_sha256"]="unknown"
        with self.assertRaises(ValueError):
            analyze(fixture(),[],import_graph=sample)

    def test_report_files_contain_metadata_and_are_reproducible(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td)
            mp=root/"whole-game-map.json"
            evidence=root/"verified-leaf-registrations.json"
            mp.write_text(json.dumps(fixture()))
            evidence.write_text(json.dumps([verified(0x200000)]))
            result=run(mp,evidence,root/"reports")
            audit=json.loads((root/"reports"/"startup-chain-coverage.json").read_text())
            markdown=(root/"reports"/"startup-chain-coverage.md").read_text()
            self.assertEqual(result,audit)
            self.assertIn("0x136710",markdown)
            self.assertNotIn("Game.zip",markdown)


if __name__=="__main__":
    unittest.main()
