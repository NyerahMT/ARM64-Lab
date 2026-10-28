"""Launch-first diagnostics: synthetic metadata only; no commercial code."""
import json
from pathlib import Path
import sys
import tempfile
import unittest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"scripts"))
from mxbikes_launch_frontier import summarize,run,SHA,EXPECTED_SOURCE,EXPECTED_IMPORT


def fixtures():
    mapping={
        "input_sha256":SHA,"original_file_verified":True,
        "direct_call_graph":{
            "0x136710":["0x136120","0x133e80","0x201000"],
            "0x136120":[],
        }
    }
    link={
        "source_original_sha256":SHA,"source":EXPECTED_SOURCE,
        "native_dispatch_table":[{"original_rva":"0x220000",
                                  "native_symbol":"mx_unwindless_native_00220000"}],
        "verified_native_function_registrations":1,
        "main_direct_call_edges_within_depth":3,
        "unresolved_main_direct_edges":3,
        "prioritized_unresolved_edges":[
            {"source_rva":"0x136710","target_rva":hex(x),
             "native_status":"unwindless_first_block_only_no_verified_native",
             "source_depth":0,"ready_for_native_dispatch":False}
            for x in (0x136120,0x133e80,0x201000)]
    }
    imports={
        "original_sha256":SHA,"input_kind":EXPECTED_IMPORT,
        "direct_iat_callsites":[{"source_rva":"0x136710",
                                 "import_dll":"MSVCR90.dll","import_symbol":"fopen"}]
    }
    service={"original_sha256":SHA,"services":[
        {"dll":"MSVCR90.dll","symbol":"fopen","family":"file_io","status":"missing"},
        {"dll":"kernel32.dll","symbol":"GetTickCount","family":"clock","status":"bounded_host_dispatch"}
    ]}
    probe={
        "original_x64_startup_probe":{
            "original_process_milestones_reached":{"crt_tail":True,"game_main":True},
            "original_instructions_reached":1241,
            "first_stopping_boundary":{
                "type":"missing_original_file_or_unimplemented_readonly_crt_file_operation",
                "import":"MSVCR90.dll::fopen"}
        },
        "native_arm64_startup_readiness":{"native_verified_original_complete_functions":0}
    }
    coverage={"original_sha256":SHA,"combined":{
        "verified_native_leaves_from_same_run":1,
        "verified_leaves_potentially_reachable":0,
        "potentially_reachable_static_nodes":19
    }}
    return [mapping,link,imports,service,probe,coverage]


class LaunchFrontierTests(unittest.TestCase):
    def test_separates_real_original_x64_frontier_from_arm64_boot(self):
        r=summarize(*fixtures())
        self.assertEqual(r["native_functions_full_return_differential_verified"],1)
        self.assertEqual(r["native_functions_linked_into_persistent_executable"],0)
        self.assertEqual(r["main_call_closure"]["bounded_static_direct_call_edges_unresolved"],3)
        self.assertEqual(r["main_call_closure"]["direct_callees_verified"],0)
        self.assertEqual(r["main_call_closure"]["first_unresolved_edges"][0]["target_rva"],"0x136120")
        self.assertTrue(r["launch_gates"]["original_x64_game_main_observed_in_emulator"])
        self.assertFalse(r["launch_gates"]["native_game_main_full_function_verified"])
        self.assertFalse(r["launch_gates"]["native_first_main_callee_full_function_verified"])
        self.assertFalse(r["launch_gates"]["persistent_arm64_function_objects_linked"])
        self.assertEqual(r["original_x64_reference_frontier"]["service_status"],
                         {"family":"file_io","status":"missing"})
        self.assertEqual(r["original_x64_reference_frontier"]["initial_probe_native_evidence_count"],0)
        self.assertFalse(r["overall_port_completion_percent_available"])
        self.assertEqual(r["launch_milestones_passed"],0)

    def test_closure_progress_not_equivalent_to_running_executable(self):
        values=fixtures()
        values[1]["native_dispatch_table"].append({
            "original_rva":"0x136120","native_symbol":"mx_verified_00136120"})
        values[1]["verified_native_function_registrations"]=2
        values[1]["unresolved_main_direct_edges"]=2
        values[1]["prioritized_unresolved_edges"]=[
            x for x in values[1]["prioritized_unresolved_edges"]
            if x["target_rva"]!="0x136120"]
        values[5]["combined"]["verified_native_leaves_from_same_run"]=2
        result=summarize(*values)
        self.assertEqual(result["main_call_closure"]["direct_callees_verified"],1)
        self.assertTrue(result["launch_gates"]["native_first_main_callee_full_function_verified"])
        self.assertFalse(result["launch_gates"]["persistent_arm64_function_objects_linked"])
        self.assertFalse(result["launch_gates"]["original_native_arm64_entry_executed"])

    def test_bad_sha_and_fabricated_native_evidence_fail_closed(self):
        import copy
        values=fixtures()
        values[3]["original_sha256"]="wrong"
        with self.assertRaises(ValueError):summarize(*values)
        values=fixtures()
        values[1]["native_dispatch_table"].append(values[1]["native_dispatch_table"][0])
        values[1]["verified_native_function_registrations"]=2
        with self.assertRaises(ValueError):summarize(*values)
        values=fixtures()
        values[1]["unresolved_main_direct_edges"]=2
        with self.assertRaises(ValueError):summarize(*values)
        values=fixtures()
        values[0]["direct_call_graph"]["0x136710"].remove("0x136120")
        with self.assertRaises(ValueError):summarize(*values)

    def test_compact_artifacts_reproducible_without_binary_or_code(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp)
            paths=[]
            for i,x in enumerate(fixtures()):
                p=root/f"input-{i}.json"
                p.write_text(json.dumps(x))
                paths.append(p)
            output=root/"metadata"
            result=run(*paths,output)
            emitted=json.loads((output/"launch-first-blocker-ledger.json").read_text())
            self.assertEqual(emitted,result)
            markdown=(output/"launch-first-blocker-ledger.md").read_text()
            self.assertIn("native functions linked in an executable: **0**",markdown.lower())
            self.assertIn("0x136120",markdown)
            self.assertIn("MSVCR90.dll::fopen",markdown)
            self.assertNotIn("original_executable_bytes",json.dumps(result))
            self.assertTrue(result["source_code_or_original_executable_exported"] is False)


if __name__=="__main__":
    unittest.main()
