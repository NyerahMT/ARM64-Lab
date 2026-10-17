"""Synthetic startup graph classification tests; no commercial binaries."""
import unittest
from tools.startup_frontier import analyze_graph, classify, make_summary


class StartupFrontierTests(unittest.TestCase):
    def test_category_and_lifecycle_handling(self):
        self.assertEqual(classify("KERNEL32.DLL::QueryPerformanceCounter"), "time_and_scheduling")
        self.assertEqual(classify("STEAM_API64.DLL::SteamAPI_Shutdown"), "steam_lifecycle")
        self.assertEqual(classify("UNKNOWN.DLL::DifferentFunction"), "uncategorized")

    def test_bounded_graph_and_api_paths(self):
        graph = {
            "entry_function_found": True,
            "entry_function_rva": "0x100",
            "graph_depth_limit": 2,
            "graph_nodes": [
                {"rva":"0x100","depth":0,"external":False},
                {"rva":"0x200","depth":1,"external":False},
                {"rva":"0x300","depth":2,"external":False},
            ],
            "graph_edges": [
                {"from":"0x100","to":"0x200","external":False},
                {"from":"0x200","to":"0x300","external":False},
                {"from":"0x200","to":"external:1","api":"KERNEL32.DLL::Sleep","external":True},
                {"from":"0x300","to":"external:2","api":"STEAM_API64.DLL::SteamAPI_Shutdown","external":True},
            ],
        }
        report = analyze_graph(graph)
        self.assertEqual(report["internal_nodes_at_depth_limit"], 1)
        self.assertEqual(report["external_api_call_edges"], 2)
        self.assertEqual(report["distinct_external_api_names"], 2)
        groups = {p["category"]:p for p in report["compatibility_groups"]}
        self.assertEqual(groups["steam_lifecycle"]["priority"], "lifecycle; not necessarily boot-critical")
        self.assertEqual(groups["time_and_scheduling"]["paths"]["KERNEL32.DLL::Sleep"], [
            "0x100","0x200","KERNEL32.DLL::Sleep",
        ])
        self.assertIn("shutdown", make_summary(report).lower() + " shutdown")

    def test_missing_entry_rejected(self):
        with self.assertRaises(ValueError):
            analyze_graph({"entry_function_found":False, "graph_nodes":[], "graph_edges":[]})


if __name__ == "__main__":
    unittest.main()
