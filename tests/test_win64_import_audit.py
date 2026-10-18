"""Synthetic test cases: no commercial game inputs."""
import unittest
from tools.win64_import_audit import audit_inventory, norm_dll, markdown_summary

class ImportAuditTests(unittest.TestCase):
    def test_import_status_and_dynamic_calls(self):
        inventory={"sha256":"synthetic","imports":{
            "KERNEL32.DLL":["GetTickCount","GetStartupInfoA","Unseen"],
            "MSVCR90.dll":["_acmdln","fopen","strcpy"],
            "steam_api64.dll":["SteamAPI_Init","SteamAPI_RestartAppIfNecessary"],
            "OPENGL32.dll":["wglCreateContext"]}}
        trace={"windows_imports_called":{
            "KERNEL32.dll::GetTickCount":4,"MSVCR90.dll::fopen":1,
            "steam_api64.dll::SteamAPI_Init":1},
            "unimplemented_import":"steam_api64.dll::SteamAPI_Init"}
        r=audit_inventory(inventory,trace,{"steam_api64.dll":[{"archive":"Game.zip","size_bytes":250656}]})
        self.assertEqual((r["dll_count"],r["total_imports"],r["trace_calls_matched"]),(4,9,6))
        self.assertEqual(r["trace_calls_unmatched"],[])
        by_name={(x["dll"],x["symbol"]):x for x in r["imports"]}
        self.assertEqual(by_name["msvcr90.dll","_acmdln"]["kind"],"data")
        self.assertEqual(by_name["steam_api64.dll","SteamAPI_Init"]["status"],"needs_real_steam_integration")
        self.assertIn("SteamAPI_Init",markdown_summary(r))
    def test_fail_closed(self):
        with self.assertRaises(ValueError):norm_dll("../kernel32.dll")
        with self.assertRaises(ValueError):audit_inventory({"imports":{}})
        with self.assertRaises(ValueError):audit_inventory({"imports":{"kernel32.dll":[]}},
            {"windows_imports_called":{"badcall":3}})
    def test_missing_static_import_is_reported(self):
        r=audit_inventory({"imports":{"kernel32.dll":["Sleep"]}},
                          {"windows_imports_called":{"kernel32.dll::NewApi":2}})
        self.assertEqual(r["trace_calls_unmatched"][0]["calls"],2)

if __name__=="__main__":unittest.main()
