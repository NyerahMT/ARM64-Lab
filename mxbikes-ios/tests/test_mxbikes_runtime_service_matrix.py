"""Synthetic original import inputs, real reviewed catalog, no game executable."""
import json
from pathlib import Path
import sys
import tempfile
import unittest

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/"scripts"))
from mxbikes_runtime_service_matrix import (
    SHA, analyze, validate_catalog, render, run,
)
CATALOG=json.loads((ROOT/"scripts"/"mxbikes_runtime_service_catalog.json").read_text())
SCANTYPE="SHA-pinned PE import table plus static original x64 instructions"


def scan(services=None):
    services=CATALOG["services"] if services is None else services
    return {
        "schema":1,
        "original_sha256":SHA,
        "input_kind":SCANTYPE,
        "import_dependencies":[
            {"dll":s["dll"],"symbol":s["symbol"],"statically_referenced":1}
            for s in services
        ],
        "identified_import_thunks":6,
        "identified_direct_iat_callsites":15,
    }


class RuntimeServiceMatrixTests(unittest.TestCase):
    def test_all_twenty_known_services_grouped_but_not_assumed_implemented(self):
        report=analyze(scan(), CATALOG)
        self.assertEqual(report["total_named_services_observed"],20)
        self.assertEqual(report["bounded_host_dispatch_count"],7)
        self.assertEqual(report["test_only_guest_model_count"],6)
        self.assertEqual(report["terminal_boundary_count"],1)
        self.assertEqual(report["missing_service_count"],6)
        self.assertEqual(report["unclassified_original_imports"],[])
        self.assertEqual(len(report["families"]),8)
        self.assertEqual(report["fully_implemented_win64_services"],0)
        self.assertFalse(report["original_game_engine_booted_on_arm64"])
        self.assertFalse(report["real_windows_dlls_executed"])
        m={(s["dll"],s["symbol"]):s for s in report["services"]}
        self.assertEqual(m["kernel32.dll","GetModuleFileNameA"]["status"],
                         "test_guest_model")
        self.assertEqual(m["kernel32.dll","SetCurrentDirectoryA"]["status"],
                         "test_guest_model")
        self.assertEqual(m["msvcr90.dll","strcpy"]["status"],"test_guest_model")
        self.assertEqual(m["msvcr90.dll","strrchr"]["status"],"test_guest_model")
        self.assertEqual(m["msvcr90.dll","_amsg_exit"]["status"],
                         "terminal_boundary_only")
        self.assertEqual(m["kernel32.dll","QueryPerformanceCounter"]["status"],
                         "host_dispatch_bounded")
        text=render(report)
        self.assertIn("Missing-capability batches",text)
        self.assertIn("strrchr",text)
        self.assertIn("fopen",text)

    def test_symbol_casefold_matches_actual_import_names(self):
        original=scan()
        original["import_dependencies"][0]["dll"]="KERNEL32.DLL"
        original["import_dependencies"][0]["symbol"]="getcurrentprocessid"
        report=analyze(original,CATALOG)
        self.assertEqual(report["total_named_services_observed"],20)
        self.assertEqual(report["missing_service_count"],6)

    def test_new_original_service_requires_review_no_fake_success(self):
        data=scan()
        data["import_dependencies"].append({
            "dll":"kernel32.dll","symbol":"CreateFileA",
            "statically_referenced":2
        })
        with self.assertRaisesRegex(ValueError,"no audited runtime disposition"):
            analyze(data,CATALOG)
        loose=analyze(data,CATALOG,strict=False)
        self.assertEqual(loose["status_counts"]["unclassified"],1)
        self.assertTrue(loose["unclassified_original_imports"])
        self.assertEqual(loose["fully_implemented_win64_services"],0)

    def test_wrong_sha_duplicates_and_unsupported_capability_fail_closed(self):
        data=scan()
        data["original_sha256"]="bad"
        with self.assertRaises(ValueError):
            analyze(data,CATALOG)
        data=scan()
        data["import_dependencies"].append(data["import_dependencies"][0])
        with self.assertRaisesRegex(ValueError,"Duplicate"):
            analyze(data,CATALOG)
        cat=json.loads(json.dumps(CATALOG))
        cat["services"][0]["production_win64_service"]=True
        with self.assertRaises(ValueError):
            analyze(scan(),cat)
        cat=json.loads(json.dumps(CATALOG))
        cat["services"][0]["implementation"]=None
        with self.assertRaises(ValueError):
            validate_catalog(cat)
        cat=json.loads(json.dumps(CATALOG))
        cat["services"][0]["implementation"]="runtime/../../untrusted.c"
        with self.assertRaises(ValueError):
            validate_catalog(cat)

    def test_runtime_code_provenance_must_exist_when_checked(self):
        with tempfile.TemporaryDirectory() as td:
            with self.assertRaisesRegex(ValueError,"unavailable"):
                analyze(scan(),CATALOG,runtime_root=td)
            for item in CATALOG["services"]:
                impl=item["implementation"]
                if impl:
                    path=Path(td)/impl
                    path.parent.mkdir(parents=True,exist_ok=True)
                    path.write_text("synthetic")
            result=analyze(scan(),CATALOG,runtime_root=td)
            self.assertEqual(result["bounded_host_dispatch_count"],7)

    def test_report_written_as_metadata_only(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td)
            path=root/"scan.json"
            catalog=root/"catalog.json"
            path.write_text(json.dumps(scan()))
            catalog.write_text(json.dumps(CATALOG))
            output=root/"out"
            actual=run(path,catalog,output)
            self.assertEqual(actual,json.loads(
                (output/"startup-runtime-service-matrix.json").read_text()))
            md=(output/"startup-runtime-service-matrix.md").read_text()
            self.assertIn("Missing/unsupported runtime services: **6**",md)
            self.assertNotIn("mxbikes.exe",md.lower())
            self.assertNotIn("synthetic machine code",md)


if __name__=="__main__":
    unittest.main()
