"""Bounded original x64 startup import frontier classification tests."""
from copy import deepcopy
import unittest

from tools.boot_frontier import analyze_frontier, make_summary


def sample_trace():
    return {
        "original_instruction_count": 4270000,
        "native_arm64_executed": False,
        "stop_reason": "unsupported_external_api",
        "unimplemented_import": "steam_api64.dll::SteamAPI_Init",
        "unsupported_import_stack_return_rva": "0x2abe40",
        "windows_imports_called": {
            "KERNEL32.dll::GetTickCount": 2,
            "MSVCR90.dll::fread": 251,
            "MSVCR90.dll::_lock": 4,
            "steam_api64.dll::SteamAPI_RestartAppIfNecessary": 1,
            "steam_api64.dll::SteamAPI_Init": 1,
        },
        "crt_original_callback_entries": 5,
        "real_game_booted": False,
        "synthetic_import_returns": 300,
    }


class BootFrontierTests(unittest.TestCase):
    def test_steam_is_a_blocker_not_an_engine_milestone(self):
        report = analyze_frontier(sample_trace())
        self.assertEqual(report["first_blocker"]["name"],
                         "steam_api64.dll::SteamAPI_Init")
        self.assertEqual(report["first_blocker"]["category"],
                         "steam_or_external_runtime")
        self.assertEqual(
            report["first_blocker"]["original_guest_stack_return_rva_unexecuted"],
            "0x2abe40"
        )
        self.assertEqual(report["original_x64_instructions_executed"], 4270000)
        self.assertEqual(report["observed_x64_unique_imports"], 5)
        self.assertEqual(report["observed_x64_import_events"], 259)
        self.assertTrue(report["x64_progress_signals"]["steamapi_init_call_observed"])
        self.assertFalse(report["x64_progress_signals"]["window_api_call_observed"])
        self.assertFalse(report["x64_progress_signals"]["graphics_context_or_gl_call_observed"])
        self.assertFalse(any(report["native_milestones"].values()))
        self.assertIn("All four native", make_summary(report))
        statuses = {
            entry["import"]: entry["native_status"]
            for group in report["observed_groups"] for entry in group["imports"]
        }
        self.assertEqual(
            statuses["KERNEL32.dll::GetTickCount"],
            "native_portable_service_tested_in_isolation"
        )
        self.assertEqual(
            statuses["MSVCR90.dll::_lock"], "synthetic_crt_contract_only"
        )
        self.assertEqual(
            statuses["steam_api64.dll::SteamAPI_Init"],
            "steam_integration_not_implemented"
        )

    def test_dynamic_gl_does_not_imply_native_rendered_frame(self):
        data = sample_trace()
        data["stop_reason"] = "unsupported_external_api"
        data["unimplemented_import"] = "OPENGL32.dll::wglCreateContext"
        data["windows_imports_called"]["OPENGL32.dll::wglCreateContext"] = 1
        data["windows_imports_called"]["USER32.dll::CreateWindowExA"] = 1
        report = analyze_frontier(data)
        self.assertTrue(report["x64_progress_signals"]["graphics_context_or_gl_call_observed"])
        self.assertTrue(report["x64_progress_signals"]["window_api_call_observed"])
        self.assertFalse(report["native_milestones"]["first_original_rendered_frame"])
        self.assertEqual(report["first_blocker"]["category"], "graphics_context")

    def test_missing_or_unobserved_blocker_fails_closed(self):
        data = sample_trace()
        data["unimplemented_import"] = "USER32.dll::CreateWindowExA"
        with self.assertRaises(ValueError):
            analyze_frontier(data)
        data = sample_trace()
        data.pop("original_instruction_count")
        with self.assertRaises(ValueError):
            analyze_frontier(data)
        data = sample_trace()
        data["native_arm64_executed"] = True
        with self.assertRaises(ValueError):
            analyze_frontier(data)

    def test_bad_values_rejected_and_no_false_success(self):
        for field, value in (
            ("original_instruction_count", -1),
            ("original_instruction_count", 10_000_001),
            ("original_instruction_count", True),
            ("windows_imports_called", {}),
        ):
            data = sample_trace()
            data[field] = value
            if field == "windows_imports_called":
                data["unimplemented_import"] = "not_a_real_import"
            with self.subTest(field=field,value=str(value)):
                with self.assertRaises(ValueError):
                    analyze_frontier(data)
        for key, count in (
            ("MSVCR90.dll::fread", 0),
            ("MSVCR90.dll::fread", -1),
            ("MSVCR90.dll::fread", True),
        ):
            data=sample_trace()
            data["windows_imports_called"][key]=count
            with self.assertRaises(ValueError):
                analyze_frontier(data)
        data=sample_trace()
        data["windows_imports_called"]["some malformed import"]=1
        with self.assertRaises(ValueError):
            analyze_frontier(data)

    def test_bad_return_rva_rejected(self):
        for value in ("after", "0x", "0x100000000", 4, True):
            data = sample_trace()
            data["unsupported_import_stack_return_rva"] = value
            with self.subTest(value=str(value)):
                with self.assertRaises(ValueError):
                    analyze_frontier(data)

    def test_no_supported_import_and_memory_fault(self):
        data = sample_trace()
        data["unimplemented_import"] = None
        data["stop_reason"] = "emulator_exception"
        data["memory_fault"] = {"pc_rva": "0x123", "fault_address": "0x123456"}
        result = analyze_frontier(data)
        self.assertEqual(result["first_blocker"]["category"], "guest_memory")
        self.assertFalse(any(result["native_milestones"].values()))


if __name__ == "__main__":
    unittest.main()
