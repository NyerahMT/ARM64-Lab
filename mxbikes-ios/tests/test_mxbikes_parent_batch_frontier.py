"""Synthetic branch-matrix regression for all-parent Win64 first-CALL tracing.

All instruction bytes are invented fixtures; no commercial executable data.
"""
import sys
from pathlib import Path
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from mxbikes_parent_batch_frontier import (
    analyze, run_fixture, preflight, MAX_CASES, MAX_INSTRUCTIONS,
)
from mxbikes_win64_unwind_frame import decode_unwind
from test_mxbikes_parent_call_frontier import (
    SyntheticPE, PARENT, CALLEE, XDATA, PROLOGUE, EXIT,
    body, direct_call, mapping, verified,
)

def branching_body():
    # push rbx, sub rsp,32; test ecx,ecx; JNE skips first CALL.
    # Two reachable genuine x64 first-CALL sites in one parent.
    prefix = PROLOGUE + bytes.fromhex("85c9 7505")
    first = direct_call(prefix)
    second = direct_call(prefix + first)
    return prefix + first + second + EXIT

class BatchedParentFirstCallTests(unittest.TestCase):
    def test_all_twelve_seeded_cases_split_real_x64_branch_paths(self):
        pe = SyntheticPE(branching_body())
        data = analyze(pe, mapping(), verified(), max_cases=MAX_CASES)
        self.assertEqual(data["parent_functions_considered"], 1)
        self.assertEqual(data["original_x64_fixtures_executed"], MAX_CASES)
        self.assertEqual(data["original_parent_entries_reaching_verified_first_call"], 1)
        self.assertEqual(data["distinct_original_verified_first_call_edges_reached"], 2)
        self.assertEqual(data["fixture_outcomes"]["original_x64_first_verified_call_reached"], MAX_CASES)
        self.assertEqual(data["native_parent_functions_added"], 0)
        self.assertFalse(data["original_game_code_or_guest_register_values_exported"])

    def test_unsupported_guest_memory_across_all_fixtures_is_not_promoted(self):
        # Actual x64 code reads at fixture-controlled RCX with no guest heap mapping.
        pe = SyntheticPE(body(PROLOGUE + bytes.fromhex("8b01")))
        report = analyze(pe, mapping(), verified(), max_cases=MAX_CASES)
        # A minority of explicit register fixtures can validly read the
        # mapped guest stack. They MUST be accepted, while unmapped guest
        # pointers MUST fault. Neither outcome creates native parent code.
        self.assertEqual(report["original_x64_fixtures_executed"], MAX_CASES)
        self.assertGreater(report["fixture_outcomes"].get(
            "original_x64_guest_memory_or_execution_fault", 0), 0)
        self.assertGreater(report["fixture_outcomes"].get(
            "original_x64_first_verified_call_reached", 0), 0)
        self.assertEqual(report["native_parent_functions_added"], 0)

    def test_second_verified_call_after_unverified_first_is_not_reached(self):
        prefix = PROLOGUE
        other = direct_call(prefix, CALLEE + 0x30)
        correct = direct_call(prefix + other)
        pe = SyntheticPE(prefix + other + correct + EXIT)
        report = analyze(pe, mapping(), verified(), max_cases=4)
        self.assertEqual(report["distinct_original_verified_first_call_edges_reached"], 0)
        self.assertEqual(report["fixture_outcomes"]["first_call_not_native_verified"], 4)

    def test_bounded_infinite_loop_is_terminated(self):
        pe = SyntheticPE(PROLOGUE + bytes.fromhex("ebfe"))
        report = analyze(pe, mapping(), verified(), max_cases=3)
        self.assertEqual(report["fixture_outcomes"]["instruction_budget_exhausted"], 3)
        self.assertEqual(report["native_parent_functions_added"], 0)

    def test_test_domain_heap_fixture_does_not_promote_native_parent(self):
        # A synthesized guest pointer into a deliberately bounded page
        # is an x64 fixture only, not proof of real Windows heap behavior.
        pe = SyntheticPE(body(PROLOGUE + bytes.fromhex("8b01")))
        report = analyze(pe, mapping(), verified(), max_cases=MAX_CASES)
        self.assertEqual(report["fixture_count_per_eligible_parent"], MAX_CASES)
        self.assertEqual(report["original_x64_fixtures_executed"], MAX_CASES)
        self.assertGreater(report["fixture_profile_outcomes"].get(
            "bounded_guest_heap_and_pe_snapshot:original_x64_first_verified_call_reached", 0), 0)
        self.assertEqual(report["native_parent_functions_added"], 0)

    def test_extended_fixtures_can_read_only_real_pe_data_snapshot(self):
        import struct
        target = 0x300000
        prefix = PROLOGUE
        # mov eax, dword ptr [rip+disp32] from a non-executable PE data
        # section. The page contains a real fixture byte image, not an
        # invented Windows import result or executable function.
        load_rva = PARENT + len(prefix)
        disp = target - (load_rva + 6)
        prefix += b"\x8b\x05" + struct.pack("<i", disp)
        pe = SyntheticPE(body(prefix))
        backing = bytearray(4096)
        backing[:4] = b"\x12\x34\x56\x78"
        pe.sections = [(".rdata", 4096, target, 4096, 0, 0x40000040)]
        pe.b = bytes(backing)
        original_read = pe.read_rva
        def read_backed_rva(rva, size):
            if target <= rva and rva + size <= target + len(pe.b):
                return pe.b[rva - target:rva - target + size]
            return original_read(rva, size)
        pe.read_rva = read_backed_rva
        report = analyze(pe, mapping(), verified(), max_cases=MAX_CASES)
        self.assertEqual(report["original_x64_fixtures_executed"], MAX_CASES)
        self.assertEqual(report["distinct_original_verified_first_call_edges_reached"], 1)
        self.assertEqual(report["distinct_first_call_edges_reached_without_heap_or_pe_data"], 0)
        self.assertEqual(report["distinct_first_call_edges_reached_using_extended_test_memory"], 1)
        self.assertEqual(report["native_parent_functions_added"], 0)

    def test_extended_fixtures_never_map_executable_snapshot_as_fake_data(self):
        import struct
        target = 0x300000
        prefix = PROLOGUE
        disp = target - (PARENT + len(prefix) + 6)
        prefix += b"\x8b\x05" + struct.pack("<i", disp)
        pe = SyntheticPE(body(prefix))
        pe.sections = [(".text", 4096, target, 4096, 0, 0x60000020)]
        pe.b = bytes(4096)
        report = analyze(pe, mapping(), verified(), max_cases=MAX_CASES)
        self.assertEqual(report["distinct_original_verified_first_call_edges_reached"], 0)
        self.assertEqual(report["native_parent_functions_added"], 0)

    def test_exact_legal_zero_prologue_unwind_can_reach_valid_first_call(self):
        # Original x64 frameless body uses a transient RSP adjustment before
        # CALL, with a valid Win64 pre-CALL 16-byte aligned stack.
        prefix = bytes.fromhex("488d6424d8")
        pe = SyntheticPE(
            prefix + direct_call(prefix) + bytes.fromhex("488d642428c3"),
            xdata=bytes([1, 0, 0, 0]),
        )
        report = analyze(pe, mapping(), verified(), max_cases=6)
        self.assertEqual(report["exact_empty_unwind_parent_records_accepted"], 1)
        self.assertEqual(report["distinct_original_verified_first_call_edges_reached"], 1)
        self.assertEqual(report["fixture_outcomes"]["original_x64_first_verified_call_reached"], 6)
        self.assertEqual(report["native_parent_functions_added"], 0)

    def test_empty_unwind_header_must_have_no_flags_frame_or_codes(self):
        prefix = bytes.fromhex("488d6424d8")
        src = prefix + direct_call(prefix) + bytes.fromhex("488d642428c3")
        for bad in (bytes([0x21, 0, 0, 0]),  # chained entry
                    bytes([1, 0, 1, 0]),     # code slot specified
                    bytes([1, 0, 0, 0x05]),  # RBP frame declared
                    bytes([3, 0, 0, 0])):   # unknown x64 unwind version
            report = analyze(SyntheticPE(src, xdata=bad), mapping(), verified(), max_cases=6)
            self.assertEqual(report["original_x64_fixtures_executed"], 0)
            self.assertEqual(report["native_parent_functions_added"], 0)

    def test_unwind_disagreement_skips_all_fixtures(self):
        bad = bytes([1, 5, 2, 0, 5, 0x42, 1, 0x30])
        report = analyze(SyntheticPE(xdata=bad), mapping(), verified())
        self.assertEqual(report["original_x64_fixtures_executed"], 0)
        self.assertEqual(report["candidate_parent_rejections"][
            "unwind_stack_allocation_disagrees_with_x64"], 1)

    def test_complete_native_manifest_required_and_bounded_fixtures(self):
        x = verified()[0]
        x["full_function_behavior_verified"] = False
        report = analyze(SyntheticPE(), mapping(), [x])
        self.assertEqual(report["parent_functions_considered"], 0)
        self.assertEqual(report["original_x64_fixtures_executed"], 0)
        with self.assertRaises(ValueError):
            analyze(SyntheticPE(), mapping(), verified(), max_cases=MAX_CASES + 1)
        with self.assertRaises(ValueError):
            analyze(SyntheticPE(), mapping(), verified(), max_cases=0)
        m = mapping()
        m["original_file_verified"] = False
        with self.assertRaises(ValueError):
            analyze(SyntheticPE(), m, verified())

    def test_direct_unconditional_first_call_after_prologue(self):
        pe = SyntheticPE(body(PROLOGUE))
        result = analyze(pe, mapping(), verified(), max_cases=8)
        self.assertEqual(result["distinct_original_verified_first_call_edges_reached"], 1)
        self.assertEqual(result["original_parent_entries_reaching_verified_first_call"], 1)
        self.assertEqual(result["fixture_outcomes"]["original_x64_first_verified_call_reached"], 8)

if __name__ == "__main__":
    unittest.main()
