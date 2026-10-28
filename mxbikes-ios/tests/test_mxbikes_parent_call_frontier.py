"""Synthetic Win64 frame-to-first-CALL frontier regression tests.

No original MX Bikes bytes, generated original code or commercial assets.
"""
from pathlib import Path
import struct
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from mxbikes_parent_call_frontier import analyze, inspect_prefix, verified_targets
from mxbikes_win64_unwind_frame import decode_unwind, INPUT_SHA

PARENT = 0x200000
CALLEE = 0x200800
PDATA = 0x5000
XDATA = 0x6000
PROLOGUE = bytes.fromhex("53 4883ec20")  # push rbx; sub rsp,0x20
MOV = bytes.fromhex("b934120000")         # mov ecx,0x1234
EXIT = bytes.fromhex("4883c4205bc3")      # add rsp,0x20; pop rbx; ret
UNWIND = bytes([1, 5, 2, 0, 5, 0x32, 1, 0x30])

def direct_call(prefix, target=CALLEE):
    call_rva = PARENT + len(prefix)
    return b"\xe8" + struct.pack("<i", target - (call_rva + 5))

def body(prefix=PROLOGUE + MOV, target=CALLEE):
    return prefix + direct_call(prefix, target) + EXIT

class SyntheticPE:
    def __init__(self, data=None, xdata=UNWIND, include_pdata=True):
        self.data = body() if data is None else data
        self.xdata = xdata
        # Even the negative case has a well-formed unwind directory; its
        # record simply belongs to another function, not to this parent.
        begin = PARENT if include_pdata else PARENT + 0x1000
        self.pdata = struct.pack("<III", begin, begin + len(self.data), XDATA)
    def directory(self, entry):
        assert entry == 3
        return PDATA, len(self.pdata)
    def read_rva(self, rva, size):
        for start, data in (
            (PDATA, self.pdata), (XDATA, self.xdata), (PARENT, self.data)
        ):
            pos = rva - start
            if 0 <= pos <= len(data) and 0 <= size <= len(data) - pos:
                return data[pos:pos + size]
        raise ValueError("Synthetic RVA not mapped")

def mapping():
    return {
        "input_sha256": INPUT_SHA,
        "original_file_verified": True,
        "direct_call_graph": {hex(PARENT): [hex(CALLEE)]},
    }

def verified():
    return [{
        "original_rva": hex(CALLEE), "full_function_behavior_verified": True,
        "win64_guest_call_abi_verified": True,
        "code_presence": "ephemeral_ci_elf_only",
    }]

class OriginalParentCallFrontierTests(unittest.TestCase):
    def test_real_win64_entry_prefix_reaches_first_verified_call_and_stack_state(self):
        result = analyze(SyntheticPE(), mapping(), verified())
        self.assertEqual(result["parent_functions_considered"], 1)
        self.assertEqual(result["original_x64_entries_reaching_verified_leaf_as_first_call"], 1)
        trace = result["traces"][0]
        self.assertEqual(trace["callsite_rva"], hex(PARENT + len(PROLOGUE + MOV)))
        self.assertEqual(trace["pre_call_rsp_decrement_from_entry"], 40)
        self.assertEqual(trace["declared_prologue_rsp_decrement"], 40)
        self.assertEqual(trace["original_prefix_instructions_executed"], 3)
        self.assertFalse(trace["rbp_frame_declared"])
        self.assertFalse(trace["native_parent_function_verified"])
        self.assertEqual(result["full_parent_native_verified"], 0)

    def test_native_verified_first_call_immediately_after_unwind_prologue(self):
        # The first post-prologue instruction can itself be a CALL.
        report = analyze(SyntheticPE(body(PROLOGUE)), mapping(), verified())
        self.assertEqual(report["original_x64_entries_reaching_verified_leaf_as_first_call"], 1)
        self.assertEqual(report["traces"][0]["pre_call_rsp_decrement_from_entry"], 40)

    def test_verified_evidence_must_be_complete_native_proof(self):
        row = verified()[0]
        row["win64_guest_call_abi_verified"] = False
        self.assertEqual(verified_targets([row]), set())
        self.assertEqual(analyze(SyntheticPE(), mapping(), [row])["parent_functions_considered"], 0)

    def test_unwind_stack_disagreement_stops_audit(self):
        bad_unwind = bytes([1, 5, 2, 0, 5, 0x42, 1, 0x30])
        result = analyze(SyntheticPE(xdata=bad_unwind), mapping(), verified())
        self.assertEqual(result["original_x64_entries_reaching_verified_leaf_as_first_call"], 0)
        self.assertEqual(result["outcomes"]["unwind_stack_allocation_disagrees_with_x64"], 1)

    def test_prior_conditional_branch_is_not_pretended_to_be_straight_line(self):
        pe = SyntheticPE(body(PROLOGUE + bytes.fromhex("7500") + MOV))
        result = analyze(pe, mapping(), verified())
        self.assertEqual(result["outcomes"]["control_flow_before_first_call"], 1)

    def test_unverified_first_direct_callee_blocks_later_real_leaf(self):
        pe = SyntheticPE(body(PROLOGUE + MOV, target=CALLEE + 16))
        result = analyze(pe, mapping(), verified())
        self.assertEqual(result["outcomes"]["first_call_target_not_verified_native"], 1)

    def test_indirect_first_call_is_not_manually_resolved(self):
        pe = SyntheticPE(PROLOGUE + MOV + bytes.fromhex("ffd0") + EXIT)
        result = analyze(pe, mapping(), verified())
        self.assertEqual(result["outcomes"]["indirect_first_call"], 1)

    def test_unmapped_guest_memory_fails_closed(self):
        # mov eax,[rcx] tries to read a deliberately unprovided guest region.
        pe = SyntheticPE(body(PROLOGUE + bytes.fromhex("8b01") + MOV))
        result = analyze(pe, mapping(), verified())
        self.assertEqual(result["outcomes"]["entry_to_first_call_emulation_fault"], 1)

    def test_untrusted_game_digest_is_rejected_before_disassembly(self):
        m = mapping()
        m["input_sha256"] = "not-the-pinned-game"
        with self.assertRaises(ValueError):
            analyze(SyntheticPE(), m, verified())
        with self.assertRaises(ValueError):
            verified_targets({"not": "a native manifest"})

    def test_missing_original_unwind_never_promoted(self):
        result = analyze(SyntheticPE(include_pdata=False), mapping(), verified())
        self.assertEqual(result["outcomes"]["missing_parent_unwind_record"], 1)

if __name__ == "__main__":
    unittest.main()
