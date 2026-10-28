"""Dynamic actual x64 startup function ISA audit; no fake native proofs."""
from pathlib import Path
import sys,unittest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"scripts"))
from mxbikes_startup_native_family_audit import analyze_original_native_gates

BASE=0x140000000
class FakePE:
    def __init__(self,parts):
        self.parts=parts
    def read_rva(self,addr,length):
        if addr not in self.parts or len(self.parts[addr])!=length:
            raise ValueError("not original mapped")
        return self.parts[addr]

def candidate(entry,data):
    return {"original_function_entry_rva":hex(entry),
            "original_unwind_end_rva":hex(entry+len(data)),
            "post_main_instruction_hits":10,
            "unique_post_main_pc_rvas":3}

class OriginalNativeISAAnalysis(unittest.TestCase):
    def test_grouped_native_gate_classes_from_real_decoder_not_invented(self):
        examples=[
            (0x1000,bytes.fromhex("e800000000c3"),"Win64 CALL/import closure"),
            (0x1100,bytes.fromhex("0f28c1c3"),"SIMD/FP state"),
            (0x1200,bytes.fromhex("488b03c3"),"guest data-memory model"),
            (0x1300,bytes.fromhex("b801000000c3"),"scalar/branch semantics"),
            (0x1400,bytes.fromhex("488b0500000000c3"),"guest data-memory model"),
        ]
        priorities={"prioritized_original_functions":[candidate(a,blob) for a,blob,_ in examples]}
        audit=analyze_original_native_gates(
            FakePE({a:blob for a,blob,_ in examples}),priorities,base=BASE)
        self.assertEqual(audit["function_families_audited"],len(examples))
        for item,(_,blob,gate) in zip(audit["original_function_audits"],examples):
            self.assertEqual(item["audit_status"],"complete_linear_disassembly_not_CFG_proof")
            self.assertEqual(item["first_native_gate_family"],gate)
            self.assertFalse(item["complete_native_ARM64_executable_function_proved"])
            self.assertEqual(item["original_unwind_length_bytes"],len(blob))
            self.assertNotIn("original_bytes",item)
        self.assertEqual(audit["first_translation_blocker_family_counts"]["Win64 CALL/import closure"],1)
        self.assertFalse(audit["commercial_machine_bytes_exported"])

    def test_reject_partial_and_unmapped_inputs_and_massive_ranges(self):
        a=0x1000
        unresolved=analyze_original_native_gates(FakePE({a:b"\x0f"}),
            {"prioritized_original_functions":[candidate(a,b"\x0f")]},base=BASE)
        self.assertEqual(unresolved["original_function_audits"][0]["audit_status"],
                         "partial_linear_disassembly_requires_recovery")
        missing=analyze_original_native_gates(FakePE({}),
            {"prioritized_original_functions":[candidate(a,b"\xc3")]},base=BASE)
        self.assertEqual(missing["original_function_audits"][0]["audit_status"],
                         "unreadable_original_PE_window")
        with self.assertRaises(ValueError):
            analyze_original_native_gates(FakePE({}),
                {"prioritized_original_functions":[candidate(a,b"\xc3")]*129},
                base=BASE)

if __name__=="__main__":
    unittest.main()
