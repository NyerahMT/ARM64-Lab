"""Synthetic PE64 unwind and import callsite-to-engine handoff tests."""
import unittest

from tests.test_pe_call_clusters import FakePE
from tools.pe_import_handoff import find_handoff


class ImportedCallsiteTests(unittest.TestCase):
    def test_rip_indirect_import_and_next_branch(self):
        # CALL [RIP+0xA] reads IAT RVA 0x2010. The return RVA is 0x2006.
        pe = FakePE({0x2000: bytes.fromhex("ff150a00000085c07401c3c3")})
        result = find_handoff(pe,0x2006,{0x2010:"synthetic.dll::Init"})
        self.assertEqual(result["original_import_call_site_rva"], "0x2000")
        self.assertEqual(result["guest_return_rva"], "0x2006")
        self.assertEqual(result["import"]["kind"], "iat_indirect_call")
        self.assertEqual(result["import"]["symbol"], "synthetic.dll::Init")
        self.assertEqual(result["unwind_caller_rva"], "0x2000")
        self.assertEqual(result["next_instruction_rva"], "0x2006")
        self.assertTrue(result["nearby_next_12_has_conditional_branch"])
        branch=result["post_import_accumulator_zero_branch"]
        self.assertEqual(branch["predicate_register"],"eax")
        self.assertEqual(branch["zero_result_continuation_rva"],"0x200b")
        self.assertEqual(branch["nonzero_result_continuation_rva"],"0x200a")
        self.assertTrue(branch["both_continuations_unexecuted"])
        self.assertEqual(result["function_static_import_calls"],
                         [{"name":"synthetic.dll::Init","sites":1}])
        self.assertFalse(result["native_engine_execution"])
        self.assertFalse(result["supported_imported_service_executed"])

    def test_direct_call_import_jump_thunk(self):
        pe=FakePE({0x1200: bytes.fromhex("e8fb0d000085c0c3")},
                  extras={0x2000: bytes.fromhex("ff25fa0f0000")})
        result=find_handoff(pe,0x1205,{0x3000:"synthetic.dll::Start"})
        self.assertEqual(result["import"]["kind"],
                         "direct_call_via_iat_jmp_thunk")
        self.assertEqual(result["import"]["symbol"],"synthetic.dll::Start")
        self.assertEqual(result["import"]["thunk_rva"],"0x2000")
        self.assertIsNone(result["post_import_accumulator_zero_branch"])

    def test_reject_unverified_or_missing_return_site(self):
        pe=FakePE({0x2100: bytes.fromhex("31c0c3")})
        with self.assertRaisesRegex(ValueError,"imported CALL"):
            find_handoff(pe,0x2102,{})
        with self.assertRaises(ValueError):
            find_handoff(pe,0x9999,{})
        with self.assertRaises(ValueError):
            find_handoff(pe,True,{})
        with self.assertRaises(ValueError):
            find_handoff(pe,0x2101,{0x100000000:"a.dll::f"})

    def test_partial_bytecode_and_missing_import_fail_closed(self):
        pe=FakePE({0x2200:bytes.fromhex("ff150a000000c3")})
        with self.assertRaisesRegex(ValueError,"verified imported"):
            find_handoff(pe,0x2206,{})
        with self.assertRaises(ValueError):
            find_handoff(pe,0x2206,{0x2210:"a.dll::f"},
                         max_function_bytes=1)

if __name__=="__main__":
    unittest.main()
