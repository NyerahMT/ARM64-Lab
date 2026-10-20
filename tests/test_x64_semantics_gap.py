"""Synthetic aggregate semantic-profile tests; no game code or bytes."""
import unittest
from tools.x64_semantics_gap import (
    aggregate_callbacks, summarize_mnemonics,
)

class AggregateGapTests(unittest.TestCase):
    def test_single_profile_groups_related_instruction_families(self):
        profile=summarize_mnemonics({
            "mov":7, "cmp":3, "jne":2, "ret":1,
            "xor":4, "or":1, "movzx":2, "test":1, "jns":1,
        })
        self.assertEqual(profile["instruction_total"],22)
        self.assertEqual(profile["mnemonics_currently_recognized"],13)
        self.assertEqual(profile["mnemonics_needing_extensions"],9)
        self.assertEqual(profile["extension_families"],{
            "flags_and_predicates":2,
            "integer_logic":5,
            "integer_width_conversion":2,
        })
        self.assertFalse(profile["native_translation_claimed"])
        self.assertFalse(profile["operand_and_import_semantics_verified"])

    def test_grouped_profiles_do_not_lose_repeated_mnemonics(self):
        result=aggregate_callbacks({
            "callback-a":{"mov":4,"xor":2,"ret":1},
            "callback-b":{"mov":6,"jns":1,"test":1,"ret":1},
            "callback-c":{"mov":1,"movsxd":1,"ret":1},
        })
        shared=result["grouped_instruction_profile"]
        self.assertEqual(shared["instruction_total"],18)
        self.assertEqual(shared["unsupported_mnemonics"],{
            "jns":1,"movsxd":1,"test":1,"xor":2,
        })
        self.assertEqual(shared["mnemonics_needing_extensions"],5)
        self.assertEqual(len(result["callbacks"]),3)

    def test_bad_counts_fail_closed(self):
        for value in (0,-1,True,1.5,"4",None):
            with self.subTest(value=value):
                with self.assertRaises(ValueError):
                    summarize_mnemonics({"mov":value})
        for value in ({}, {".db":1}, {"mov":4097},
                      {"not a mnemonic":1}, {"ä":1}):
            with self.subTest(value=value):
                with self.assertRaises(ValueError):
                    summarize_mnemonics(value)
        with self.assertRaises(ValueError):
            aggregate_callbacks({})
        with self.assertRaises(ValueError):
            aggregate_callbacks({"callback":{"mov":1},"invalid":{"xor":0}})
        with self.assertRaises(ValueError):
            aggregate_callbacks({str(x):{"ret":1} for x in range(33)})

if __name__=="__main__":
    unittest.main()
