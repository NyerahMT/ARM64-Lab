"""Synthetic original x64 second-JGE identity and fail-closed patch tests."""
from pathlib import Path
import sys
import unittest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"scripts"))
from mxbikes_main_callee_second_jge_native import (
    ENTRY,JGE_FALLTHROUGH,verify_second_branch,extend_joined_source)
import mxbikes_main_joined_callee_native as joined

class OriginalSecondJGETests(unittest.TestCase):
    def test_exact_original_nonempty_x64_control_sequence(self):
        # Independent assembler-known x64 bytes for the four source opcodes.
        body=bytes.fromhex(
            "488b542408"  # MOV RDX,[RSP+8]
            "4c8d1dce4cd100" # LEA R11,[RIP+0xd14cce]
            "4181fa80000000" # CMP R10D,0x80
            "0f8da8000000" # JGE 0x136207
        )
        self.assertEqual(len(body),JGE_FALLTHROUGH-ENTRY)
        class FakePE:
            def __init__(self,data):self.data=data
            def read_rva(self,at,size):
                if at!=ENTRY or size!=len(self.data):raise ValueError
                return self.data
        address=verify_second_branch(FakePE(body))
        self.assertEqual(address,joined.BASE+0x136152+0xd14cce)
        corrupted=bytearray(body);corrupted[-1]^=1
        with self.assertRaises(ValueError):
            verify_second_branch(FakePE(bytes(corrupted)))

    def test_next_original_control_budget_and_no_false_arm64_claim(self):
        from mxbikes_main_callee_second_jge_native import (
            JGE_FALLTHROUGH,discover_next_control)
        # MOV EAX,3 / TEST EAX,EAX / JNE +2 / RET / RET
        body=bytes.fromhex("b80300000085c07502c3c3")+b"\x90"*192
        class FakePE:
            def read_rva(self,at,size):
                if at!=JGE_FALLTHROUGH or size!=192:raise ValueError
                return body[:size]
        result=discover_next_control(FakePE())
        self.assertEqual(result["original_straightline_instructions"],2)
        self.assertEqual(result["next_original_control_kind"],"jne")
        self.assertFalse(result["native_arm64_continuation_implemented"])
        with self.assertRaises(ValueError):
            discover_next_control(FakePE(),max_bytes=999)
        with self.assertRaises(ValueError):
            discover_next_control(FakePE(),start=JGE_FALLTHROUGH+1)

    def test_integration_keeps_native_return_and_rejects_changed_linker(self):
        template=joined.SOURCE
        patched=extend_joined_source(template,joined.BASE+0xe4)
        self.assertIn("static int native_nonempty_jge",patched)
        self.assertIn("r,s,m,CALLEE,AFTER_CALL,TAKEN,SECOND_JGE_FALLTHROUGH);",patched)
        self.assertIn("s.instructions!=(f->in_byte==0U?18U:20U)",patched)
        self.assertIn("return mx_game_main_callee_finish_empty(s,m,&callee_layout);",patched)
        with self.assertRaises(ValueError):
            extend_joined_source(template.replace("TAKEN,FALLTHROUGH);",
                                                  "TAKEN,OTHER);"),joined.BASE+0xe4)
        with self.assertRaises(ValueError):
            extend_joined_source(template,0)

if __name__=="__main__":
    unittest.main()
