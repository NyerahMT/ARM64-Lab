import unittest,sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"scripts"))
import mxbikes_main_callee_three_branches_native as three
import mxbikes_main_callee_next_pair_native as prior
import mxbikes_main_callee_arg_group_native as argv
import mxbikes_main_callee_quote_jne_native as quote
import mxbikes_main_callee_followup_native as followup
import mxbikes_main_callee_third_jle_native as third
import mxbikes_main_callee_second_jge_native as second
import mxbikes_main_callee_branch_pair_native as pair
import mxbikes_main_joined_callee_native as joined
class ParserTripleTests(unittest.TestCase):
    def test_three_exact_original_control_shapes_fail_closed(self):
        blocks=[
         {"instruction_forms":[{"mnemonic":"cmp","op_str":"al, 0x7e"}],
           "control_rva":"0x13619d","control_kind":"jg",
           "control_direct_target_rva":"0x1361b9","control_next_rva":"0x13619f"},
         {"instruction_forms":[{"mnemonic":"nop","op_str":"dword ptr [rax]"},
             {"mnemonic":"cmp","op_str":"al, 0x20"}],
           "control_rva":"0x1361e2","control_kind":"jle",
           "control_direct_target_rva":"0x1361f2","control_next_rva":"0x1361e4"},
         {"instruction_forms":[{"mnemonic":"cmp","op_str":"byte ptr [rcx], 0"}],
           "control_rva":"0x1361f5","control_kind":"je",
           "control_direct_target_rva":"0x1361fd","control_next_rva":"0x1361f7"}]
        original=three.mapping.first_control
        try:
            three.mapping.first_control=lambda _pe,entry:blocks[
              (three.JG_ROOT,three.JLE_ROOT,three.JE_ROOT).index(entry)]
            self.assertEqual(three.verify_original_controls(None),blocks)
            blocks[2]["control_next_rva"]="0x1361f8"
            with self.assertRaises(ValueError):three.verify_original_controls(None)
        finally:three.mapping.first_control=original
    def test_native_link_preserves_original_argument_memory(self):
        src=third.extend_third_jle(second.extend_joined_source(
          joined.SOURCE,joined.BASE+0xd14cce))
        src=pair.extend_native_pair(src,[0]*16,["returned"]*10+
          ["frontier"]*6,[18]*10+[38]*6)
        src=followup.extend_joined_native_followup(src)
        src=quote.extend_quote_native(src)
        src=argv.extend_native_argument_blocks(src,[0]*16,[0]*16,[18]*16)
        src=prior.append_native_pair(src)
        ref=[(b,joined.BASE+(three.JE_TAKEN if b==0 else three.JE_FALL),
            0,int(b==0),int(bool(b&128))) for b in (0,0x51,0x81)]
        adapted=three.append_native(src,ref)
        self.assertIn("static int native_three_controls",adapted)
        self.assertIn("native_arg_store(s,m);",adapted)
        self.assertIn("expected_arg_slot_after[i]",adapted)
        self.assertIn("mx_native_link_call_frontier_set",adapted)
        self.assertIn("proof_bytes[3]",adapted)
        with self.assertRaises(ValueError):three.append_native(joined.SOURCE,ref)
if __name__=="__main__":unittest.main()
