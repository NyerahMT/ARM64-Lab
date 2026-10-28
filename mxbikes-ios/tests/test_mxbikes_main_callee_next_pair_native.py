"""Run native grouped original signed-JL and zero-check JE without game assets."""
from pathlib import Path
import sys,unittest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"scripts"))
import mxbikes_main_callee_next_pair_native as group
import mxbikes_main_callee_arg_group_native as argv
import mxbikes_main_callee_quote_jne_native as quote
import mxbikes_main_callee_followup_native as followup
import mxbikes_main_callee_third_jle_native as third
import mxbikes_main_callee_second_jge_native as second
import mxbikes_main_callee_branch_pair_native as pair
import mxbikes_main_joined_callee_native as joined

class NextParserNativeBranches(unittest.TestCase):
    def test_original_jl_je_metadata_gate(self):
        quote_branch={
          "instruction_forms":[{"mnemonic":"movzx","op_str":"eax, byte ptr [rdx]"},
                               {"mnemonic":"cmp","op_str":"al, 0x20"}],
          "control_rva":"0x136199","control_kind":"jl",
          "control_direct_target_rva":"0x1361b9","control_next_rva":"0x13619b"}
        unquote_branch={
          "instruction_forms":[{"mnemonic":"movzx","op_str":"eax, byte ptr [rcx]"},
                               {"mnemonic":"test","op_str":"al, al"}],
          "control_rva":"0x1361da","control_kind":"je",
          "control_direct_target_rva":"0x1361f2","control_next_rva":"0x1361dc"}
        orig=group.static.first_control
        try:
            group.static.first_control=lambda _pe,address: (
                quote_branch if address==group.QUOTE else unquote_branch)
            self.assertEqual(group.verify_original_next_pair(None),
                             (quote_branch,unquote_branch))
            bad={**quote_branch,"control_next_rva":"0x13619c"}
            group.static.first_control=lambda _pe,address: (
                bad if address==group.QUOTE else unquote_branch)
            with self.assertRaises(ValueError):
                group.verify_original_next_pair(None)
        finally:
            group.static.first_control=orig

    def test_original_shared_node_is_only_a_frontier_on_JL_edge(self):
        stops=frozenset((0x13619b,0x1361b9,0x1361dc,0x1361f2))
        self.assertFalse(group.pair.reaches_authenticated_frontier(
            0x1361b9,stops,[group.joined.BASE+0x136188],True))
        self.assertTrue(group.pair.reaches_authenticated_frontier(
            0x1361b9,stops,[group.joined.BASE+0x136199,
                            group.joined.BASE+0x1361b9],True))
        self.assertTrue(group.pair.reaches_authenticated_frontier(
            0x1361b9,stops,[group.joined.BASE+0x13619d,
                            group.joined.BASE+0x1361b9],True))
        self.assertFalse(group.pair.reaches_authenticated_frontier(
            0x1361b9,stops,[group.joined.BASE+0x136199,
                            group.joined.BASE+0x1361b9],True,True))
        self.assertTrue(group.pair.reaches_authenticated_frontier(
            0x1361b9,stops,[group.joined.BASE+0x1361a9,
                            group.joined.BASE+0x1361ab,group.joined.BASE+0x1361b9],True,True))
        self.assertTrue(group.pair.reaches_authenticated_frontier(
            0x1361dc,stops,[group.joined.BASE+0x1361da],True))
        self.assertFalse(group.pair.reaches_authenticated_frontier(
            0x1361d5,stops,[group.joined.BASE+0x1361cd],True))
        loop_stops=frozenset((0x136194,0x1361ad,0x1361b9,0x1361e0))
        self.assertFalse(group.pair.reaches_authenticated_frontier(
            0x136194,loop_stops,
            [group.joined.BASE+0x136192,group.joined.BASE+0x136194],
            True,True))
        self.assertTrue(group.pair.reaches_authenticated_frontier(
            0x136194,loop_stops,
            [group.joined.BASE+0x1361a9,group.joined.BASE+0x136194],
            True,True))
        self.assertFalse(group.pair.reaches_authenticated_frontier(
            0x1361e0,loop_stops,[group.joined.BASE+0x1361dc,
                                group.joined.BASE+0x1361e0],True,True))
        self.assertTrue(group.pair.reaches_authenticated_frontier(
            0x1361e0,loop_stops,[group.joined.BASE+0x1361f0,
                                group.joined.BASE+0x1361e0],True,True))
        zero_stops=frozenset((*loop_stops,0x1361f2))
        self.assertFalse(group.pair.reaches_authenticated_frontier(
            0x1361f2,zero_stops,[group.joined.BASE+0x1361e2,
                                 group.joined.BASE+0x1361f2],True,True))
        self.assertTrue(group.pair.reaches_authenticated_frontier(
            0x1361f2,zero_stops,[group.joined.BASE+0x1361f0,
                                 group.joined.BASE+0x1361f2],True,True))

    def test_integrated_linker_keeps_real_memory_writes_and_branches(self):
        source=third.extend_third_jle(second.extend_joined_source(
            joined.SOURCE,joined.BASE+0xd14cce))
        source=pair.extend_native_pair(
            source,[0]*16,["returned"]*11+["frontier"]*5,[18]*11+[37]*5)
        source=followup.extend_joined_native_followup(source)
        source=quote.extend_quote_native(source)
        source=argv.extend_native_argument_blocks(
            source,[0]*16,[0]*16,[18]*16)
        adapted=group.append_native_pair(source)
        self.assertIn("static int native_comparison_pair",adapted)
        self.assertIn("mxbikes_native_multifrontier.h",adapted)
        self.assertIn("mx_native_link_call_frontier_set",adapted)
        self.assertIn("proven_frontiers,4U",adapted)
        self.assertIn("return native_comparison_pair(s,m)",adapted)
        self.assertIn("expected_arg_slot_after[i]",adapted)
        self.assertIn(str(joined.BASE+group.QUOTE_GE),adapted)
        self.assertIn(str(joined.BASE+group.NON_NUL),adapted)
        with self.assertRaises(ValueError):
            group.append_native_pair(joined.SOURCE)

if __name__=="__main__":
    unittest.main()
