"""Test static x64 original quote/unquoted backedges and native integration."""
from pathlib import Path
import sys,unittest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"scripts"))
import mxbikes_main_callee_parser_loop_native as loop
import mxbikes_main_callee_three_branches_native as before
import mxbikes_main_callee_next_pair_native as prev
import mxbikes_main_callee_arg_group_native as argv
import mxbikes_main_callee_quote_jne_native as quote
import mxbikes_main_callee_followup_native as followup
import mxbikes_main_callee_third_jle_native as third
import mxbikes_main_callee_second_jge_native as second
import mxbikes_main_callee_branch_pair_native as pair
import mxbikes_main_joined_callee_native as joined
class ScannerLoopNative(unittest.TestCase):
 def test_four_exact_original_transfer_shapes_and_strict_ends(self):
    originals=[
     ([("cmp","al, 0x22")],0x1361a1,"je",0x1361ad,0x1361a3),
     ([("inc","rdx"),("cmp","byte ptr [rdx], r9b")],
      0x1361a9,"jne",0x136194,0x1361ab),
     ([],0x1361ab,"jmp",0x1361b9,0x1361ad),
     ([("cmp","al, 0x7e")],0x1361e6,"jg",0x1361f2,0x1361e8),
     ([("mov","al, byte ptr [rcx + 1]"),("inc","rcx"),("test","al, al")],
      0x1361f0,"jne",0x1361e0,0x1361f2)]
    rows=[{"instruction_forms":[{"mnemonic":mn,"op_str":op} for mn,op in forms],
           "control_rva":hex(pc),"control_kind":mnemonic,
           "control_direct_target_rva":hex(taken),"control_next_rva":hex(fall)}
          for forms,pc,mnemonic,taken,fall in originals]
    fn=loop.mapping.first_control
    try:
        loop.mapping.first_control=lambda _pe,entry:rows[
         (loop.QUOTE_CMP,loop.QUOTE_SCAN,loop.QUOTE_JUMP,
          loop.UNQUOTED_CMP,loop.UNQUOTED_SCAN).index(entry)]
        self.assertEqual(loop.verify_original_loops(None),rows)
        rows[3]["control_direct_target_rva"]="0x1361f3"
        with self.assertRaises(ValueError):loop.verify_original_loops(None)
    finally:loop.mapping.first_control=fn

 def test_integrated_call_registry_retains_all_scanner_backedges(self):
    src=third.extend_third_jle(second.extend_joined_source(
      joined.SOURCE,joined.BASE+0xd14cce))
    src=pair.extend_native_pair(src,[0]*16,["returned"]*9+["frontier"]*7,
                                [18]*9+[44]*7)
    src=followup.extend_joined_native_followup(src)
    src=quote.extend_quote_native(src)
    src=argv.extend_native_argument_blocks(src,[0]*16,[0]*16,[18]*16)
    src=prev.append_native_pair(src)
    isolated=[(b,joined.BASE+(before.JE_TAKEN if b==0 else before.JE_FALL),
               0,int(b==0),int(bool(b&128))) for b in (0,0x51,0x81)]
    src=before.append_native(src,isolated)
    done=loop.extend_native(src)
    self.assertIn("static int native_loop_edges",done)
    self.assertIn("return native_loop_edges(s,m);",done)
    self.assertIn("expected_arg_slot_after[i]",done)
    self.assertIn(str(joined.BASE+loop.UNQUOTED_BACKEDGE),done)
    self.assertIn("proven_frontiers,5U",done)
    with self.assertRaises(ValueError):loop.extend_native(joined.SOURCE)
if __name__=="__main__":unittest.main()
