import unittest,sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"scripts"))
import mxbikes_main_callee_tail_native as tail
import mxbikes_main_callee_parser_loop_native as loop
import mxbikes_main_callee_three_branches_native as triple
import mxbikes_main_callee_next_pair_native as previous
import mxbikes_main_callee_arg_group_native as argv
import mxbikes_main_callee_quote_jne_native as quote
import mxbikes_main_callee_followup_native as followup
import mxbikes_main_callee_third_jle_native as third
import mxbikes_main_callee_second_jge_native as second
import mxbikes_main_callee_branch_pair_native as pair
import mxbikes_main_joined_callee_native as joined
class TailTests(unittest.TestCase):
 def test_exact_original_jne_and_ret_shapes(self):
    cases={
      tail.CHECK:([("cmp","byte ptr [rcx], 0")],"0x1361f5","je","0x1361fd","0x1361f7"),
      tail.WRITE:([("mov","byte ptr [rcx], 0"),("inc","rcx"),
        ("mov","al, byte ptr [rcx]"),("test","al, al")],
        "0x136201","jne","0x136152","0x136207"),
      tail.RELOAD:([("mov","al, byte ptr [rcx]"),("test","al, al")],
        "0x136201","jne","0x136152","0x136207"),
      tail.JNE:([],"0x136201","jne","0x136152","0x136207"),
      tail.RETURN:([("xor","eax, eax")],"0x136209","ret",None,"0x13620a"),
      tail.LOOP:([("cmp","r10d, 0x80")],"0x136159","jge","0x136207","0x13615f")}
    old=tail.mapping.first_control
    try:
      tail.mapping.first_control=lambda _pe,pc:{
        "instruction_forms":[{"mnemonic":m,"op_str":v} for m,v in cases[pc][0]],
        "control_rva":cases[pc][1],"control_kind":cases[pc][2],
        "control_direct_target_rva":cases[pc][3],"control_next_rva":cases[pc][4]}
      self.assertIsNone(tail.verify(None))
      cases[tail.JNE]=([],"0x136201","jne","0x136151","0x136207")
      with self.assertRaises(ValueError):tail.verify(None)
    finally:tail.mapping.first_control=old
 def test_full_linkage_preserves_argv_memory_and_isolated_original_je(self):
    src=third.extend_third_jle(second.extend_joined_source(
        joined.SOURCE,joined.BASE+0xd14cce))
    src=pair.extend_native_pair(src,[0]*16,["returned"]*9+
        ["frontier"]*7,[18]*9+[42]*7)
    src=followup.extend_joined_native_followup(src)
    src=quote.extend_quote_native(src)
    src=argv.extend_native_argument_blocks(src,[0]*16,[0]*16,[18]*16)
    src=previous.append_native_pair(src)
    original=[(v,joined.BASE+(triple.JE_TAKEN if v==0 else triple.JE_FALL),
        0,int(v==0),int(bool(v&128))) for v in (0,0x51,0x81)]
    src=triple.append_native(src,original)
    src=loop.extend_native(src)
    extended=tail.extend(src,[0]*16,[0]*16)
    self.assertIn("native_parser_tail(",extended)
    self.assertIn("first_after[CASES]",extended)
    self.assertIn("return mx_game_main_callee_finish_empty(s,m,&callee_layout)",extended)
    with self.assertRaises(ValueError):tail.extend(joined.SOURCE,[0]*16,[0]*16)
if __name__=="__main__":unittest.main()
