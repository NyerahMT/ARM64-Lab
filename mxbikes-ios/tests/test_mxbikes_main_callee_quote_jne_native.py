"""Proven original command quote-JNE semantics and native link regression."""
from pathlib import Path
import sys,unittest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"scripts"))
import mxbikes_main_callee_quote_jne_native as quote
import mxbikes_main_callee_followup_native as followup
import mxbikes_main_callee_branch_pair_native as pair
import mxbikes_main_callee_third_jle_native as third
import mxbikes_main_callee_second_jge_native as second
import mxbikes_main_joined_callee_native as joined

class OriginalQuoteJNE(unittest.TestCase):
    def test_original_jne_opcode_and_next_address_fail_closed(self):
        good={"control_rva":"0x136188","control_kind":"jne",
          "control_direct_target_rva":"0x1361b9",
          "control_next_rva":"0x13618a","instruction_forms":[
             {"mnemonic":"xor","op_str":"r9d, r9d"},
             {"mnemonic":"cmp","op_str":"al, 0x22"}]}
        class Fake:
            def __init__(self,record):self.record=record
        original=quote.mapping.first_control
        try:
            quote.mapping.first_control=lambda _pe,_entry:good
            self.assertEqual(quote.original_branch(Fake(good)),good)
            for k,v in (("control_next_rva","0x13618c"),
                        ("control_direct_target_rva","0x1361b8"),
                        ("control_kind","je")):
                bad={**good,k:v}
                quote.mapping.first_control=lambda _pe,_entry,bad=bad:bad
                with self.assertRaises(ValueError):
                    quote.original_branch(Fake(bad))
        finally:
            quote.mapping.first_control=original

    def test_real_linker_exact_native_quote_target_and_restored_callee_returns(self):
        base=third.extend_third_jle(second.extend_joined_source(
            joined.SOURCE,joined.BASE+0xd14cce))
        src=pair.extend_native_pair(base,[0]*16,
              ["returned"]*11+["frontier"]*5,[18]*11+[31]*5)
        src=followup.extend_joined_native_followup(src)
        adapted=quote.extend_quote_native(src)
        self.assertIn("static int native_quote_branch",adapted)
        self.assertIn("s->r9=0U",adapted)
        self.assertIn("return native_quote_branch(s,m);",adapted)
        self.assertIn(str(joined.BASE+quote.NOT_QUOTE),adapted)
        self.assertIn(str(joined.BASE+quote.FALLTHROUGH),adapted)
        with self.assertRaises(ValueError):
            quote.extend_quote_native(joined.SOURCE)

if __name__=="__main__":
    unittest.main()
