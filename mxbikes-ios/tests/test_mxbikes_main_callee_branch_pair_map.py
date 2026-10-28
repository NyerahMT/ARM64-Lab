"""Synthetic static original branching and conservative source provenance."""
from pathlib import Path
import sys
import unittest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"scripts"))
import mxbikes_main_callee_branch_pair_map as pair
import mxbikes_main_callee_third_jle_native as third

class PairMapTests(unittest.TestCase):
    def test_two_distinct_original_successor_discoveries(self):
        class PE:
            def read_rva(self,rva,size):
                if size!=192:raise ValueError
                # Both synthetic blocks terminate at exact direct x64 Jcc.
                return (bytes.fromhex("90 31c0 7502")+
                        b"\x90"*(size-5)) if rva==third.FALLTHROUGH else (
                        bytes.fromhex("83f801 7402")+b"\x90"*(size-5))
        a=pair.first_control(PE(),third.FALLTHROUGH)
        b=pair.first_control(PE(),third.TAKEN)
        self.assertEqual(a["control_kind"],"jne")
        self.assertEqual(b["control_kind"],"je")
        self.assertEqual(a["straightline_instructions"],2)
        self.assertEqual(b["straightline_instructions"],1)
        self.assertFalse(a["native_arm64_successor_executed"])
        a2=pair.first_control(PE(),pair.FOLLOWUP_ROOTS[0])
        b2=pair.first_control(PE(),pair.FOLLOWUP_ROOTS[1])
        self.assertEqual(a2["control_kind"],"je")
        self.assertEqual(b2["control_kind"],"je")
        c2=pair.first_control(PE(),0x136183)
        self.assertEqual(c2["entry_rva"],"0x136183")
        for address in (0x13618a,0x1361b9,0x136194,0x1361d5,0x13619b,0x1361dc,0x1361f2,0x13619f,0x1361e4,0x1361f7,0x1361fd,0x1361a3,0x1361ab,0x1361ad,0x1361e8,0x136201,0x136207,0x136152,0x1361cf,0x1361d0,0x1361e0):
            block=pair.first_control(PE(),address)
            self.assertEqual(block["entry_rva"],hex(address))
            self.assertFalse(block["native_arm64_successor_executed"])
        with self.assertRaises(ValueError):
            pair.first_control(PE(),third.JLE)

if __name__=="__main__":
    unittest.main()
