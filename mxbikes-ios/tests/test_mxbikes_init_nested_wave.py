"""Synthetic boundary regression for private original initializer dependency wave."""
import struct,sys,unittest
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"scripts"))
import mxbikes_init_nested_wave as probe

class SyntheticPe:
    def __init__(self,origin,payload):
        self.origin=origin
        self.payload=payload
    def read_rva(self,rva,size):
        off=rva-self.origin
        if not 0<=off<len(self.payload):
            raise ValueError("out of synthetic mapping")
        return self.payload[off:off+size]+bytes(max(0,size-(len(self.payload)-off)))
    def directory(self,_):
        return (0,0)

class NestedCallWaveTests(unittest.TestCase):
    def test_original_direct_call_and_strict_continuation(self):
        start=probe.NESTED
        target=0x155100
        call=b"\xe8"+struct.pack("<i",target-(start+5))
        fake=SyntheticPe(start,call+b"\x90"*10)
        info=probe.decode_call(fake,start,following=start+5)
        self.assertEqual(info["callee_rva"],hex(target))
        self.assertEqual(info["kind"],"direct_original_game_call")
        with self.assertRaises(ValueError):
            probe.decode_call(fake,start,following=start+6)
        with self.assertRaises(ValueError):
            probe.decode_call(SyntheticPe(start,b"\x90"*10),start)
    def test_bounded_child_block_and_unwindless_not_a_verified_entry(self):
        start=0x155100
        # push rsi, xor eax/eax, ret (trailing padding never promoted)
        fake=SyntheticPe(start,b"\x56\x31\xc0\xc3"+b"\x90"*350)
        row=probe.scan_first_block(fake,start)
        self.assertEqual(row["precontrol_instruction_count"],2)
        self.assertEqual(row["control_kind"],"ret")
        self.assertNotIn("direct_destination_rva",row)
        self.assertIs(row["native_arm64_executed"],False)
        wave,budget=probe.bounded_wave(fake,start)
        self.assertEqual(len(wave),1)
        self.assertTrue(budget["all_static_targets_exhausted"])
        self.assertEqual(wave[0]["unwind"]["status"],"no_valid_unwind_table")
    def test_unsupported_and_indirect_are_not_fake_translated(self):
        start=probe.NESTED
        fake=SyntheticPe(start,b"\xff\x15\x00\x00\x00\x00"+b"\x90"*10)
        row=probe.decode_call(fake,start)
        self.assertEqual(row["kind"],"unresolved_indirect_call")
        self.assertIsNone(row["callee_rva"])
        with self.assertRaises(ValueError):
            probe.scan_first_block(fake,0)
        with self.assertRaises(ValueError):
            probe.scan_first_block(fake,start,cap=100)

if __name__=="__main__":
    unittest.main()
