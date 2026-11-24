"""Public synthetic regression for local-code discovery."""
import unittest
from mxbikes_native_cfg_lift import decode_cfg, synthetic_input
from mxbikes_native_local_discovery import discover

def reader(windows):
    def read(pc,n):
        matches=[(a,raw) for a,raw in windows if a<=pc<a+len(raw)]
        if len(matches)!=1:raise ValueError("Unmapped code")
        a,raw=matches[0]
        return raw[pc-a:pc-a+n]
    return read

class DiscoveryTests(unittest.TestCase):
    def test_local_call_branch_and_return(self):
        windows,entry,stop=synthetic_input()
        out=discover(reader(windows),entry,stop)
        self.assertEqual(out,windows)
        self.assertEqual(decode_cfg(out,entry,stop),decode_cfg(windows,entry,stop))
    def test_unmapped_and_indirect_targets(self):
        for raw in (bytes.fromhex("eb7f"),bytes.fromhex("ffd0"),bytes.fromhex("ffe0")):
            with self.subTest(raw=raw):
                with self.assertRaises(ValueError):
                    discover(reader([(0x1000,raw)]),0x1000,0x1002)
    def test_bound(self):
        with self.assertRaisesRegex(ValueError,"budget"):
            discover(reader([(0x1000,b"\x90\x90")]),0x1000,0x1002,max_nodes=1)
    def test_call_frontier_does_not_decode_after_stop(self):
        raw=bytes.fromhex("e8fb000000 0f0b")
        out=discover(reader([(0x1000,raw)]),0x1000,0x1100)
        self.assertEqual(out,[(0x1000,raw[:5])])
        self.assertEqual(decode_cfg(out,0x1000,0x1100)[2],{0x1000})

if __name__=="__main__":unittest.main()
