import pathlib
import shutil
import subprocess
import tempfile
import unittest

from tools.pe_probe import PE
from tools.leaf_lift import recognize, lift_to_c, candidate_patterns

class ProbeTests(unittest.TestCase):
    def test_reject_empty_and_invalid_mz(self):
        with tempfile.TemporaryDirectory() as d:
            p=pathlib.Path(d)/'x.exe'
            for data in (b'', b'MZ'+b'\0'*510):
                p.write_bytes(data)
                with self.assertRaises(ValueError):
                    PE(p)

class LiftTests(unittest.TestCase):
    def test_return_zero(self):
        self.assertEqual(recognize(bytes.fromhex('33c0c3')),0)

    def test_zero_extended_eax(self):
        self.assertEqual(recognize(bytes.fromhex('b8ffffffffc3')),0xffffffff)

    def test_unsupported_sequences_fail(self):
        for raw in ('33c0','33c0c390','48c7c001000000c3',''):
            with self.subTest(raw=raw),self.assertRaises(ValueError):
                recognize(bytes.fromhex(raw))

    def test_scanner_returns_offsets(self):
        rows=list(candidate_patterns(bytes.fromhex('90 33c0c3 90 b87b000000c3 90')))
        self.assertEqual([(i,n) for i,_,n in rows],[(1,0),(5,123)])

    def test_generated_c_runs_with_correct_result(self):
        cc=shutil.which('cc')
        if not cc:
            self.skipTest('No host C compiler')
        with tempfile.TemporaryDirectory() as d:
            d=pathlib.Path(d)
            (d/'lift.c').write_text(lift_to_c(bytes.fromhex('b8ffffffffc3')))
            (d/'test.c').write_text('extern unsigned long long lifted_leaf_return(void);\n'
               'int main(void){return lifted_leaf_return()==4294967295ULL ? 0 : 1;}\n')
            subprocess.run([cc,str(d/'lift.c'),str(d/'test.c'),'-o',str(d/'run')],check=True)
            subprocess.run([str(d/'run')],check=True)

if __name__=='__main__':
    unittest.main()
