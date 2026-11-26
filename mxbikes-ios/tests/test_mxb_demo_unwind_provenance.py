import struct
import sys
import unittest
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'scripts'))
from mxb_demo_unwind_provenance import classify


def fixture():
    b=bytearray(1024);b[:2]=b'MZ';struct.pack_into('<I',b,0x3c,0x80)
    b[0x80:0x84]=b'PE\0\0';struct.pack_into('<HH',b,0x84,0x8664,1);struct.pack_into('<H',b,0x94,240)
    o=0x98;struct.pack_into('<H',b,o,0x20b);struct.pack_into('<II',b,o+112+24,0x1000,36)
    struct.pack_into('<IIII',b,o+240+8,512,0x1000,512,512)
    struct.pack_into('<9I',b,512,0x2000,0x2010,0x1040,0x2010,0x2020,0x1050,0x2020,0x2030,0x1070)
    b[0x240]=1;b[0x250]=33;b[0x252]=1
    struct.pack_into('<III',b,0x258,0x2000,0x2010,0x1040)
    b[0x270]=33;struct.pack_into('<III',b,0x274,0x2010,0x2020,0x1050)
    return b

class Tests(unittest.TestCase):
    def test_chain(self):
        r=classify(fixture());self.assertFalse(r[0x2000]['chained']);self.assertEqual(r[0x2010]['root_rva'],0x2000);self.assertEqual(r[0x2020]['chain_depth'],2)
    def test_cycle(self):
        b=fixture();struct.pack_into('<III',b,0x258,0x2020,0x2030,0x1070)
        with self.assertRaisesRegex(ValueError,'cycle'):classify(b)
    def test_bad_parent(self):
        b=fixture();struct.pack_into('<I',b,0x25c,0x2011)
        with self.assertRaisesRegex(ValueError,'parent'):classify(b)
    def test_invalid_flags(self):
        b=fixture();b[0x250]=41
        with self.assertRaisesRegex(ValueError,'unwind info'):classify(b)
    def test_invalid_directory(self):
        b=fixture();struct.pack_into('<I',b,0x98+112+24+4,35)
        with self.assertRaisesRegex(ValueError,'directory'):classify(b)
    def test_truncated(self):
        with self.assertRaises(ValueError):classify(fixture()[:600])
if __name__=='__main__':unittest.main()
