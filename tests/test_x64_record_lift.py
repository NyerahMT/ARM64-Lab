"""Validate fail-closed record-writer shape recognition on synthetic data."""
import unittest
from tools.x64_record_lift import lift_indexed_record_writer,UnsupportedRecordWriter

class RecordWriterTests(unittest.TestCase):
    def test_reject_wrong_shape(self):
        for code in (b"\x90"*76,b"\xc3",b""):
            with self.assertRaises(UnsupportedRecordWriter):
                lift_indexed_record_writer(code,0x1000)
    def test_reject_unsafe_count(self):
        with self.assertRaises(UnsupportedRecordWriter):
            lift_indexed_record_writer(b"\xc3",0x1000,max_records=0)

if __name__=="__main__":unittest.main()
