import hashlib
import io
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
from mxb_demo_pkz_audit import audit, index, verify, key

class Tests(unittest.TestCase):
    def archive(self, rows):
        b = io.BytesIO()
        with zipfile.ZipFile(b, 'w') as z:
            for name, data, comp in rows:
                z.writestr(name, data, compress_type=comp)
        return zipfile.ZipFile(b)
    def test_stored_deflated(self):
        with self.archive([('UI/A.bin', b'a'*100, 0), ('UI/B.bin', b'b'*70000, 8)]) as z:
            entries = index(z)
            self.assertEqual(set(entries), {'ui/a.bin','ui/b.bin'})
            for k, b in [('ui/a.bin',b'a'*100),('ui/b.bin',b'b'*70000)]:
                self.assertEqual(verify(z, entries[k])['sha256'], hashlib.sha256(b).hexdigest())
    def test_duplicate(self):
        with self.archive([('UI/A', b'a', 0), ('ui\\a', b'b', 8)]) as z:
            with self.assertRaises(ValueError): index(z)
    def test_unsafe(self):
        for name in ('../a','/a','C:/a','a//b','a./b','a /b','a\x00b'):
            with self.subTest(name=name), self.assertRaises(ValueError): key(name)
    def test_budget(self):
        with self.archive([('a',b'1234',8)]) as z:
            with self.assertRaises(ValueError): verify(z, index(z)['a'],3)
    def test_crc(self):
        b=io.BytesIO()
        with zipfile.ZipFile(b,'w') as z: z.writestr('a',b'abcdef')
        raw=bytearray(b.getvalue()); offset=30+1; raw[offset]^=1
        with zipfile.ZipFile(io.BytesIO(raw)) as z:
            with self.assertRaises(zipfile.BadZipFile): verify(z,index(z)['a'])
    def test_audit_sampling(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/'fixture.pkz'
            with zipfile.ZipFile(p,'w') as z:
                for n,b,c in [('ui/a',b'a'*100,0),('ui/b',b'b'*70000,8),
                              ('ui/c',b'c'*5,8),('ui/d',b'd'*80000,8)]:
                    z.writestr(n,b,compress_type=c)
            r=audit(p,max_samples=3)
            self.assertEqual((r['members'],r['sampled_members'],r['sampled_bytes']),(4,3,70105))
            self.assertFalse(r['original_engine_reads_verified'])
            self.assertEqual([s['sha256'] for s in r['samples']],
                [hashlib.sha256(b).hexdigest() for b in (b'a'*100,b'c'*5,b'b'*70000)])
if __name__=='__main__':unittest.main()
