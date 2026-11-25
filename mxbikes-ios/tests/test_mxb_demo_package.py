import hashlib
from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import stat
import tempfile
import unittest
import zipfile
from mxb_demo_package import inspect_directory, stage_zip, select_members

class PackageTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name); self.zip = self.root / 'input.zip'
        self.dest = self.root / 'out'
        self.manifest = {'mxbikes.exe': (3, hashlib.sha256(b'exe').hexdigest()),
                         'core.ini': (3, hashlib.sha256(b'ini').hexdigest()),
                         'ui.pkz': (4, None)}
    def make(self, entries=None):
        if entries is None:
            entries = [('demo/mxbikes.exe', b'exe'), ('demo/core.ini', b'ini'),
                       ('demo/ui.pkz', b'data'), ('demo/extra.dll', b'x')]
        with zipfile.ZipFile(self.zip, 'w', compression=zipfile.ZIP_DEFLATED) as z:
            for name, data in entries: z.writestr(name, data)
    def stage(self): return stage_zip(self.zip, self.dest, self.manifest)
    def reject(self, entries):
        self.make(entries)
        with self.assertRaises(ValueError): self.stage()
        self.assertFalse(self.dest.exists())
        self.assertFalse(list(self.root.glob('.mxb-stage-*')))
    def test_valid(self):
        self.make(); self.assertTrue(self.stage()['ready'])
        self.assertEqual(set(p.name for p in self.dest.iterdir()), set(self.manifest))
        self.assertEqual((self.dest/'ui.pkz').read_bytes(), b'data')
    def test_missing(self): self.reject([('mxbikes.exe', b'exe')])
    def test_size(self): self.reject([('mxbikes.exe', b'exe'), ('core.ini', b'i'), ('ui.pkz', b'data')])
    def test_sha(self): self.reject([('mxbikes.exe', b'exe'), ('core.ini', b'bad'), ('ui.pkz', b'data')])
    def test_duplicate(self): self.reject([('mxbikes.exe', b'exe'), ('core.ini', b'ini'), ('CORE.INI', b'ini'), ('ui.pkz', b'data')])
    def test_mixed(self): self.reject([('a/mxbikes.exe', b'exe'), ('b/core.ini', b'ini'), ('a/ui.pkz', b'data')])
    def test_traversal(self): self.reject([('../mxbikes.exe', b'exe'), ('core.ini', b'ini'), ('ui.pkz', b'data')])
    def test_absolute(self): self.reject([('/mxbikes.exe', b'exe'), ('core.ini', b'ini'), ('ui.pkz', b'data')])
    def test_symlink_member(self):
        link = zipfile.ZipInfo('core.ini'); link.create_system=3; link.external_attr=(stat.S_IFLNK|0o777)<<16
        self.reject([('mxbikes.exe', b'exe'), (link, b'ini'), ('ui.pkz', b'data')])
    def test_existing(self):
        self.make(); self.dest.mkdir(); (self.dest/'keep').write_text('keep')
        with self.assertRaises(FileExistsError): self.stage()
        self.assertEqual((self.dest/'keep').read_text(), 'keep')
    def test_direct_missing(self):
        self.assertFalse(inspect_directory(self.root, self.manifest)['ready'])
    def test_directory_hash(self):
        self.make(); self.stage(); (self.dest/'core.ini').write_bytes(b'bad')
        self.assertFalse(inspect_directory(self.dest, self.manifest)['ready'])
    def test_directory_link(self):
        self.make(); self.stage(); (self.dest/'core.ini').unlink(); (self.dest/'core.ini').symlink_to(self.dest/'mxbikes.exe')
        self.assertFalse(inspect_directory(self.dest, self.manifest)['ready'])
    def test_hash_all(self):
        self.make(); self.stage(); r=inspect_directory(self.dest, self.manifest, hash_all=True)
        self.assertTrue(r['ready']); self.assertEqual(r['files'][2]['sha256'],hashlib.sha256(b'data').hexdigest())

if __name__ == '__main__': unittest.main()
