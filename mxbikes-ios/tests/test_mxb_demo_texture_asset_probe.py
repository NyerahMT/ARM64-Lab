import importlib.util
import os
from pathlib import Path
import shutil
import struct
import subprocess
import sys
import tempfile
import unittest
import zipfile
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'scripts'))
from mxb_demo_texture_asset_probe import decode_tga,upload,probe

def tga(w,h,kind,bits,desc,payload):
    return struct.pack('<BBBHHBHHHHBB',0,0,kind,0,0,0,0,0,w,h,bits,desc)+payload

RED=b'\x00\x00\xff';GREEN=b'\x00\xff\x00';BLUE=b'\xff\x00\x00';WHITE=b'\xff\xff\xff'
R=b'\xff\x00\x00\xff';G=b'\x00\xff\x00\xff';B=b'\x00\x00\xff\xff';W=b'\xff\xff\xff\xff'

class Tests(unittest.TestCase):
    def test_raw_origins(self):
        self.assertEqual(decode_tga(tga(2,2,2,24,0,RED+GREEN+BLUE+WHITE)),(2,2,R+G+B+W))
        self.assertEqual(decode_tga(tga(2,2,2,24,0x20,BLUE+WHITE+RED+GREEN)),(2,2,R+G+B+W))
        self.assertEqual(decode_tga(tga(2,2,2,24,0x30,WHITE+BLUE+GREEN+RED)),(2,2,R+G+B+W))
    def test_rle_and_alpha(self):
        self.assertEqual(decode_tga(tga(3,1,10,24,0,b'\x81'+RED+b'\x00'+BLUE)),(3,1,R+R+B))
        self.assertEqual(decode_tga(tga(1,1,2,32,8,RED+b'\x80')),(1,1,R[:3]+b'\x80'))
        self.assertEqual(decode_tga(tga(1,1,2,32,0,RED+b'\x00')),(1,1,R))
    def test_malformed(self):
        for data in (tga(1,1,10,24,0,b'\x81'+RED),tga(2,1,2,24,0,RED),
                     tga(0,1,2,24,0,b''),tga(1,1,2,24,0xc0,RED)):
            with self.assertRaises(ValueError):decode_tga(data)
    def test_real_native_adapter(self):
        if importlib.util.find_spec('ziglang') is not None:
            cc=[sys.executable,'-m','ziglang','cc']
        elif shutil.which('clang'):
            cc=['clang']
        elif shutil.which('gcc'):
            cc=['gcc']
        else:self.skipTest('native compiler unavailable')
        root=Path(__file__).resolve().parents[1]/'runtime'
        with tempfile.TemporaryDirectory() as d:
            lib=Path(d)/('texture.dll' if os.name=='nt' else 'texture.so')
            flags=['-shared','-O2']
            if os.name!='nt':flags+=['-fPIC']
            else:flags+=['-Wl,--export-all-symbols']
            subprocess.run(cc+flags+['-o',str(lib),str(root/'mxb_gl_texture.c')],check=True)
            w,h,p=decode_tga(tga(2,2,2,24,0,RED+GREEN+BLUE+WHITE))
            result=upload(lib,w,h,p)
            self.assertEqual(result['rgba_bytes'],16)
            self.assertTrue(result['native_texture_upload_verified'])
            with zipfile.ZipFile(Path(d)/'fixture.pkz','w') as z:
                z.writestr('ui/test.tga',tga(2,2,2,24,0,RED+GREEN+BLUE+WHITE))
            actual=probe(Path(d)/'fixture.pkz',lib)
            self.assertEqual(actual['uploads'],[result])
            self.assertFalse(actual['original_engine_calls_verified'])
if __name__=='__main__':unittest.main()
