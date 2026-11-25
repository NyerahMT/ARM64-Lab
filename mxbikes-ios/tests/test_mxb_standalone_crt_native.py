"""Build and run native standalone CRT component tests without original game assets."""
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

ROOT=Path(__file__).resolve().parents[1]
RUNTIME=ROOT/"runtime"
SOURCES=[RUNTIME/"mxb_standalone_crt.c",ROOT/"tests"/"mxb_standalone_crt_smoke.c"]
FLAGS=["-std=c11","-Wall","-Wextra","-Werror","-O2","-I"+str(RUNTIME)]

class StandaloneNativeCRT(unittest.TestCase):
    def test_host_smoke(self):
        if not shutil.which("cc"):self.skipTest("C compiler unavailable")
        with tempfile.TemporaryDirectory() as td:
            out=Path(td)/"smoke"
            subprocess.run(["cc",*FLAGS,"-DHOST",*map(str,SOURCES),"-o",str(out)],check=True)
            subprocess.run([str(out)],check=True)

    def test_ios_arm64_compile(self):
        if not shutil.which("clang"):self.skipTest("Clang unavailable")
        with tempfile.TemporaryDirectory() as td:
            for src in SOURCES:
                out=Path(td)/(src.stem+".o")
                subprocess.run(["clang","--target=arm64-apple-ios15.0",
                    "-ffreestanding","-fno-builtin",*FLAGS,"-c",str(src),"-o",str(out)],check=True)
                self.assertEqual(out.read_bytes()[:4],b"\xcf\xfa\xed\xfe")

if __name__=="__main__":unittest.main()
