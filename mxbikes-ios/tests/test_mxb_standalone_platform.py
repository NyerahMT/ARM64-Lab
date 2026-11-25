"""Build the standalone virtual directory and guest clock component."""
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
SOURCES=[ROOT/"runtime/mxb_standalone_platform.c",ROOT/"tests/mxb_standalone_platform_smoke.c"]
FLAGS=["-std=c11","-Wall","-Wextra","-Werror","-O2","-I"+str(ROOT/"runtime")]
class PlatformTests(unittest.TestCase):
    def test_host(self):
        if not shutil.which("cc"):self.skipTest("C compiler unavailable")
        with tempfile.TemporaryDirectory() as d:
            out=Path(d)/"smoke"
            subprocess.run(["cc",*FLAGS,"-DHOST",*map(str,SOURCES),"-o",str(out)],check=True)
            subprocess.run([str(out)],check=True)
    def test_ios_arm64_compile(self):
        if not shutil.which("clang"):self.skipTest("Clang unavailable")
        with tempfile.TemporaryDirectory() as d:
            for src in SOURCES:
                out=Path(d)/(src.stem+".o")
                subprocess.run(["clang","--target=arm64-apple-ios15.0","-ffreestanding",
                                "-fno-builtin",*FLAGS,"-c",str(src),"-o",str(out)],check=True)
                self.assertEqual(out.read_bytes()[:8],b"\xcf\xfa\xed\xfe\x0c\x00\x00\x01")
if __name__=="__main__":unittest.main()
