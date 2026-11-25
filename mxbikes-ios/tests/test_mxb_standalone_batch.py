"""Source-only native startup regression and iOS cross-build, no game assets."""
import shutil, subprocess, tempfile, unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
RUNTIME=ROOT/"runtime"
FLAGS=["-std=c11","-Wall","-Wextra","-Werror","-O2","-I"+str(RUNTIME)]
LIBS=[RUNTIME/f"mxb_standalone_{n}.c" for n in ("crt","platform","heap","memory","imports")]
FIXTURES=[ROOT/"tests"/f"mxb_standalone_{n}_smoke.c" for n in ("imports","heap","memory")]
class BatchTests(unittest.TestCase):
    def test_host(self):
        if not shutil.which("cc"):self.skipTest("C compiler unavailable")
        with tempfile.TemporaryDirectory() as d:
            for src in FIXTURES:
                out=Path(d)/src.stem
                subprocess.run(["cc",*FLAGS,"-DHOST",*map(str,LIBS),str(src),"-o",str(out)],check=True)
                subprocess.run([str(out)],check=True)
    def test_ios_arm64_compile(self):
        if not shutil.which("clang"):self.skipTest("Clang unavailable")
        with tempfile.TemporaryDirectory() as d:
            for src in LIBS+FIXTURES:
                out=Path(d)/(src.stem+".o")
                subprocess.run(["clang","--target=arm64-apple-ios15.0","-ffreestanding",
                                "-fno-builtin",*FLAGS,"-c",str(src),"-o",str(out)],check=True)
                self.assertEqual(out.read_bytes()[:8],b"\xcf\xfa\xed\xfe\x0c\x00\x00\x01")
if __name__=="__main__":unittest.main()
