"""Native POSIX file adapter regression without proprietary assets."""
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
ROOT=Path(__file__).resolve().parents[1]
class AssetSessionTests(unittest.TestCase):
    def test_native(self):
        if not shutil.which("cc"):self.skipTest("C compiler unavailable")
        with tempfile.TemporaryDirectory() as d:
            exe=Path(d)/"session"
            subprocess.run(["cc","-std=c11","-Wall","-Wextra","-Werror","-O2",
                "-I"+str(ROOT/"runtime"),str(ROOT/"runtime/mxb_standalone_files.c"),
                str(ROOT/"runtime/mxb_standalone_asset_session.c"),
                str(ROOT/"tests/mxb_standalone_asset_session_smoke.c"),"-o",str(exe)],check=True)
            subprocess.run([str(exe)],check=True)
if __name__=="__main__":unittest.main()
