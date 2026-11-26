"""Compile the actual generated dispatcher with the portable native runtime."""
import importlib.util
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/"scripts"))
import mxb_demo_auto_translate as auto

class ObservedAOTTests(unittest.TestCase):
    def test_generated_dispatch_runtime(self):
        if importlib.util.find_spec("ziglang") is not None:
            cc=[sys.executable,"-m","ziglang","cc"]
        elif shutil.which("clang") or shutil.which("gcc"):
            cc=[shutil.which("clang") or shutil.which("gcc")]
        else:self.skipTest("host C compiler unavailable")
        # Synthetic, fully specified x64 instructions only; no game bytes.
        ins={
            0x1000:(bytes.fromhex("b878563412"),"mov","eax, 0x12345678"),
            0x1005:(bytes.fromhex("8901"),"mov","dword ptr [rcx], eax"),
            0x1007:(bytes.fromhex("e8f40f0000"),"call","0x2000"),
            0x100c:(bytes.fromhex("8b11"),"mov","edx, dword ptr [rcx]"),
            0x100e:(bytes.fromhex("90"),"nop",""),
        }
        shards,dispatcher=auto.generate_shards(ins,set(ins),2)
        self.assertEqual(len(shards),3)
        with tempfile.TemporaryDirectory() as temp:
            folder=Path(temp)
            sources=[]
            for i,source in enumerate([*shards,dispatcher]):
                p=folder/f"unit-{i}.c"
                p.write_text(source,encoding="utf-8")
                sources.append(str(p))
            exe=folder/("smoke.exe" if os.name=="nt" else "smoke")
            subprocess.run([*cc,"-std=c11","-O2","-Wall","-Wextra","-Werror",
                            "-Wno-unused-function","-DMXB_USE_OBSERVED_RUNTIME_ABI",
                            "-I",str(ROOT/"runtime"),*sources,
                            str(ROOT/"runtime/mxb_observed_runtime.c"),
                            str(ROOT/"runtime/mxb_observed_memory.c"),
                            str(ROOT/"tests/mxb_observed_aot_smoke.c"),
                            *([] if os.name=="nt" else ["-lm"]),"-o",str(exe)],check=True)
            subprocess.run([str(exe)],check=True)
if __name__=="__main__":unittest.main()
