#!/usr/bin/env python3
"""Run the complete existing synthetic Win64 graphics ABI C fixture on AArch64.

No original game executable, game assets, authentication, or GPU is used.
This is runtime behavior validation, not merely cross-compilation.
"""
from pathlib import Path
import subprocess
import sys
import tempfile

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT.parent))
from tools.import_aot_smoke import execute_arm64_elf

def run():
    fixtures={
        "geometry":["runtime/mxb_gl_surface.c","runtime/mxb_gl_win64_abi.c",
                    "tests/mxb_gl_win64_abi_smoke.c"],
        "textures":["runtime/mxb_gl_texture.c","runtime/mxb_gl_texture_probe.c",
                    "tests/mxb_gl_texture_batch_smoke.c"],
    }
    with tempfile.TemporaryDirectory(prefix="mxb-native-arm64-graphics-") as td:
        for name,sources in fixtures.items():
            out=Path(td)/(name+".elf")
            cmd=["clang","--target=aarch64-unknown-linux-gnu","-fuse-ld=lld",
                 "-nostdlib","-static","-ffreestanding","-fno-builtin",
                 "-fno-stack-protector","-O2","-std=c11","-Wall","-Wextra","-Werror",
                 "-DMXB_FREESTANDING_TEST","-I"+str(ROOT/"runtime"),
                 "-Wl,-e,smoke","-Wl,--build-id=none","-Wl,-z,max-page-size=4096",
                 *[str(ROOT/p) for p in sources],
                 str(ROOT/"tests/mxb_gl_freestanding_test_shim.c"),
                 "-o",str(out)]
            result=subprocess.run(cmd,capture_output=True,text=True)
            if result.returncode:
                raise RuntimeError("AArch64 "+name+" fixture link failed: "+result.stderr)
            proof=execute_arm64_elf(out,instruction_budget=6000000,timeout_us=15000000)
            print("PASS: native AArch64 "+name+" Win64 ABI fixture: "+str(proof))

if __name__=="__main__":
    run()
