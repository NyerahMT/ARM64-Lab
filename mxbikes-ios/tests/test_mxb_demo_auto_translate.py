"""Compiled regression for the automatic AOT shard boundary and sparse dispatch."""
import importlib.util
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import mxb_demo_auto_translate as auto
import mxb_demo_block_batch as blocks


class AutoTranslateTests(unittest.TestCase):
    def test_planner_regressions(self):
        self.assertEqual(auto.regressions(), 15)

    def test_dense_page_and_sparse_holes(self):
        cc = shutil.which("clang") or shutil.which("gcc")
        if importlib.util.find_spec("ziglang") is not None:
            compiler = [sys.executable, "-m", "ziglang", "cc"]
        elif cc:
            compiler = [cc]
        else:
            self.skipTest("host C compiler unavailable")
        selected = {0x1000 + 2*i for i in range(40)} | {0x2000, 0x2002}
        ins = {pc: (b"\x90", "nop", "") for pc in selected}
        shards, dispatch = auto.generate_shards(ins, selected, 7)
        self.assertEqual(len(shards), 6)
        cases = ",".join(str(pc) for pc in sorted(selected))
        driver = blocks.PREAMBLE + """
extern int mxb_auto_step(mxb_cfg*);
int main(void) {
    const uint64_t selected[] = {""" + cases + """};
    mxb_cfg state = {0};
    if (mxb_auto_step(0) != -1) return 1;
    for (uint64_t pc = 0xfff; pc <= 0x2003; ++pc) {
        int present = 0;
        for (unsigned i = 0; i < sizeof(selected)/sizeof(selected[0]); ++i)
            if (pc == selected[i]) present = 1;
        state.rip = pc;
        int result = mxb_auto_step(&state);
        if (result != (present ? 1 : 2)) return 2;
        if (state.rip != pc + (present ? 1 : 0)) return 3;
    }
    return 0;
}
"""
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            paths = []
            for i, source in enumerate([*shards, dispatch, driver]):
                path = root / f"unit-{i}.c"
                path.write_text(source, encoding="utf-8")
                paths.append(str(path))
            exe = root / ("test.exe" if os.name == "nt" else "test")
            subprocess.run([*compiler, "-std=c11", "-O2", "-Wall", "-Wextra",
                            "-Werror", "-Wno-unused-function", *paths,
                            *([] if os.name == "nt" else ["-lm"]), "-o", str(exe)], check=True)
            subprocess.run([str(exe)], check=True)


if __name__ == "__main__":
    unittest.main()
