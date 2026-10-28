"""Synthetic genuine x64→host→AArch64 execution of a two-exit leaf CFG.

Uses synthetic instructions; the owned game executable stays private.
CI must run this before private original-code translation.
"""
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import mxbikes_verified_leaf_autolink as leaf
from mxbikes_wave_native_selection import SHA

BYTES = bytes.fromhex("85c9 7406 b801000000 c3 b802000000 c3")
RVA = 0x200000


class SyntheticPE:
    b = b"bounded-original-fixture"

    def read_rva(self, address, width):
        if address != RVA or width > len(BYTES):
            raise ValueError("Synthetic original PE read outside authorized body")
        return BYTES[:width]


def sample_map():
    return {
        "input_sha256": SHA,
        "original_file_verified": True,
        "direct_call_graph": {
            "0x136710": [hex(RVA)],
            "0x2ab02c": [hex(RVA)],
        },
        "interval_map": [{
            "rva": hex(RVA), "status": "decoded_linear", "bytes": len(BYTES),
        }],
    }


def sample_waves():
    return {"schema": 1, "original_sha256": SHA, "code_batches": [
        {"batch_id": "wave-001", "original_entries": [hex(RVA)],
         "native_dispatch_ready": False},
    ]}


class MultiBlockDifferentialTests(unittest.TestCase):
    def test_original_reference_and_host_and_aarch64_all_match(self):
        digest = type("Digest", (), {"hexdigest": lambda self: SHA})()
        with patch.object(leaf, "PE", return_value=SyntheticPE()), patch.object(
                leaf.hashlib, "sha256", return_value=digest):
            _, candidates, kinds, _ = leaf.discover(
                "synthetic-input", sample_map(), sample_waves())
        self.assertEqual(len(candidates), 1)
        candidate = candidates[0]
        self.assertEqual(candidate["kind"], "bounded_forward_cfg")
        self.assertEqual(kinds["bounded_forward_cfg"], 1)
        self.assertEqual(candidate["wave_batch_id"], "wave-001")
        refs = [leaf.x64_reference(candidate, i) for i in range(leaf.FIXTURES)]
        traces = candidate["_original_traces"]
        self.assertEqual(len(traces), leaf.FIXTURES)
        self.assertEqual(set().union(*map(set, traces)),
                         {op["rva"] for op in candidate["cfg_plan"]["ops"]})
        branch = RVA + 2
        taken = {b for trace in traces for a, b in zip(trace, trace[1:])
                 if a == branch}
        self.assertEqual(taken, {RVA+4, RVA+10})
        source = leaf.generate_source(candidates, {RVA: refs})
        with tempfile.TemporaryDirectory(prefix="mxb-acyclic-fixture-") as td:
            root = Path(td)
            code = root / "generated-synthetic.c"
            code.write_text(source)
            flags = ["-O2", "-std=c11", "-Wall", "-Wextra", "-Werror",
                     "-I", str(leaf.ROOT / "arm64-lab" / "runtime")]
            host = root / "host"
            proc = subprocess.run(["cc", *flags, "-DHOST", str(code),
                                   "-o", str(host)], capture_output=True, text=True)
            self.assertEqual(proc.returncode, 0, proc.stderr[-3000:])
            proc = subprocess.run([str(host)], capture_output=True, text=True)
            self.assertEqual(proc.returncode, 0, proc.stderr[-3000:])
            arm = root / "synthetic-arm64.elf"
            proc = subprocess.run([
                "clang", "--target=aarch64-unknown-linux-gnu",
                "-fuse-ld=lld", "-nostdlib", "-static", "-ffreestanding",
                "-fno-stack-protector", "-fno-builtin", *flags,
                "-Wl,-e,smoke", "-Wl,-z,max-page-size=4096",
                "-Wl,--build-id=none", str(code), "-o", str(arm)
            ], capture_output=True, text=True)
            self.assertEqual(proc.returncode, 0, proc.stderr[-3000:])
            result = leaf.execute_arm64_elf(
                arm, instruction_budget=500000, timeout_us=10000000)
            self.assertEqual(result["arm64_smoke_exit"], 0)


if __name__ == "__main__":
    unittest.main()
