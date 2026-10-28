"""Synthetic full-chain x64 vs host vs AArch64 for expanded closed leaf forms."""
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import mxbikes_verified_leaf_autolink as leaf
from mxbikes_wave_native_selection import SHA

BODIES = {
    0x200000: bytes.fromhex("31c0c3"),
    0x200020: bytes.fromhex("33c0c3"),
    0x200040: bytes.fromhex("8bc1c3"),
    0x200060: bytes.fromhex("89d0c3"),
    0x200080: bytes.fromhex("4889c8c3"),
    0x2000a0: bytes.fromhex("418bc0c3"),
    0x2000c0: bytes.fromhex("418bc1c3"),
    0x2000e0: bytes.fromhex("498bc0c3"),
    0x200100: bytes.fromhex("498bc1c3"),
    0x200120: bytes.fromhex("488bc2c3"),
    0x200140: bytes.fromhex("488d41f8c3"),
    0x200160: bytes.fromhex("488d4208c3"),
    0x200180: bytes.fromhex("488d81f8ffffffc3"),
    0x2001a0: bytes.fromhex("8d41f8c3"),
    0x2001c0: bytes.fromhex("8d4208c3"),
    0x2001e0: bytes.fromhex("8d8278563412c3"),
}
KINDS = ["xor_eax_eax_ret", "xor_eax_eax_ret", "mov_eax_ecx_ret",
         "mov_eax_edx_ret", "mov_rax_rcx_ret",
         "mov_eax_r8d_ret", "mov_eax_r9d_ret", "mov_rax_r8_ret",
         "mov_rax_r9_ret", "mov_rax_rdx_ret",
         "lea_rax_rcx_disp_ret", "lea_rax_rdx_disp_ret",
         "lea_rax_rcx_disp_ret", "lea_eax_rcx_disp_ret",
         "lea_eax_rdx_disp_ret", "lea_eax_rdx_disp_ret"]


class SyntheticPE:
    b = b"original-leaf-forms-synthetic-only"

    def read_rva(self, address, width):
        body = BODIES.get(address)
        if body is None or width > len(body):
            raise ValueError("Unrecognized synthetic code RVA")
        return body[:width]


class FastLeafFormsTests(unittest.TestCase):
    def test_decode_known_closed_forms_and_reject_memory_access(self):
        for i, (rva, body) in enumerate(sorted(BODIES.items())):
            self.assertEqual(leaf.classify(body)[0], KINDS[i])
        for body in (bytes.fromhex("8b01c3"),
                     bytes.fromhex("31c1c3"),
                     bytes.fromhex("4831c1c3")):
            self.assertIsNone(leaf.classify(body))

    def test_original_x64_host_native_and_aarch64_differential(self):
        mapping = {
            "original_file_verified": True, "input_sha256": SHA,
            "direct_call_graph": {
                "0x136710": [hex(rva) for rva in BODIES],
            },
            "interval_map": [],
        }
        digest = type("Digest", (), {"hexdigest": lambda self: SHA})()
        with patch.object(leaf, "PE", return_value=SyntheticPE()), patch.object(
                leaf.hashlib, "sha256", return_value=digest):
            _, candidates, kinds, count = leaf.discover(
                "synthetic-closed-original", mapping)
        self.assertEqual(count, 16)
        self.assertEqual([x["kind"] for x in candidates], KINDS)
        self.assertEqual(len(candidates), 16)
        refs = {
            item["rva"]: [leaf.x64_reference(item, j)
                          for j in range(leaf.FIXTURES)] for item in candidates
        }
        source = leaf.generate_source(candidates, refs)
        with tempfile.TemporaryDirectory(prefix="mxb-fastforms-") as td:
            root = Path(td)
            code = root / "synthetic.c"
            code.write_text(source)
            flags = ["-O2", "-std=c11", "-Wall", "-Wextra", "-Werror",
                     "-I", str(leaf.ROOT / "arm64-lab" / "runtime")]
            host = root / "host"
            proc = subprocess.run(["cc", *flags, "-DHOST", str(code),
                                   "-o", str(host)], capture_output=True, text=True)
            self.assertEqual(proc.returncode, 0, proc.stderr[-3000:])
            proc = subprocess.run([str(host)], capture_output=True, text=True)
            self.assertEqual(proc.returncode, 0, proc.stderr[-3000:])
            arm = root / "aarch64.elf"
            proc = subprocess.run([
                "clang", "--target=aarch64-unknown-linux-gnu",
                "-fuse-ld=lld", "-nostdlib", "-static", "-ffreestanding",
                "-fno-stack-protector", "-fno-builtin", *flags,
                "-Wl,-e,smoke", "-Wl,-z,max-page-size=4096",
                "-Wl,--build-id=none", str(code), "-o", str(arm)
            ], capture_output=True, text=True)
            self.assertEqual(proc.returncode, 0, proc.stderr[-3000:])
            result = leaf.execute_arm64_elf(
                arm, instruction_budget=650000, timeout_us=10000000)
            self.assertEqual(result["arm64_smoke_exit"], 0)


if __name__ == "__main__":
    unittest.main()
