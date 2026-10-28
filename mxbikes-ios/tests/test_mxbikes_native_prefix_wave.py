"""Native x64-host-ARM64 differential for bounded original-style caller prefixes.

Synthetic bytes only. Independent x64 execution is the reference oracle.
No original proprietary game code is embedded in public test assets.
"""
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"scripts"))
import mxbikes_native_prefix_wave as pilot

# Push/stack setup, LEA SP, stack load/store, and flag-changing instructions.
PREFIXES=[
    bytes.fromhex("53 4883ec20 4889d9 31c0"),
    bytes.fromhex("488d6424d8 488d4c2410"),
    bytes.fromhex("4883ec28 48894c2420 488b442420"),
    bytes.fromhex("4883ec28 488d6c2420 488b4500"),
    bytes.fromhex("4883ec28 4885c9 4889ca"),
    bytes.fromhex("4883ec28 4889e5 488b4508"),
]
START=0x200000

def synthetic_item(index,prefix):
    rva=START+index*0x100
    # CALL disp32=0 targets exact next instruction, not an injected callee.
    blob=prefix+b"\xe8\x00\x00\x00\x00"
    child=rva+len(blob)
    return pilot.candidate_from_blob(blob,rva,{child})

class NativePrefixWaveTests(unittest.TestCase):
    def test_classifies_all_prologue_operand_families(self):
        for i,prefix in enumerate(PREFIXES):
            with self.subTest(index=i):
                item=synthetic_item(i,prefix)
                self.assertIsNotNone(item)
                self.assertEqual(item["prefix_bytes"],len(prefix))
                self.assertGreater(item["instructions"],0)
        self.assertIsNone(pilot.candidate_from_blob(
            bytes.fromhex("53 eb02 90 90 e800000000"),
            START,{START+11}))
        self.assertIsNone(pilot.candidate_from_blob(
            bytes.fromhex("488b01 e800000000"),
            START,{START+8}))
        self.assertIsNone(pilot.candidate_from_blob(
            bytes.fromhex("4883ec28 e800000000"),
            START,{START+11}))

    def test_original_x64_vs_compiled_host_vs_executed_arm64(self):
        selected=[]
        ref={}
        for i,prefix in enumerate(PREFIXES):
            item=synthetic_item(i,prefix)
            self.assertIsNotNone(item)
            refs=[pilot.original_reference(item,case)
                  for case in range(pilot.CASES)]
            self.assertTrue(all(x is not None for x in refs))
            selected.append(item)
            ref[item["rva"]]=refs
        source=pilot.generate(selected,ref)
        with tempfile.TemporaryDirectory(prefix="native-x64-prefix-") as td:
            root=Path(td)
            code=root/"prefix.c";code.write_text(source)
            flags=["-std=c11","-O2","-Wall","-Wextra","-Werror",
                   "-I",str(pilot.ROOT/"arm64-lab"/"runtime")]
            host=root/"host"
            p=subprocess.run(["cc",*flags,"-DHOST",str(code),"-o",str(host)],
                             capture_output=True,text=True)
            self.assertEqual(p.returncode,0,p.stderr[-2500:])
            p=subprocess.run([str(host)],capture_output=True,text=True)
            self.assertEqual(p.returncode,0,p.stderr[-2500:])
            arm=root/"arm64.elf"
            p=subprocess.run(["clang","--target=aarch64-unknown-linux-gnu",
                "-fuse-ld=lld","-nostdlib","-static","-ffreestanding",
                "-fno-builtin","-fno-stack-protector",*flags,
                "-Wl,-e,smoke","-Wl,-z,max-page-size=4096",
                "-Wl,--build-id=none",str(code),"-o",str(arm)],
                capture_output=True,text=True)
            self.assertEqual(p.returncode,0,p.stderr[-2500:])
            result=pilot.execute_arm64_elf(
                arm,instruction_budget=2500000,timeout_us=15000000)
            self.assertEqual(result["arm64_smoke_exit"],0)

    def test_multi_root_native_parent_wave_prioritizes_and_bounds_candidates(self):
        mapping={"direct_call_graph":{
            hex(START+i*0x100):[hex(0x300000+i*0x100)] for i in range(180)
        }}
        wave=pilot.prioritized_parent_wave(mapping,limit=128)
        self.assertEqual(len(wave),128)
        self.assertEqual(len({row[0] for row in wave}),128)
        with self.assertRaises(ValueError):
            pilot.prioritized_parent_wave(mapping,limit=pilot.MAX_PARENT_SCAN+1)

    def test_unsupported_data_reg_and_implicit_control_fails_closed(self):
        # Unsupported arbitrary [RCX] load and conditional flow never qualify.
        for blob in (
            bytes.fromhex("488b01 e800000000"),
            bytes.fromhex("4883ec20 7502 e800000000"),
            bytes.fromhex("4883ec20 ffd0"),
        ):
            self.assertIsNone(pilot.candidate_from_blob(blob,START,{START+len(blob)}))
        with self.assertRaises(ValueError):
            pilot.discover(type("FakePE",(),{})(),
                           {"original_file_verified":False},limit=1)

if __name__=="__main__":
    unittest.main()
