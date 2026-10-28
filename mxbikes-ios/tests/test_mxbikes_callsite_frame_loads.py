"""Fixture-bounded RBP-relative x64 reads -> actual ARM64 CALL differential.

RBP is intentionally seeded as entry RSP + 64 in the original Unicorn
reference; this is *not* proof of the game's unconverted parent prologue.
"""
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from capstone import Cs, CS_ARCH_X86, CS_MODE_64

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"scripts"))
from mxbikes_callsite_prefix import (
    select_prefix_chain, decode_frame_pointer_load_prefix, emit_native_prefix,
    FRAME_ANCHOR_FROM_RSP
)
from mxbikes_native_callsite_batch import (
    discover_original_call_sites,callsite_native_source,original_reference,
    execute_arm64_elf,ROOT,EXE_SHA,FIXTURES,characterize_frame_predecessor,
)

CALLER_PREFIXES={
    0x200000:bytes.fromhex("488b4de0"),          # mov rcx,[rbp-32]
    0x200100:bytes.fromhex("8b5510"),            # mov edx,[rbp+16]
    0x200200:bytes.fromhex("488b4de08b5510"),    # 2-instruction call setup
    0x200300:bytes.fromhex("488b45c0"),          # mov rax,[rbp-64]
    0x200400:bytes.fromhex("488b8d80000000"),    # mov rcx,[rbp+128]
    0x200500:bytes.fromhex("488b9550010000"),    # mov rdx,[rbp+336]
    0x200600:bytes.fromhex("488b8d00020000"),    # mov rcx,[rbp+512]
}
CHILD=0x200800
CHILD_BODY=b"\xc3"


def parent(rva,part):
    delta=CHILD-(rva+len(part)+5)
    return part+b"\xe8"+delta.to_bytes(4,"little",signed=True)+b"\xc3"


CODE={rva:parent(rva,pre) for rva,pre in CALLER_PREFIXES.items()}
CODE[CHILD]=CHILD_BODY


class SyntheticOwnedGame:
    def read_rva(self,rva,size):
        code=CODE.get(rva)
        if code is None or size!=len(code):
            raise ValueError("Read outside synthetic original function boundaries")
        return code


def mapping():
    return {
        "original_file_verified":True,"input_sha256":EXE_SHA,
        "direct_call_graph":{hex(rva):[hex(CHILD)] for rva in CALLER_PREFIXES},
        "interval_map":[
            {"rva":hex(rva),"end_rva":hex(rva+len(CODE[rva])),
             "status":"decoded_linear","bytes":len(CODE[rva]),
             "instructions":len(list(Cs(CS_ARCH_X86,CS_MODE_64).disasm(CODE[rva],rva)))}
            for rva in CALLER_PREFIXES
        ],
    }


def leaf():
    return {"rva":CHILD,"body":CHILD_BODY,"kind":"ret",
            "imm":None,"cfg_plan":None,"wave_batch_id":None}


def expected_value(offset,width):
    return int.from_bytes(
        bytes((k*17+9)&255 for k in range(offset,offset+width)),
        "little"
    )


class GuestFramePointerBatches(unittest.TestCase):
    def test_reject_outside_modeled_frame_or_unsupported_access(self):
        decoder=Cs(CS_ARCH_X86,CS_MODE_64)
        decoder.detail=True
        rejected=[
            "488b45b8",       # [rbp-72] before initialized RSP
            "488b4580",       # [rbp-128] outside initialized stack
            "488b8520040000", # +1056 still outside the 1024-byte fixture
            "488b4c4de0",     # indexed [rbp+rcx*2-32], unsupported
            "488945e0",       # STORE, not a frame load
            "488b4c2408",     # RSP load is a different model
        ]
        for raw in rejected:
            with self.subTest(raw=raw):
                ins=list(decoder.disasm(bytes.fromhex(raw),0x300000))
                if ins:
                    self.assertIsNone(decode_frame_pointer_load_prefix(ins[0]))
        with self.assertRaises(ValueError):
            emit_native_prefix({
                "kind":"frame_pointer_load","dst":"rcx","bits":64,
                "frame_disp":-80,"stack_offset":-16
            })
        with self.assertRaises(ValueError):
            emit_native_prefix({
                "kind":"frame_pointer_load","dst":"rcx","bits":64,
                "frame_disp":0,"stack_offset":0
            })

    def test_aggregate_original_frame_rejection_reasons(self):
        decoder=Cs(CS_ARCH_X86,CS_MODE_64)
        decoder.detail=True
        expected={
            "488b4de0":"rbp:bounded_fixture_eligible",
            "488b45b8":"rbp:before_fixture_window",
            "488b4580":"rbp:before_fixture_window",
            "488b8500040000":"rbp:after_fixture_window",
            "488b8d80000000":"rbp:bounded_fixture_eligible",
            "488b4c4de0":"rbp:indexed_address",
            "0fb64df8":"rbp:non_mov",
            "488b4c2408":None,
        }
        for encoded,classification in expected.items():
            with self.subTest(encoded=encoded):
                parts=list(decoder.disasm(bytes.fromhex(encoded),0x300000))
                self.assertEqual(len(parts),1)
                self.assertEqual(characterize_frame_predecessor(parts[0]),
                                 classification)

    def test_original_frame_loads_and_multi_instruction_call_match_arm64(self):
        sites=discover_original_call_sites(SyntheticOwnedGame(),mapping(),[leaf()])
        self.assertEqual(len(sites),len(CALLER_PREFIXES))
        self.assertEqual(sum(len(s["prefixes"])>1 for s in sites),1)
        self.assertEqual(FRAME_ANCHOR_FROM_RSP,64)
        for site in sites:
            self.assertTrue(site["prefixes"])
            for part in site["prefixes"]:
                self.assertEqual(part["kind"],"frame_pointer_load")
                self.assertIn("mx_cfg_transfer(&memory",emit_native_prefix(part))
            for case in range(FIXTURES):
                _,_,result=original_reference(site,case)
                for part in site["prefixes"]:
                    self.assertEqual(
                        result[part["dst"]],
                        expected_value(part["stack_offset"],part["bits"]//8))
        generated=callsite_native_source(sites,[leaf()],sites)
        self.assertIn("frame_value",generated)
        with tempfile.TemporaryDirectory(prefix="mxb-rbp-guest-frame-") as td:
            root=Path(td)
            source=root/"original-frame-caller.c"
            source.write_text(generated)
            flags=["-O2","-std=c11","-Wall","-Wextra","-Werror",
                   "-I",str(ROOT/"arm64-lab"/"runtime")]
            host=root/"host"
            run=subprocess.run(["cc",*flags,"-DHOST",str(source),"-o",str(host)],
                               capture_output=True,text=True)
            self.assertEqual(run.returncode,0,run.stderr[-3000:])
            run=subprocess.run([str(host)],capture_output=True,text=True)
            self.assertEqual(run.returncode,0,run.stderr[-3000:])
            arm=root/"native-aarch64.elf"
            run=subprocess.run(["clang","--target=aarch64-unknown-linux-gnu",
                "-fuse-ld=lld","-nostdlib","-static","-ffreestanding",
                "-fno-stack-protector","-fno-builtin",*flags,
                "-Wl,-e,smoke","-Wl,-z,max-page-size=4096",
                "-Wl,--build-id=none",str(source),"-o",str(arm)],
                capture_output=True,text=True)
            self.assertEqual(run.returncode,0,run.stderr[-3000:])
            result=execute_arm64_elf(arm,instruction_budget=2500000,
                                     timeout_us=15000000)
            self.assertEqual(result["arm64_smoke_exit"],0)


if __name__=="__main__":
    unittest.main()
