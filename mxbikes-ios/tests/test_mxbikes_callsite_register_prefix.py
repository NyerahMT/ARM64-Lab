"""Synthetic original MOV-register→CALL→RET slice against native ARM64.

Tests the one instruction before the original direct CALL independently of any
claim that the surrounding game function has been fully translated.
"""
import sys
from pathlib import Path
import subprocess
import tempfile
import unittest
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"scripts"))
from mxbikes_callsite_prefix import decode_mov_prefix, emit_native_prefix
from mxbikes_native_callsite_batch import (
    discover_original_call_sites, callsite_native_source,
    execute_arm64_elf,ROOT,EXE_SHA
)

PARENT=0x200000
TARGET=0x200100
LEAF=bytes.fromhex("8bc1c3")
REGISTER_MOV=bytes.fromhex("4889d9") # MOV rcx,rbx ; caller sets argument.
delta=TARGET-(PARENT+len(REGISTER_MOV)+5)
PARENT_BYTES=REGISTER_MOV+b"\xe8"+delta.to_bytes(4,"little",signed=True)+b"\xc3"


class SyntheticPE:
    def read_rva(self,addr,size):
        table={PARENT:PARENT_BYTES,TARGET:LEAF}
        value=table.get(addr)
        if value is None or size!=len(value):
            raise ValueError("Original synthetic region absent")
        return value


def mapping():
    return {"original_file_verified":True,"input_sha256":EXE_SHA,
            "direct_call_graph":{hex(PARENT):[hex(TARGET)]},
            "interval_map":[{"rva":hex(PARENT),"end_rva":hex(PARENT+len(PARENT_BYTES)),
                             "bytes":len(PARENT_BYTES),"status":"decoded_linear",
                             "instructions":3}]}


def callee():
    return {"rva":TARGET,"body":LEAF,"kind":"mov_eax_ecx_ret",
            "imm":None,"cfg_plan":None,"wave_batch_id":None}


class OriginalRegisterPrefixTests(unittest.TestCase):
    def test_exact_register_only_decoding(self):
        decoder=Cs(CS_ARCH_X86,CS_MODE_64)
        decoder.detail=True
        ins=list(decoder.disasm(REGISTER_MOV,PARENT))[0]
        decoded=decode_mov_prefix(ins)
        self.assertEqual(decoded["src"],"rbx")
        self.assertEqual(decoded["dst"],"rcx")
        self.assertEqual(decoded["bits"],64)
        self.assertEqual(emit_native_prefix(decoded),"s.rcx=s.rbx;")
        for blob in ("488b01","488b0424","4889e1"):
            ins=list(decoder.disasm(bytes.fromhex(blob),PARENT))[0]
            self.assertIsNone(decode_mov_prefix(ins))
        with self.assertRaises(ValueError):
            emit_native_prefix({"kind":"register_mov","src":"rsp","dst":"rax","bits":64})

    def test_original_register_setup_call_reference_matches_executed_arm64(self):
        sites=discover_original_call_sites(SyntheticPE(),mapping(),[callee()])
        self.assertEqual(len(sites),1)
        self.assertEqual(sites[0]["entry_rva"],PARENT)
        self.assertEqual(sites[0]["original_prefix_bytes"],REGISTER_MOV)
        self.assertEqual(sites[0]["callsite_rva"],PARENT+3)
        src=callsite_native_source(sites,[callee()],sites)
        self.assertIn("s.rcx=s.rbx;",src)
        self.assertIn("uint32_t site_index;",src)
        with tempfile.TemporaryDirectory(prefix="mxb-reg-call-synthetic-") as td:
            root=Path(td)
            cfile=root/"original-reg-call.c"
            cfile.write_text(src)
            flags=["-O2","-std=c11","-Wall","-Wextra","-Werror",
                   "-I",str(ROOT/"arm64-lab"/"runtime")]
            host=root/"host"
            proc=subprocess.run(["cc",*flags,"-DHOST",str(cfile),"-o",str(host)],
                                capture_output=True,text=True)
            self.assertEqual(proc.returncode,0,proc.stderr[-3000:])
            proc=subprocess.run([str(host)],capture_output=True,text=True)
            self.assertEqual(proc.returncode,0,proc.stderr[-3000:])
            arm=root/"native-arm64.elf"
            proc=subprocess.run(["clang","--target=aarch64-unknown-linux-gnu",
                "-fuse-ld=lld","-nostdlib","-static","-ffreestanding",
                "-fno-stack-protector","-fno-builtin",*flags,"-Wl,-e,smoke",
                "-Wl,-z,max-page-size=4096","-Wl,--build-id=none",
                str(cfile),"-o",str(arm)],capture_output=True,text=True)
            self.assertEqual(proc.returncode,0,proc.stderr[-3000:])
            result=execute_arm64_elf(arm,instruction_budget=1000000,
                                     timeout_us=12000000)
            self.assertEqual(result["arm64_smoke_exit"],0)


if __name__=="__main__":
    unittest.main()
