"""Four-instruction original argument-setup plus CALL differential regression.

The original bytes are synthetic fixtures; verified parent-function coverage
is never inferred from this partial straight-line CALL prefix.
"""
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"scripts"))
from mxbikes_callsite_prefix import select_prefix_chain
from mxbikes_native_callsite_batch import (
    discover_original_call_sites, callsite_native_source,
    execute_arm64_elf, ROOT, EXE_SHA, FIXTURES, original_reference
)

PARENT=0x200000
TARGET=0x200500
LEAF=bytes.fromhex("8bc1c3")
# XOR edx,edx ; MOV ecx,42 ; LEA r8,[rcx+8] ; MOV r9,r8
SETUP=bytes.fromhex("31d2 b92a000000 4c8d4108 4d89c1")
CALL=b"\xe8"+(TARGET-(PARENT+len(SETUP)+5)).to_bytes(4,"little",signed=True)
BODY=SETUP+CALL+b"\xc3"


class SyntheticPE:
    def read_rva(self,rva,width):
        body={PARENT:BODY,TARGET:LEAF}.get(rva)
        if body is None or width!=len(body):
            raise ValueError("Invalid synthetic original callsite read")
        return body


def graph():
    return {
        "original_file_verified":True,"input_sha256":EXE_SHA,
        "direct_call_graph":{hex(PARENT):[hex(TARGET)]},
        "interval_map":[{"rva":hex(PARENT),"end_rva":hex(PARENT+len(BODY)),
                         "bytes":len(BODY),"status":"decoded_linear",
                         "instructions":6}]
    }


def leaf():
    return {"rva":TARGET,"body":LEAF,"kind":"mov_eax_ecx_ret",
            "imm":None,"cfg_plan":None,"wave_batch_id":None}


class BatchedArgumentSetupTests(unittest.TestCase):
    def test_discovers_entire_contiguous_safe_setup(self):
        decoder=Cs(CS_ARCH_X86,CS_MODE_64)
        decoder.detail=True
        ins=list(decoder.disasm(BODY,PARENT))
        self.assertEqual(len(ins),6)
        setup=select_prefix_chain(ins,4)
        self.assertEqual(len(setup),4)
        self.assertEqual([x["kind"] for x in setup],
                         ["zero_register","immediate_register",
                          "effective_address","register_mov"])
        sites=discover_original_call_sites(SyntheticPE(),graph(),[leaf()])
        self.assertEqual(len(sites),1)
        self.assertEqual(sites[0]["entry_rva"],PARENT)
        self.assertEqual(sites[0]["original_prefix_bytes"],SETUP)
        self.assertEqual(len(sites[0]["prefixes"]),4)
        self.assertFalse(sites[0]["parent_function_native_complete"])

    def test_bounded_recognizer_stops_before_unsupported_opcode(self):
        decoder=Cs(CS_ARCH_X86,CS_MODE_64)
        decoder.detail=True
        data=bytes.fromhex("31d2 90 b92a000000 90")
        data+=CALL+b"\xc3"
        ins=list(decoder.disasm(data,PARENT))
        call_index=next(i for i,x in enumerate(ins) if x.mnemonic=="call")
        found=select_prefix_chain(ins,call_index)
        self.assertEqual(len(found),0)

    def test_host_and_executed_arm64_match_original_four_setup_instructions(self):
        sites=discover_original_call_sites(SyntheticPE(),graph(),[leaf()])
        for i in range(FIXTURES):
            seed,initial_flags,observed=original_reference(sites[0],i)
            self.assertEqual(observed["rcx"],42)
            self.assertEqual(observed["rdx"],0)
            self.assertEqual(observed["r8"],50)
            self.assertEqual(observed["r9"],50)
            self.assertEqual(observed["rax"],42)
        source=callsite_native_source(sites,[leaf()],sites)
        self.assertIn("s.rcx=UINT64_C(42);",source)
        self.assertIn("s.r8=s.rcx+UINT64_C(8);",source)
        self.assertIn("s.r9=s.r8;",source)
        with tempfile.TemporaryDirectory(prefix="mxb-four-arg-") as td:
            directory=Path(td)
            code=directory/"verified-synthetic-original.c"
            code.write_text(source)
            common=["-O2","-std=c11","-Wall","-Wextra","-Werror",
                    "-I",str(ROOT/"arm64-lab"/"runtime")]
            host=directory/"host"
            result=subprocess.run(["cc",*common,"-DHOST",str(code),"-o",str(host)],
                                  capture_output=True,text=True)
            self.assertEqual(result.returncode,0,result.stderr[-3000:])
            result=subprocess.run([str(host)],capture_output=True,text=True)
            self.assertEqual(result.returncode,0,result.stderr[-3000:])
            elf=directory/"test-arm64.elf"
            result=subprocess.run([
                "clang","--target=aarch64-unknown-linux-gnu","-fuse-ld=lld",
                "-nostdlib","-static","-ffreestanding",
                "-fno-stack-protector","-fno-builtin",
                *common,"-Wl,-e,smoke","-Wl,-z,max-page-size=4096",
                "-Wl,--build-id=none",str(code),"-o",str(elf)
            ],capture_output=True,text=True)
            self.assertEqual(result.returncode,0,result.stderr[-3000:])
            proof=execute_arm64_elf(elf,instruction_budget=1000000,
                                    timeout_us=12000000)
            self.assertEqual(proof["arm64_smoke_exit"],0)


if __name__=="__main__":
    unittest.main()
