"""Synthetic entire x64 prefix+CALL differential across safe setup families."""
import sys
from pathlib import Path
import subprocess
import tempfile
import unittest

from capstone import Cs, CS_ARCH_X86, CS_MODE_64
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"scripts"))
from mxbikes_callsite_prefix import select_prefix,emit_native_prefix
from mxbikes_native_callsite_batch import (
    discover_original_call_sites,callsite_native_source,
    execute_arm64_elf,ROOT,EXE_SHA
)
TARGET=0x200900
LEAF=bytes.fromhex("8bc1c3")
PREFIXES={
    0x200000:bytes.fromhex("488d4c2420"),       # lea rcx,[rsp+32]
    0x200100:bytes.fromhex("31d2"),             # xor edx,edx
    0x200200:bytes.fromhex("b92a000000"),       # mov ecx,42
    0x200300:bytes.fromhex("49b82a00000000000000"), # mov r8,42
}


def make_parent(rva,prefix):
    delta=TARGET-(rva+len(prefix)+5)
    return prefix+b"\xe8"+delta.to_bytes(4,"little",signed=True)+b"\xc3"


PARENTS={rva:make_parent(rva,prefix) for rva,prefix in PREFIXES.items()}


class PrivateSynthetic:
    def read_rva(self,rva,size):
        table={**PARENTS,TARGET:LEAF}
        item=table.get(rva)
        if item is None or len(item)!=size:
            raise ValueError("Synthetic original interval read not authorized")
        return item


def mapping():
    return {"input_sha256":EXE_SHA,"original_file_verified":True,
            "direct_call_graph":{hex(rva):[hex(TARGET)] for rva in PARENTS},
            "interval_map":[{"rva":hex(rva),"end_rva":hex(rva+len(body)),
                             "status":"decoded_linear","bytes":len(body),
                             "instructions":3} for rva,body in PARENTS.items()]}


def leaf():
    return {"rva":TARGET,"body":LEAF,"kind":"mov_eax_ecx_ret",
            "imm":None,"cfg_plan":None,"wave_batch_id":None}


class OriginalPrefixFamiliesTests(unittest.TestCase):
    def test_decoder_never_accepts_indirect_guest_memory(self):
        dec=Cs(CS_ARCH_X86,CS_MODE_64)
        dec.detail=True
        for blob in (bytes.fromhex("488b4c2480"),
                     bytes.fromhex("488b05aabbccdd")):
            inst=list(dec.disasm(blob,0x1234))
            if inst:
                self.assertIsNone(select_prefix(inst+[type("Next",(),{"address":inst[0].address+inst[0].size})()],1))
        # A nonindexed MOV write into a bounded guest heap page is now
        # supported, but remains distinct from arbitrary host pointer writes.
        original_store=list(dec.disasm(bytes.fromhex("488901"),0x1234))[0]
        after_store=type("Next",(),{"address":0x1234+original_store.size})()
        self.assertEqual(select_prefix([original_store,after_store],1)["kind"],
                         "guest_heap_store")
        with self.assertRaises(ValueError):
            emit_native_prefix({"kind":"effective_address","dst":"rsp",
                                "src":"rsp","disp":4,"bits":64})

    def test_all_setup_families_match_original_x64_host_and_arm64(self):
        sites=discover_original_call_sites(PrivateSynthetic(),mapping(),[leaf()])
        self.assertEqual(len(sites),len(PREFIXES))
        self.assertTrue(all(site["prefix"] for site in sites),
                        [(hex(site["parent_rva"]),site["prefix"]) for site in sites])
        self.assertEqual({s["prefix"]["kind"] for s in sites},
                         {"effective_address","zero_register",
                          "immediate_register"})
        source=callsite_native_source(sites,[leaf()],sites)
        self.assertIn("s.rcx=s.rsp+UINT64_C(32);",source)
        self.assertIn("s.rdx=0U;s.cf=0U;s.zf=1U;s.sf=0U;",source)
        self.assertIn("s.rcx=UINT64_C(42);",source)
        with tempfile.TemporaryDirectory(prefix="mxb-prefix-families-") as td:
            root=Path(td)
            cfile=root/"safe-x64-original-prefix-fixtures.c"
            cfile.write_text(source)
            flags=["-O2","-std=c11","-Wall","-Wextra","-Werror",
                   "-I",str(ROOT/"arm64-lab"/"runtime")]
            exe=root/"host"
            out=subprocess.run(["cc",*flags,"-DHOST",str(cfile),"-o",str(exe)],
                               capture_output=True,text=True)
            self.assertEqual(out.returncode,0,out.stderr[-3000:])
            out=subprocess.run([str(exe)],capture_output=True,text=True)
            self.assertEqual(out.returncode,0,out.stderr[-3000:])
            arm=root/"native-aarch64.elf"
            out=subprocess.run(["clang","--target=aarch64-unknown-linux-gnu",
                "-fuse-ld=lld","-nostdlib","-static","-ffreestanding",
                "-fno-stack-protector","-fno-builtin",*flags,
                "-Wl,-e,smoke","-Wl,-z,max-page-size=4096",
                "-Wl,--build-id=none",str(cfile),"-o",str(arm)],
                capture_output=True,text=True)
            self.assertEqual(out.returncode,0,out.stderr[-3000:])
            out=execute_arm64_elf(arm,instruction_budget=2000000,
                                  timeout_us=15000000)
            self.assertEqual(out["arm64_smoke_exit"],0)


if __name__=="__main__":
    unittest.main()
