"""Exact x64 guest-pointer MOV store → native ARM64 CALL differential.

Synthetic Win64 original MOV instructions only. Both emulator results must
agree on post-store guest bytes, final register state and CALL return address.
"""
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"scripts"))
from mxbikes_callsite_prefix import select_prefix_chain, emit_native_prefix
from mxbikes_native_callsite_batch import (
    discover_original_call_sites, callsite_native_source, original_reference,
    execute_arm64_elf, ROOT, EXE_SHA, FIXTURES,
    GUEST_HEAP, GUEST_HEAP_BASE_OFFSET,
)

STORES={
    0x200000:bytes.fromhex("48894b08"), # mov qword [rbx+8],rcx
    0x200100:bytes.fromhex("8956f0"),   # mov dword [rsi-16],edx
}
LEAF_ADDR=0x200800
LEAF=b"\xc3"


def make_function(rva,store):
    delta=LEAF_ADDR-(rva+len(store)+5)
    return store+b"\xe8"+delta.to_bytes(4,"little",signed=True)+b"\xc3"


SOURCE={rva:make_function(rva,store) for rva,store in STORES.items()}
SOURCE[LEAF_ADDR]=LEAF


class FakeOriginalGame:
    def read_rva(self,rva,width):
        body=SOURCE.get(rva)
        if body is None or width!=len(body):
            raise ValueError("Outside the synthetic original function map")
        return body


def original_map():
    return {
        "original_file_verified":True,"input_sha256":EXE_SHA,
        "direct_call_graph":{hex(rva):[hex(LEAF_ADDR)] for rva in STORES},
        "interval_map":[{"rva":hex(rva),"end_rva":hex(rva+len(SOURCE[rva])),
                         "status":"decoded_linear","bytes":len(SOURCE[rva]),
                         "instructions":3} for rva in STORES],
    }


def leaf():
    return {"rva":LEAF_ADDR,"body":LEAF,"kind":"ret",
            "imm":None,"cfg_plan":None,"wave_batch_id":None}


class GuestMemoryStoreBatchTests(unittest.TestCase):
    def test_store_decoder_and_guest_write_guards(self):
        sites=discover_original_call_sites(FakeOriginalGame(),original_map(),[leaf()])
        self.assertEqual(len(sites),2)
        for site in sites:
            self.assertEqual(len(site["prefixes"]),1)
            operation=site["prefixes"][0]
            self.assertEqual(operation["kind"],"guest_heap_store")
            self.assertEqual(operation["src"],"rbx" if site["parent_rva"]==0x200000 else "rsi")
            self.assertIn("mx_cfg_transfer(&memory",emit_native_prefix(operation))
            self.assertIn(",1))return 8;",emit_native_prefix(operation))
        decoder=Cs(CS_ARCH_X86,CS_MODE_64)
        decoder.detail=True
        denied=[
            "488b4b08",         # a read is not a write
            "48894c9308",       # indexed write isn't modeled here
            "48898b00010000",   # +256 displacement outside fixture
            "48890d00000000",   # RIP-relative store
            "48894c2408",       # stack memory isn't guest heap
        ]
        for encoded in denied:
            with self.subTest(encoded=encoded):
                data=bytes.fromhex(encoded)
                ins=list(decoder.disasm(data,0x300000))
                fake=type("Next",(),{"address":0x300000+len(data)})()
                parts=select_prefix_chain(ins+[fake],1)
                if encoded=="488b4b08":
                    self.assertEqual(parts[0]["kind"],"guest_heap_load")
                else:
                    self.assertEqual(parts,[])
        with self.assertRaises(ValueError):
            emit_native_prefix({"kind":"guest_heap_store",
                "src":"rsp","value_reg":"rcx","bits":64,"disp":8})

    def test_original_store_bytes_match_native_host_and_arm64(self):
        sites=discover_original_call_sites(FakeOriginalGame(),original_map(),[leaf()])
        for site in sites:
            store=site["prefixes"][0]
            for j in range(FIXTURES):
                seed,_,result=original_reference(site,j)
                address=seed[store["src"]]+store["disp"]
                size=store["bits"]//8
                self.assertEqual(result["_store_addr"],address)
                self.assertEqual(result["_store_size"],size)
                self.assertEqual(result["_store_value"],
                                 seed[store["value_reg"]] & ((1<<(size*8))-1))
        source=callsite_native_source(sites,[leaf()],sites)
        self.assertIn("expected_store_value",source)
        self.assertIn("guest_store_addr",source)
        with tempfile.TemporaryDirectory(prefix="mxb-guest-store-native-") as td:
            root=Path(td)
            code=root/"original-store-synthetic.c"
            code.write_text(source)
            flags=["-O2","-std=c11","-Wall","-Wextra","-Werror",
                   "-I",str(ROOT/"arm64-lab"/"runtime")]
            host=root/"host"
            proc=subprocess.run(["cc",*flags,"-DHOST",str(code),"-o",str(host)],
                                capture_output=True,text=True)
            self.assertEqual(proc.returncode,0,proc.stderr[-3000:])
            proc=subprocess.run([str(host)],capture_output=True,text=True)
            self.assertEqual(proc.returncode,0,proc.stderr[-3000:])
            arm=root/"native-guest-store.elf"
            proc=subprocess.run(["clang","--target=aarch64-unknown-linux-gnu",
                "-fuse-ld=lld","-nostdlib","-static","-ffreestanding",
                "-fno-stack-protector","-fno-builtin",*flags,
                "-Wl,-e,smoke","-Wl,-z,max-page-size=4096",
                "-Wl,--build-id=none",str(code),"-o",str(arm)],
                capture_output=True,text=True)
            self.assertEqual(proc.returncode,0,proc.stderr[-3000:])
            check=execute_arm64_elf(arm,instruction_budget=2000000,
                                    timeout_us=15000000)
            self.assertEqual(check["arm64_smoke_exit"],0)


if __name__=="__main__":
    unittest.main()
