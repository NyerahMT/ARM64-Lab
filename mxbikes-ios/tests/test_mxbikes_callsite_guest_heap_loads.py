"""Original x64 guest-pointer load→verified leaf differential against AArch64.

All tests use synthetic original x64 bytes and deterministic guest-only pages.
Proves bounded memory-load and CALL semantics, never full parent execution.
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
    execute_arm64_elf, ROOT, EXE_SHA, FIXTURES
)

BODIES={
    0x200000: bytes.fromhex("488b4b08"),  # mov rcx,[rbx+8]
    0x200100: bytes.fromhex("4c8b4610"),  # mov r8,[rsi+16]
    0x200200: bytes.fromhex("488b0b"),    # mov rcx,[rbx]
}
CHILDREN={
    0x200500: bytes.fromhex("8bc1c3"),    # mov eax,ecx ; ret
    0x200600: bytes.fromhex("418bc0c3"),  # mov eax,r8d ; ret
}
TARGETS={0x200000:0x200500,0x200100:0x200600,0x200200:0x200500}

def parent(rva,prefix):
    dest=TARGETS[rva]
    return prefix+b"\xe8"+(dest-(rva+len(prefix)+5)).to_bytes(
        4,"little",signed=True)+b"\xc3"

GAME={rva:parent(rva,blob) for rva,blob in BODIES.items()}
GAME.update(CHILDREN)

class SyntheticPE:
    def read_rva(self,rva,length):
        code=GAME.get(rva)
        if code is None or len(code)!=length:
            raise ValueError("Synthetic game address outside fixture")
        return code

def mapping():
    return {
        "input_sha256":EXE_SHA, "original_file_verified":True,
        "direct_call_graph":{hex(src):[hex(dest)]
                             for src,dest in TARGETS.items()},
        "interval_map":[{"rva":hex(rva),"end_rva":hex(rva+len(GAME[rva])),
                         "bytes":len(GAME[rva]),"status":"decoded_linear",
                         "instructions":3} for rva in BODIES],
    }

def leaf(rva):
    return {"rva":rva,"body":CHILDREN[rva],"imm":None,
            "kind":"mov_eax_ecx_ret" if rva==0x200500 else "mov_eax_r8d_ret",
            "cfg_plan":None,"wave_batch_id":None}

def input_value(base_index,disp):
    start=256+disp
    return int.from_bytes(bytes((k*13+31+base_index)&255
                                for k in range(start,start+4)),"little")

class GuestPointerBatchTests(unittest.TestCase):
    def test_restricts_original_guest_reads_to_bounded_nonindexed_pages(self):
        sites=discover_original_call_sites(
            SyntheticPE(),mapping(),[leaf(rva) for rva in CHILDREN])
        self.assertEqual(len(sites),3)
        for site in sites:
            self.assertEqual(len(site["prefixes"]),1)
            item=site["prefixes"][0]
            self.assertEqual(item["kind"],"guest_heap_load")
            self.assertIn("mx_cfg_transfer",emit_native_prefix(item))
        decoder=Cs(CS_ARCH_X86,CS_MODE_64)
        decoder.detail=True
        bad=[
            "488b8b00010000",# +256 outside bounded displacement
            "488b0d00000000",# RIP-relative addressing not modeled
        ]
        for encoded in bad:
            code=bytes.fromhex(encoded)
            inst=list(decoder.disasm(code,0x300000))
            fake_call=type("Next",(),{"address":0x300000+len(code)})()
            with self.subTest(hex=encoded):
                self.assertEqual(select_prefix_chain(inst+[fake_call],1),[])
        # Frame-pointer loads use a separately seeded bounded guest-stack
        # fixture and must never be misclassified as arbitrary heap reads.
        frame=list(decoder.disasm(bytes.fromhex("488b4d08"),0x300000))[0]
        fake_frame=type("Next",(),{"address":0x300000+frame.size})()
        self.assertEqual(select_prefix_chain([frame,fake_frame],1)[0]["kind"],
                         "frame_pointer_load")
        from mxbikes_callsite_prefix import decode_guest_heap_load_prefix
        self.assertIsNone(decode_guest_heap_load_prefix(frame))
        # Stores are a separate bounded family, never misclassified as loads.
        original_store=bytes.fromhex("48894b08")
        ins=list(decoder.disasm(original_store,0x300000))[0]
        next_call=type("Next",(),{"address":0x300000+len(original_store)})()
        self.assertEqual(select_prefix_chain([ins,next_call],1)[0]["kind"],
                         "guest_heap_store")
        from mxbikes_callsite_prefix import decode_guest_heap_load_prefix
        self.assertIsNone(decode_guest_heap_load_prefix(ins))
        # Indexed loads are now separately modeled with bounded SIB
        # addressing, but they are still NOT unindexed guest heap loads.
        indexed=bytes.fromhex("488b4c7308")
        op=list(decoder.disasm(indexed,0x300000))[0]
        fake=type("Next",(),{"address":0x300000+len(indexed)})()
        self.assertEqual(select_prefix_chain([op,fake],1)[0]["kind"],
                         "guest_heap_indexed_load")
        from mxbikes_callsite_prefix import decode_guest_heap_load_prefix
        self.assertIsNone(decode_guest_heap_load_prefix(op))
        with self.assertRaises(ValueError):
            emit_native_prefix({"kind":"guest_heap_load","src":"rsp",
                                "dst":"rcx","bits":64,"disp":0})

    def test_real_abi_guest_pointer_reads_match_host_and_emulated_arm64(self):
        sites=discover_original_call_sites(
            SyntheticPE(),mapping(),[leaf(rva) for rva in CHILDREN])
        for site in sites:
            setup=site["prefixes"][0]
            base_index=1 if setup["src"]=="rbx" else 7
            expect=input_value(base_index,setup["disp"])
            for n in range(FIXTURES):
                seed,flags,observed=original_reference(site,n)
                self.assertEqual(observed["rax"],expect)
                self.assertGreater(seed[setup["src"]],0x720000000)
        source=callsite_native_source(
            sites,[leaf(rva) for rva in CHILDREN],sites)
        self.assertIn("guest_heap_bytes",source)
        with tempfile.TemporaryDirectory(prefix="mxb-guest-heap-") as td:
            root=Path(td)
            output=root/"synthetic-callsite-mem.c"
            output.write_text(source)
            flags=["-O2","-std=c11","-Wall","-Wextra","-Werror",
                   "-I",str(ROOT/"arm64-lab"/"runtime")]
            host=root/"host"
            p=subprocess.run(["cc",*flags,"-DHOST",str(output),"-o",str(host)],
                             capture_output=True,text=True)
            self.assertEqual(p.returncode,0,p.stderr[-3000:])
            p=subprocess.run([str(host)],capture_output=True,text=True)
            self.assertEqual(p.returncode,0,p.stderr[-3000:])
            native=root/"guest-aarch64.elf"
            p=subprocess.run(["clang","--target=aarch64-unknown-linux-gnu",
                "-fuse-ld=lld","-nostdlib","-static","-ffreestanding",
                "-fno-stack-protector","-fno-builtin",*flags,
                "-Wl,-e,smoke","-Wl,-z,max-page-size=4096",
                "-Wl,--build-id=none",str(output),"-o",str(native)],
                capture_output=True,text=True)
            self.assertEqual(p.returncode,0,p.stderr[-3000:])
            result=execute_arm64_elf(native,instruction_budget=3500000,
                                     timeout_us=15000000)
            self.assertEqual(result["arm64_smoke_exit"],0)

if __name__=="__main__":
    unittest.main()
