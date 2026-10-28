"""Bounded x64 ModRM/SIB indexed-memory loads -> verified ARM64 CALL edges.

Synthetic original instructions only. These fixtures verify complete MOV
operand addressing and CALL/RET guest ABI; they do not verify parent functions.
"""
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from capstone import Cs, CS_ARCH_X86, CS_MODE_64

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"scripts"))
from mxbikes_callsite_prefix import select_prefix_chain,emit_native_prefix
from mxbikes_native_callsite_batch import (
    discover_original_call_sites,callsite_native_source,original_reference,
    execute_arm64_elf,ROOT,EXE_SHA,FIXTURES,GUEST_HEAP,
    GUEST_HEAP_BASE_OFFSET,
)

MOVS={
    0x200000:bytes.fromhex("488b4c9308"), # mov rcx,[rbx+rdx*4+8]
    0x200100:bytes.fromhex("428b444ef0"), # mov eax,[rsi+r9*2-16]
    0x200200:bytes.fromhex("488b0413"),   # mov rax,[rbx+rdx]
}
CALLEE=0x200800
LEAF=b"\xc3"


def parent(src,body):
    diff=CALLEE-(src+len(body)+5)
    return body+b"\xe8"+diff.to_bytes(4,"little",signed=True)+b"\xc3"


CODE={rva:parent(rva,mov) for rva,mov in MOVS.items()}
CODE[CALLEE]=LEAF


class SyntheticPE:
    def read_rva(self,rva,size):
        body=CODE.get(rva)
        if body is None or size!=len(body):
            raise ValueError("Outside synthetic original fixture bounds")
        return body


def mapping():
    return {"input_sha256":EXE_SHA,"original_file_verified":True,
            "direct_call_graph":{hex(rva):[hex(CALLEE)] for rva in MOVS},
            "interval_map":[
                {"rva":hex(rva),"end_rva":hex(rva+len(CODE[rva])),
                 "status":"decoded_linear","bytes":len(CODE[rva]),
                 "instructions":3} for rva in MOVS],
           }


def leaf():
    return {"rva":CALLEE,"body":LEAF,"kind":"ret","imm":None,
            "cfg_plan":None,"wave_batch_id":None}


def expected_bytes(base_register,disp,scale,case,width):
    gp=("rax","rbx","rcx","rdx","r8","r9","rdi","rsi","r11")
    index=gp.index(base_register)
    off=GUEST_HEAP_BASE_OFFSET+disp+(case%5)*scale
    return int.from_bytes(bytes(((k*13+31+index)&255)
                                 for k in range(off,off+width)),"little")


class IndexedGuestCallsiteTests(unittest.TestCase):
    def test_decodes_exact_indexed_read_shapes(self):
        decoder=Cs(CS_ARCH_X86,CS_MODE_64)
        decoder.detail=True
        cases=[
            ("488b4c9308","rbx","rdx",4,8,"rcx",64),
            ("428b444ef0","rsi","r9",2,-16,"rax",32),
            ("488b0413","rbx","rdx",1,0,"rax",64),
        ]
        for encoded,base,index,scale,disp,dest,bits in cases:
            with self.subTest(encoded=encoded):
                raw=bytes.fromhex(encoded)
                inst=list(decoder.disasm(raw,0x200000))
                fake=type("Next",(),{"address":0x200000+len(raw)})()
                parts=select_prefix_chain(inst+[fake],1)
                self.assertEqual(len(parts),1)
                part=parts[0]
                self.assertEqual(
                    (part["kind"],part["src"],part["index"],part["scale"],
                     part["disp"],part["dst"],part["bits"]),
                    ("guest_heap_indexed_load",base,index,scale,disp,dest,bits))
                self.assertIn("mx_cfg_transfer(&memory",emit_native_prefix(part))

    def test_rejects_unsafe_index_forms_and_writes(self):
        decoder=Cs(CS_ARCH_X86,CS_MODE_64)
        decoder.detail=True
        bad=[
            "48894c9308",     # mov [rbx+rdx*4+8],rcx: WRITE
            "488b4c9508",     # base rbp not a seeded guest heap base
            "488b0d00000000", # RIP-relative data is not guest heap
            "488b4c9300",     # explicit [rbx+rdx*4+0] valid, not in this set
        ]
        # The first three are fundamentally unsupported addressing variants.
        for blob in bad[:3]:
            with self.subTest(blob=blob):
                raw=bytes.fromhex(blob)
                ins=list(decoder.disasm(raw,0x200000))
                call=type("Next",(),{"address":0x200000+len(raw)})()
                self.assertEqual(select_prefix_chain(ins+[call],1),[])
        with self.assertRaises(ValueError):
            emit_native_prefix({"kind":"guest_heap_indexed_load",
                "dst":"rcx","bits":64,"src":"rbx","index":"rsp","scale":4,"disp":8})
        with self.assertRaises(ValueError):
            emit_native_prefix({"kind":"guest_heap_indexed_load",
                "dst":"rcx","bits":64,"src":"rbx","index":"rdx","scale":16,"disp":8})

    def test_original_indexed_load_and_call_match_host_and_arm64(self):
        sites=discover_original_call_sites(SyntheticPE(),mapping(),[leaf()])
        self.assertEqual(len(sites),len(MOVS))
        self.assertTrue(all(len(s["prefixes"])==1 for s in sites))
        for site in sites:
            item=site["prefixes"][0]
            self.assertEqual(item["kind"],"guest_heap_indexed_load")
            for case in range(FIXTURES):
                seed,_,result=original_reference(site,case)
                self.assertEqual(seed[item["index"]],case%5)
                self.assertGreaterEqual(seed[item["src"]],GUEST_HEAP)
                value=expected_bytes(item["src"],item["disp"],item["scale"],
                                     case,item["bits"]//8)
                self.assertEqual(result[item["dst"]],value)
        source=callsite_native_source(sites,[leaf()],sites)
        self.assertIn("guest_indexed_address",source)
        with tempfile.TemporaryDirectory(prefix="mxb-indexed-guest-") as td:
            root=Path(td)
            code=root/"indexed-guest-test.c"
            code.write_text(source)
            options=["-O2","-std=c11","-Wall","-Wextra","-Werror",
                     "-I",str(ROOT/"arm64-lab"/"runtime")]
            host=root/"host"
            result=subprocess.run(["cc",*options,"-DHOST",str(code),"-o",str(host)],
                                  capture_output=True,text=True)
            self.assertEqual(result.returncode,0,result.stderr[-3000:])
            result=subprocess.run([str(host)],capture_output=True,text=True)
            self.assertEqual(result.returncode,0,result.stderr[-3000:])
            arm=root/"indexed-arm64.elf"
            result=subprocess.run(["clang","--target=aarch64-unknown-linux-gnu",
                "-fuse-ld=lld","-nostdlib","-static","-ffreestanding",
                "-fno-stack-protector","-fno-builtin",*options,
                "-Wl,-e,smoke","-Wl,-z,max-page-size=4096",
                "-Wl,--build-id=none",str(code),"-o",str(arm)],
                capture_output=True,text=True)
            self.assertEqual(result.returncode,0,result.stderr[-3000:])
            run=execute_arm64_elf(arm,instruction_budget=2500000,
                                  timeout_us=15000000)
            self.assertEqual(run["arm64_smoke_exit"],0)


if __name__=="__main__":
    unittest.main()
