"""Bounded original Win64 shadow-stack argument MOV->CALL differential.

Synthetic code only. Same deterministic argument bytes are installed in the
original x64 emulator and native ARM64 guest-memory adapters.
"""
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"scripts"))
from mxbikes_callsite_prefix import select_prefix_chain, emit_native_prefix
from mxbikes_native_callsite_batch import (
    discover_original_call_sites, callsite_native_source, original_reference,
    execute_arm64_elf, ROOT, EXE_SHA, FIXTURES
)
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

PARENTS={
    0x200000: bytes.fromhex("488b4c2420"),  # mov rcx,qword ptr [rsp+32]
    0x200100: bytes.fromhex("8b542428"),    # mov edx,dword ptr [rsp+40]
}
CHILDREN={
    0x200500: bytes.fromhex("8bc1c3"),      # mov eax,ecx ; ret
    0x200600: bytes.fromhex("8bc2c3"),      # mov eax,edx ; ret
}
EDGES={0x200000:0x200500,0x200100:0x200600}

def body(rva,setup):
    destination=EDGES[rva]
    return setup+b"\xe8"+(destination-(rva+len(setup)+5)).to_bytes(
        4,"little",signed=True)+b"\xc3"

CODE={rva:body(rva,prefix) for rva,prefix in PARENTS.items()}
CODE.update(CHILDREN)

class TestPE:
    def read_rva(self,rva,n):
        data=CODE.get(rva)
        if data is None or n!=len(data):
            raise ValueError("Synthetic memory outside fixture")
        return data

def leaf(rva):
    return {"rva":rva,"body":CHILDREN[rva],
            "kind":"mov_eax_ecx_ret" if rva==0x200500 else "mov_eax_edx_ret",
            "imm":None,"cfg_plan":None,"wave_batch_id":None}

def original_map():
    return {
        "input_sha256":EXE_SHA, "original_file_verified":True,
        "direct_call_graph":{hex(rva):[hex(dest)] for rva,dest in EDGES.items()},
        "interval_map":[{"rva":hex(rva),"end_rva":hex(rva+len(CODE[rva])),
                         "bytes":len(CODE[rva]),"status":"decoded_linear",
                         "instructions":3} for rva in PARENTS],
    }

def expected_arg(off,width):
    return int.from_bytes(bytes((k*17+9)&255 for k in range(off,off+width)),
                          "little")

class StackArgumentBatches(unittest.TestCase):
    def test_stack_read_only_and_reject_arbitrary_pointer_loads(self):
        d=Cs(CS_ARCH_X86,CS_MODE_64)
        d.detail=True
        sites=discover_original_call_sites(TestPE(),original_map(),
                                           [leaf(r) for r in CHILDREN])
        self.assertEqual(len(sites),2)
        for row in sites:
            self.assertEqual(len(row["prefixes"]),1)
            operation=row["prefixes"][0]
            self.assertEqual(operation["kind"],"stack_argument_load")
            self.assertEqual(row["preceding_operand_family"],"mov:reg<-mem_rsp")
            self.assertIn("mx_cfg_transfer(&memory",emit_native_prefix(operation))
        for blob in ("488b4c2480",   # [rsp-128], out of bounded window
                     "488b8c2480000000"): # [rsp+128], out of bounded window
            source=bytes.fromhex(blob)
            ins=list(d.disasm(source,0x300000))
            call=type("FakeCall",(),{"address":0x300000+len(source)})()
            self.assertEqual(select_prefix_chain(ins+[call],1),[])
        # A bounded guest heap WRITE now has its own decoder. It does not
        # imply arbitrary stack or host process-memory writes are supported.
        store=bytes.fromhex("488901")
        inst=list(d.disasm(store,0x300000))[0]
        fake=type("FakeCall",(),{"address":0x300000+len(store)})()
        self.assertEqual(select_prefix_chain([inst,fake],1)[0]["kind"],
                         "guest_heap_store")
        with self.assertRaises(ValueError):
            emit_native_prefix({"kind":"stack_argument_load",
                                "dst":"rcx","bits":64,"offset":124})

    def test_operand_inventory_does_not_promote_guest_pointer_reads(self):
        from mxbikes_native_callsite_batch import describe_preceding_operand_family
        decoder=Cs(CS_ARCH_X86,CS_MODE_64)
        decoder.detail=True
        reg_mem=list(decoder.disasm(bytes.fromhex("488b0b"),0x1234))[0]
        self.assertEqual(describe_preceding_operand_family(reg_mem),
                         "mov:reg<-mem_guest_base")
        self.assertEqual(describe_preceding_operand_family(None),"start_of_interval")

    def test_original_stack_argument_reads_match_host_and_executed_aarch64(self):
        sites=discover_original_call_sites(TestPE(),original_map(),
                                           [leaf(r) for r in CHILDREN])
        for site in sites:
            offset=site["prefixes"][0]["offset"]
            width=site["prefixes"][0]["bits"]//8
            assert width in (4,8)
            for i in range(FIXTURES):
                _,_,expected=original_reference(site,i)
                self.assertEqual(expected["rax"],expected_arg(offset,4))
        c=callsite_native_source(sites,[leaf(r) for r in CHILDREN],sites)
        with tempfile.TemporaryDirectory(prefix="mxb-shadow-stack-") as td:
            root=Path(td)
            source=root/"synthetic-stack-args.c"
            source.write_text(c)
            options=["-O2","-std=c11","-Wall","-Wextra","-Werror",
                     "-I",str(ROOT/"arm64-lab"/"runtime")]
            host=root/"host"
            result=subprocess.run(["cc",*options,"-DHOST",str(source),"-o",str(host)],
                                  capture_output=True,text=True)
            self.assertEqual(result.returncode,0,result.stderr[-3000:])
            result=subprocess.run([str(host)],capture_output=True,text=True)
            self.assertEqual(result.returncode,0,result.stderr[-3000:])
            arm=root/"guest-aarch64.elf"
            result=subprocess.run(["clang","--target=aarch64-unknown-linux-gnu",
                "-fuse-ld=lld","-nostdlib","-static","-ffreestanding",
                "-fno-stack-protector","-fno-builtin",*options,
                "-Wl,-e,smoke","-Wl,-z,max-page-size=4096",
                "-Wl,--build-id=none",str(source),"-o",str(arm)],
                capture_output=True,text=True)
            self.assertEqual(result.returncode,0,result.stderr[-3000:])
            run=execute_arm64_elf(arm,instruction_budget=1500000,
                                  timeout_us=15000000)
            self.assertEqual(run["arm64_smoke_exit"],0)

if __name__=="__main__":
    unittest.main()
