"""Synthetic full original x64 CALL-site -> leaf vs native ARM64 dispatch tests."""
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"scripts"))
from mxbikes_native_callsite_batch import (
    discover_original_call_sites,original_reference,callsite_native_source,
    execute_arm64_elf,FIXTURES,ROOT,EXE_SHA
)

PARENT=0x200000
TARGET=0x200100
CALL=PARENT+2
DELTA=TARGET-(CALL+5)
PARENT_BODY=b"\x90\x90\xe8"+DELTA.to_bytes(4,"little",signed=True)+b"\xc3"
CHILD_BODY=bytes.fromhex("8bc1c3")


def leaf():
    return {"rva":TARGET,"body":CHILD_BODY,"kind":"mov_eax_ecx_ret",
            "imm":None,"cfg_plan":None,"wave_batch_id":None}


class OwnedSynthetic:
    def read_rva(self,addr,size):
        data={PARENT:PARENT_BODY,TARGET:CHILD_BODY}.get(addr)
        if data is None or len(data)!=size:
            raise ValueError("Synthetic original read outside fixture")
        return data


def mapping():
    return {
        "input_sha256":EXE_SHA,"original_file_verified":True,
        "direct_call_graph":{hex(PARENT):[hex(TARGET)]},
        "interval_map":[{"rva":hex(PARENT),"end_rva":hex(PARENT+len(PARENT_BODY)),
                         "status":"decoded_linear","bytes":len(PARENT_BODY),
                         "instructions":4}],
    }


class OriginalCallsiteNativeTests(unittest.TestCase):
    def test_exact_original_call_edge_detected_and_fail_closed(self):
        sites=discover_original_call_sites(OwnedSynthetic(),mapping(),[leaf()])
        self.assertEqual(len(sites),1)
        self.assertEqual(sites[0]["callsite_rva"],CALL)
        self.assertEqual(sites[0]["target_rva"],TARGET)
        self.assertFalse(sites[0]["parent_function_native_complete"])
        self.assertEqual(discover_original_call_sites(OwnedSynthetic(),mapping(),[]),[])
        altered=mapping()
        altered["original_file_verified"]=False
        with self.assertRaises(ValueError):
            discover_original_call_sites(OwnedSynthetic(),altered,[leaf()])
        self.assertEqual(discover_original_call_sites(OwnedSynthetic(),mapping(),[leaf()],limit=0),[])

    def test_authentic_direct_call_x64_host_native_arm64_match(self):
        sites=discover_original_call_sites(OwnedSynthetic(),mapping(),[leaf()])
        self.assertEqual(len(sites),1)
        for case in range(FIXTURES):
            seed,flags,ref=original_reference(sites[0],case)
            self.assertEqual(ref["rip"],0x140000000+CALL+5)
            self.assertEqual(ref["rsp"],0x710000000+0x8000)
        source=callsite_native_source(sites,[leaf()],sites)
        self.assertIn("original_edge_fixture",source)
        with tempfile.TemporaryDirectory(prefix="mxb-authentic-callsite-") as td:
            root=Path(td)
            code=root/"original-callsite-synthetic.c"
            code.write_text(source)
            flags=["-O2","-std=c11","-Wall","-Wextra","-Werror",
                   "-I",str(ROOT/"arm64-lab"/"runtime")]
            host=root/"host"
            result=subprocess.run(["cc",*flags,"-DHOST",str(code),"-o",str(host)],
                                  capture_output=True,text=True)
            self.assertEqual(result.returncode,0,result.stderr[-3000:])
            result=subprocess.run([str(host)],capture_output=True,text=True)
            self.assertEqual(result.returncode,0,result.stderr[-3000:])
            arm=root/"native-aarch64.elf"
            result=subprocess.run(["clang","--target=aarch64-unknown-linux-gnu",
                "-fuse-ld=lld","-nostdlib","-static","-ffreestanding",
                "-fno-stack-protector","-fno-builtin",*flags,"-Wl,-e,smoke",
                "-Wl,-z,max-page-size=4096","-Wl,--build-id=none",
                str(code),"-o",str(arm)],capture_output=True,text=True)
            self.assertEqual(result.returncode,0,result.stderr[-3000:])
            verified=execute_arm64_elf(arm,instruction_budget=900000,
                                       timeout_us=10000000)
            self.assertEqual(verified["arm64_smoke_exit"],0)


if __name__=="__main__":
    unittest.main()
