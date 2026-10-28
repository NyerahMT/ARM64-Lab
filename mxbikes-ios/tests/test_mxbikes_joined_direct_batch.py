"""Synthetic original CALL→verified leaf joins; test real host and native ARM64 dispatch.

All x64 bytes are fixtures. No owned original game executable is embedded.
"""
from __future__ import annotations
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"scripts"))
from mxbikes_joined_direct_batch import (
    find_joinable, x64_reference, generate_source, FIXTURES,
    execute_arm64_elf, EXE_SHA, ROOT,
)

PARENT=0x200000
CHILD=0x200100
STACK_PREFIX=bytes.fromhex("488d6424d8")
STACK_SUFFIX=bytes.fromhex("488d642428")
CALL_DELTA=CHILD-(PARENT+5+5)
BODY=STACK_PREFIX+b"\xe8"+CALL_DELTA.to_bytes(4,"little",signed=True)+STACK_SUFFIX+b"\xc3"
CHILD_BODY=bytes.fromhex("8bc1c3")


class SyntheticPE:
    def read_rva(self, rva, size):
        rows={PARENT:BODY,CHILD:CHILD_BODY}
        if rva not in rows or size != len(rows[rva]):
            raise ValueError("Synthetic original read outside owned fixture bounds")
        return rows[rva]


def graph():
    return {
        "input_sha256":EXE_SHA,"original_file_verified":True,
        "direct_call_graph":{hex(PARENT):[hex(CHILD)]},
        "interval_map":[
            {"rva":hex(PARENT),"end_rva":hex(PARENT+len(BODY)),
             "bytes":len(BODY),"status":"decoded_linear","instructions":4},
        ],
    }


def native_leaf():
    return {"rva":CHILD, "body":CHILD_BODY,"kind":"mov_eax_ecx_ret",
            "imm":None,"cfg_plan":None, "wave_batch_id":None}


def audit():
    return [{"original_rva":hex(CHILD), "full_function_behavior_verified":True,
             "win64_guest_call_abi_verified":True,
             "code_presence":"ephemeral_ci_elf_only",
             "differential_test_run_url":
                "https://github.com/NyerahMT/ReflexBuildInput/actions/runs/123456"}]


class JoinedNativeCallerTests(unittest.TestCase):
    def test_discovers_exact_original_direct_call_and_ignores_unknown(self):
        self.assertEqual(len(BODY),16)
        candidates,counts=find_joinable(SyntheticPE(),graph(),[native_leaf()],audit())
        self.assertEqual(counts["eligible_complete_flag_preserving_caller"],1)
        self.assertEqual(len(candidates),1)
        self.assertEqual(candidates[0]["child_rva"],CHILD)
        self.assertEqual(candidates[0]["prefix_bytes"],5)
        missing,counts=find_joinable(SyntheticPE(),graph(),[native_leaf()],[])
        self.assertEqual(missing,[])
        unknown=graph()
        unknown["direct_call_graph"]={hex(PARENT):["0x200300"]}
        absent,_=find_joinable(SyntheticPE(),unknown,[native_leaf()],audit())
        self.assertEqual(absent,[])

    def test_rejects_unsupported_or_modified_direct_caller(self):
        bad=graph()
        bad["input_sha256"]="invalid"
        with self.assertRaises(ValueError):
            find_joinable(SyntheticPE(),bad,[native_leaf()],audit())
        with self.assertRaises(ValueError):
            find_joinable(SyntheticPE(),graph(),[native_leaf()],audit(),limit=10000)
        xor_child=native_leaf()
        xor_child["kind"]="xor_eax_eax_ret"
        candidate,_=find_joinable(SyntheticPE(),graph(),[xor_child],audit())
        self.assertEqual(candidate,[])

    def test_original_x64_nested_reference_matches_executed_native_arm64(self):
        candidates,_=find_joinable(SyntheticPE(),graph(),[native_leaf()],audit())
        parent=candidates[0]
        original_cases={child:["unused"] for child in []}
        original_cases[CHILD]=[x64_reference(native_leaf(),i) for i in range(FIXTURES)]
        original_cases[PARENT]=[x64_reference(parent,i) for i in range(FIXTURES)]
        visited=set().union(*(set(t) for t in parent["_joined_traces"]))
        self.assertEqual(visited,{
            PARENT,PARENT+5,PARENT+10,PARENT+15,
            CHILD,CHILD+2,
        })
        source=generate_source([parent,native_leaf()],original_cases)
        self.assertIn("mx_native_link_call(r,s,m",source)
        self.assertIn("link_entries[k].context=&registry",source)
        with tempfile.TemporaryDirectory(prefix="mxb-joined-synthetic-") as td:
            root=Path(td)
            code=root/"synthetic-joined.c"
            code.write_text(source)
            flags=["-O2","-std=c11","-Wall","-Wextra","-Werror",
                   "-I",str(ROOT/"arm64-lab"/"runtime")]
            host=root/"host"
            p=subprocess.run(["cc",*flags,"-DHOST",str(code),"-o",str(host)],
                             capture_output=True,text=True)
            self.assertEqual(p.returncode,0,p.stderr[-2500:])
            p=subprocess.run([str(host)],capture_output=True,text=True)
            self.assertEqual(p.returncode,0,p.stderr[-2500:])
            arm=root/"joined-aarch64.elf"
            p=subprocess.run([
                "clang","--target=aarch64-unknown-linux-gnu","-fuse-ld=lld",
                "-nostdlib","-static","-ffreestanding","-fno-stack-protector",
                "-fno-builtin",*flags,"-Wl,-e,smoke",
                "-Wl,-z,max-page-size=4096","-Wl,--build-id=none",
                str(code),"-o",str(arm)],capture_output=True,text=True)
            self.assertEqual(p.returncode,0,p.stderr[-2500:])
            result=execute_arm64_elf(arm,instruction_budget=900000,
                                    timeout_us=10000000)
            self.assertEqual(result["arm64_smoke_exit"],0)


    def test_three_saved_register_callers_preserve_original_guest_stack(self):
        parents = [(0x200020, 0x53, 0x5b),
                   (0x200040, 0x56, 0x5e),
                   (0x200060, 0x57, 0x5f)]
        rows={}
        for rva,push,pop in parents:
            delta=CHILD-(rva+6)
            rows[rva]=bytes([push,0xe8])+delta.to_bytes(4,"little",signed=True)+bytes([pop,0xc3])
        class SyntheticPushPE:
            def read_rva(self, rva, width):
                body=rows.get(rva)
                if body is None or width!=len(body):
                    raise ValueError("Not an owned synthetic pushed-register body")
                return body
        mapping={
            "input_sha256":EXE_SHA, "original_file_verified":True,
            "direct_call_graph":{hex(rva):[hex(CHILD)] for rva,_,_ in parents},
            "interval_map":[{"rva":hex(rva),"end_rva":hex(rva+8),
                             "status":"decoded_linear","bytes":8,
                             "instructions":4} for rva,_,_ in parents],
        }
        candidates,counts=find_joinable(
            SyntheticPushPE(),mapping,[native_leaf()],audit())
        self.assertEqual(len(candidates),3)
        self.assertEqual({c["saved_register"] for c in candidates},
                         {"rbx","rsi","rdi"})
        references={CHILD:[x64_reference(native_leaf(),i)
                           for i in range(FIXTURES)]}
        for parent in candidates:
            references[parent["rva"]]=[
                x64_reference(parent,i) for i in range(FIXTURES)]
            self.assertTrue(all(
                len(expected["joined_stack_window"])==64
                for _,_,expected in references[parent["rva"]]))
        source=generate_source(candidates+[native_leaf()],references)
        self.assertIn("expected_stack[64]",source)
        with tempfile.TemporaryDirectory(prefix="mxb-push-joined-native-") as td:
            root=Path(td)
            code=root/"original-synthetic-push.c"
            code.write_text(source)
            flags=["-O2","-std=c11","-Wall","-Wextra","-Werror",
                   "-I",str(ROOT/"arm64-lab"/"runtime")]
            host=root/"host"
            run=subprocess.run(["cc",*flags,"-DHOST",str(code),"-o",str(host)],
                               capture_output=True,text=True)
            self.assertEqual(run.returncode,0,run.stderr[-3000:])
            run=subprocess.run([str(host)],capture_output=True,text=True)
            self.assertEqual(run.returncode,0,run.stderr[-3000:])
            arm=root/"native-aarch64.elf"
            run=subprocess.run([
                "clang","--target=aarch64-unknown-linux-gnu","-fuse-ld=lld",
                "-nostdlib","-static","-ffreestanding","-fno-stack-protector",
                "-fno-builtin",*flags,"-Wl,-e,smoke",
                "-Wl,-z,max-page-size=4096","-Wl,--build-id=none",
                str(code),"-o",str(arm)],capture_output=True,text=True)
            self.assertEqual(run.returncode,0,run.stderr[-3000:])
            result=execute_arm64_elf(arm,instruction_budget=1600000,
                                    timeout_us=12000000)
            self.assertEqual(result["arm64_smoke_exit"],0)


if __name__=="__main__":
    unittest.main()
