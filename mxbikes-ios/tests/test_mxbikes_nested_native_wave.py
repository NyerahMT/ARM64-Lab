"""Synthetic whole original Win64 CALL -> callee -> RET ARM64 equivalence."""
from pathlib import Path
import sys
import unittest

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"scripts"))
import mxbikes_nested_native_wave as wave
from mxbikes_whole_game_map import INPUT_SHA

TARGET=0x220800
LEAF=bytes.fromhex("8bc1c3")  # mov eax,ecx; ret
CHILD={"rva":TARGET,"body":LEAF,"kind":"mov_eax_ecx_ret"}
BODIES=[
    # push rbx; call child; pop rbx; ret -- stack aligned across CALL
    ("53", "5bc3"),
    # sub rsp, 40; call child; add rsp, 40; ret
    ("4883ec28", "4883c428c3"),
    # preserve one argument in Win64 32-byte caller shadow allocation
    ("4883ec2848894c2420", "488b4424204883c428c3"),
    # modify register, call, then overwrite RAX from another source
    ("534889d9", "4889c85bc3"),
    # test ZF/CF before call, then preserve Win64 call stack
    ("4885c953", "5bc3"),
    # DEC preserves CF; ADD and CMP update CF/ZF/SF.
    ("5348ffc9", "5bc3"),
    ("534883c105", "5bc3"),
    ("534883f905", "5bc3"),
    ("534883e10f", "5bc3"),
]
BEGIN=0x221000

def caller(i,parts):
    before,after=parts
    start=BEGIN+i*0x100
    lead=bytes.fromhex(before)
    tail=bytes.fromhex(after)
    continuation=start+len(lead)+5
    disp=TARGET-continuation
    return start,lead+b"\xe8"+disp.to_bytes(4,"little",signed=True)+tail

class JoinedNativeDifferentialTests(unittest.TestCase):
    def setUp(self):
        self.child=dict(CHILD,statements=wave.decode_supported_leaf(CHILD))
        self.assertIsNotNone(self.child["statements"])

    def test_translates_batched_complete_function_instruction_families(self):
        for i,shape in enumerate(BODIES):
            rva,code=caller(i,shape)
            with self.subTest(case=i):
                item,why=wave.parse_parent(code,rva,{TARGET:self.child})
                self.assertIsNone(why)
                self.assertEqual(item["rva"],rva)
                self.assertEqual(item["child_rva"],TARGET)
                self.assertEqual(item["boundary"],"exact_original_pdata_parent_full_body")
        self.assertIsNone(wave.decode_supported_leaf(
            {"rva":TARGET,"body":bytes.fromhex("e800000000c3")}))

    def test_original_x64_vs_host_and_true_executed_native_aarch64(self):
        cases=[]
        refs={}
        for i,body in enumerate(BODIES):
            rva,code=caller(i,body)
            item,why=wave.parse_parent(code,rva,{TARGET:self.child})
            self.assertIsNone(why)
            results=[]
            for k in range(wave.FIXTURES):
                actual,reason=wave.x64_reference(item,self.child,k)
                self.assertIsNone(reason,reason)
                results.append(actual)
            refs[rva]=results
            cases.append(item)
        wave.compile_batch(cases,{TARGET:self.child},refs)

    def test_native_tail_call_jumps_to_verified_leaf_and_returns_to_outer_caller(self):
        rva=0x224000
        prefix_bytes=bytes.fromhex("535b") # push+pop restore Win64 entry RSP
        continuation=rva+len(prefix_bytes)+5
        disp=TARGET-continuation
        code=prefix_bytes+b"\xe9"+disp.to_bytes(4,"little",signed=True)
        item,why=wave.parse_parent(code,rva,{TARGET:self.child})
        self.assertIsNone(why)
        self.assertEqual(item["native_exit"],"tail_jump")
        original=[]
        for k in range(wave.FIXTURES):
            fixture,error=wave.x64_reference(item,self.child,k)
            self.assertIsNone(error)
            original.append(fixture)
        wave.compile_batch([item],{TARGET:self.child},{rva:original})

    def test_multi_leaf_call_chain_executes_complete_original_x64_and_native(self):
        other_rva=TARGET+0x100
        other={"rva":other_rva,"body":bytes.fromhex("89c2c3"),
               "kind":"mov_edx_eax_ret"}
        other=dict(other,statements=wave.decode_supported_leaf(other))
        self.assertIsNotNone(other["statements"])
        rva=0x223800
        def direct_call(pc,dest):
            return b"\xe8"+(dest-(pc+5)).to_bytes(4,"little",signed=True)
        prefix_bytes=bytes.fromhex("53")
        first=direct_call(rva+len(prefix_bytes),TARGET)
        gap=b"\x90"
        second=direct_call(rva+len(prefix_bytes)+len(first)+len(gap),other_rva)
        code=prefix_bytes+first+gap+second+bytes.fromhex("5bc3")
        children={TARGET:self.child,other_rva:other}
        parent,why=wave.parse_parent(code,rva,children)
        self.assertIsNone(why,why)
        self.assertEqual(parent["original_direct_calls"],2)
        self.assertEqual(parent["child_rvas"],[TARGET,other_rva])
        all_cases=[]
        for case in range(wave.FIXTURES):
            sample,reason=wave.x64_reference(parent,children,case)
            self.assertIsNone(reason,reason)
            all_cases.append(sample)
        wave.compile_batch([parent],children,{rva:all_cases})
        # Multiple calls are not admissible if even one target is unverified.
        rejected,reason=wave.parse_parent(code,rva,{TARGET:self.child})
        self.assertIsNone(rejected)
        self.assertEqual(reason,"unverified_direct_callee")

    def test_multi_call_capped_no_fabricated_children(self):
        rva=0x224800
        head=bytes.fromhex("53")
        for _ in range(wave.MAX_PARENT_CALLS+1):
            pos=rva+len(head)
            head+=b"\xe8"+(TARGET-(pos+5)).to_bytes(4,"little",signed=True)
        body=head+bytes.fromhex("5bc3")
        item,reason=wave.parse_parent(body,rva,{TARGET:self.child})
        self.assertIsNone(item)
        self.assertEqual(reason,"original_direct_call_count_outside_verified_budget")

    def test_missing_callee_indirect_calls_and_branches_refused(self):
        rva,code=caller(0,BODIES[0])
        for eligible in ({}, {TARGET+0x10:self.child}):
            item,why=wave.parse_parent(code,rva,eligible)
            self.assertIsNone(item)
            self.assertEqual(why,"unverified_direct_callee")
        for raw in [bytes.fromhex("53 ffd0 5bc3"),
                    bytes.fromhex("53 7502 9090 5bc3"),
                    bytes.fromhex("53 e800000000 e800000000 5bc3")]:
            item,why=wave.parse_parent(raw,0x222000,{0x222006:self.child})
            self.assertIsNone(item)

    def test_post_native_sweep_relinks_original_short_proven_callee(self):
        addr=0x230000
        data=bytes.fromhex("8bc1c3")
        class FakePE:
            def read_rva(self,rva,size):
                if not addr<=rva or rva+size>addr+len(data):
                    raise ValueError("Unmapped exact source bytes")
                return data[rva-addr:rva-addr+size]
        mapping={
            "input_sha256":INPUT_SHA,"original_file_verified":True,
            "interval_map":[{"rva":"0x240000","end_rva":"0x240020"}],
            "unwindless_direct_call_candidates":[{
                "rva":hex(addr),"unwind_protected":False,
                "static_first_block_verified":True,"direct_call_references":1
            }]}
        proof={
            "original_rva":hex(addr),"native_symbol":f"mx_unwindless_native_{addr:08x}",
            "original_direct_CALL_entry_without_pdata":True,
            "full_function_behavior_verified":True,
            "win64_guest_call_abi_verified":True,
            "code_presence":"ephemeral_ci_elf_only",
            "differential_test_run_url":
                "https://github.com/NyerahMT/ReflexBuildInput/actions/runs/12345"
        }
        leaves,rejected=wave.reconstruct_same_run_unwindless_leaves(
            FakePE(),mapping,[proof])
        self.assertEqual(len(leaves),1)
        self.assertEqual(leaves[0]["body"],data)
        self.assertFalse(rejected)
        parent_rva=0x220000
        pre=bytes.fromhex("53")
        direct=b"\xe8"+(addr-(parent_rva+1+5)).to_bytes(4,"little",signed=True)
        parent,reason=wave.parse_parent(pre+direct+bytes.fromhex("5bc3"),
                                        parent_rva,{addr:leaves[0]})
        self.assertIsNone(reason,reason)
        fixtures=[]
        for case in range(wave.FIXTURES):
            result,error=wave.x64_reference(parent,leaves[0],case)
            self.assertIsNone(error,error)
            fixtures.append(result)
        wave.compile_batch([parent],{addr:leaves[0]},{parent_rva:fixtures})
        corrupted={**proof,"native_symbol":"mx_unwindless_native_ffffffff"}
        rejected_leaves,counts=wave.reconstruct_same_run_unwindless_leaves(
            FakePE(),mapping,[corrupted])
        self.assertEqual(rejected_leaves,[])
        self.assertEqual(counts["invalid_prior_original_arm64_proof"],1)
        with self.assertRaises(ValueError):
            wave.reconstruct_same_run_unwindless_leaves(
                FakePE(),mapping,[proof,proof])

    def test_discovery_entire_parent_not_one_prefix(self):
        rva,code=caller(1,BODIES[1])
        class SyntheticPE:
            def read_rva(self,start,size):
                self_addr={rva:code,TARGET:LEAF}
                return self_addr[start][:size]
        mapping={
            "original_file_verified":True,"input_sha256":INPUT_SHA,
            "interval_map":[{
                "rva":hex(rva),"status":"decoded_linear","bytes":len(code)
            }],
            "direct_call_graph":{hex(rva):[hex(TARGET)]}
        }
        manifest=[{
            "original_rva":hex(TARGET),
            "full_function_behavior_verified":True,
            "win64_guest_call_abi_verified":True,
            "code_presence":"ephemeral_ci_elf_only",
        }]
        parents,children,reasons,num=wave.discover(
            SyntheticPE(),mapping,[CHILD],manifest)
        self.assertEqual(num,1)
        self.assertEqual(len(parents),1)
        self.assertEqual(len(children),1)
        self.assertEqual(sum(reasons.values()),0)
        with self.assertRaises(ValueError):
            wave.discover(SyntheticPE(),{"input_sha256":"bad"},[CHILD],manifest)

if __name__=="__main__":
    unittest.main()
