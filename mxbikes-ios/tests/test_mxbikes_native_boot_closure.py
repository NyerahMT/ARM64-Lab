"""Real-call graph closure ordering tests with synthetic x64 instruction bytes."""
from pathlib import Path
import sys
import unittest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"scripts"))
from mxbikes_native_boot_closure import analyze_native_boot_closure,_scc

BASE=0x140000000
A=0x1000
B=0x1100
C=0x1200
D=0x1300
IAT_WIN=0x3000
IAT_STEAM=0x3008
SIZE=32

def direct(frm,to):
    return b"\xe8"+(to-(frm+5)).to_bytes(4,"little",signed=True)

def indirect_iat(frm,slot):
    return b"\xff\x15"+(slot-(frm+6)).to_bytes(4,"little",signed=True)

def fill(blob):
    if len(blob)>SIZE:raise ValueError("Oversized synthetic x64 function")
    return blob+b"\x90"*(SIZE-len(blob))

class OriginalPE:
    def __init__(self,functions):
        self.functions=functions
    def read_rva(self,rva,size):
        if rva not in self.functions:raise ValueError("unknown synthetic original RVA")
        if len(self.functions[rva])!=size:raise ValueError("unexpected size")
        return self.functions[rva]

def mapping():
    code_a=(direct(A,B)+direct(A+5,C)+direct(A+10,D)+b"\xc3")
    code_b=(direct(B,A)+b"\xc3")
    code_c=b"\xc3"
    code_d=(indirect_iat(D,IAT_WIN)+indirect_iat(D+6,IAT_STEAM)+
            b"\xff\xd0"+b"\xc3")
    pe=OriginalPE({A:fill(code_a),B:fill(code_b),
                   C:fill(code_c),D:fill(code_d)})
    unwind={x:x+SIZE for x in (A,B,C,D)}
    priority={"prioritized_original_functions":[{"original_function_entry_rva":hex(A)}]}
    imports=[(IAT_WIN,"KERNEL32.dll","GetStartupInfoA"),
             (IAT_STEAM,"steam_api64.dll","SteamAPI_RestartAppIfNecessary")]
    return pe,unwind,priority,imports

def run(**args):
    pe,unwind,priority,imports=mapping()
    return analyze_native_boot_closure(pe,unwind,priority,imports,base=BASE,**args)

class OriginalBootDependencyClosureTests(unittest.TestCase):
    def test_full_transitive_original_graph_cycles_and_real_import_boundaries(self):
        x=run()
        self.assertEqual(x["observed_x64_seed_functions"],1)
        self.assertEqual(x["reachable_original_functions_inspected"],4)
        self.assertEqual(x["complete_linear_callsite_windows"],4)
        self.assertEqual(x["direct_original_CALL_edges"],4)
        self.assertEqual(x["named_original_import_dependencies"],2)
        self.assertEqual(x["steamworks_external_dependencies"],1)
        self.assertEqual(x["unresolved_indirect_CALL_sites"],1)
        self.assertEqual(x["original_call_cycle_components"],1)
        self.assertFalse(x["closure_truncated"])
        self.assertEqual(x["actual_original_arm64_functions_native_verified_by_this_pass"],0)
        self.assertFalse(x["steam_authorization_bypassed"])
        self.assertFalse(x["complete_boot_runtime_or_auth_closure"])
        self.assertTrue(x["all_original_direct_calls_closed_to_known_unwind_entries"])
        self.assertEqual(x["foundational_translation_batch_count"],1)
        self.assertEqual(
            x["topological_native_translation_batches"][
                x["foundational_no_call_no_import_translation_batch_indices"][0]
            ]["original_function_entry_rvas"],[hex(C)])
        batches=x["topological_native_translation_batches"]
        by_function={int(s,16):i for i,b in enumerate(batches)
                     for s in b["original_function_entry_rvas"]}
        self.assertEqual(by_function[A],by_function[B])
        self.assertTrue(batches[by_function[A]]["original_call_cycle"])
        self.assertLess(by_function[C],by_function[A])
        self.assertLess(by_function[D],by_function[A])
        self.assertEqual(batches[by_function[D]]["blockers"]["Steamworks_external"],1)
        self.assertEqual(batches[by_function[D]]["blockers"]["Windows_CRT_external"],1)
        self.assertEqual(batches[by_function[D]]["blockers"]["unknown_indirect_CALL"],1)
        self.assertEqual(len(x["per_original_function"][hex(A)]["direct_original_callee_entries"]),3)

    def test_closure_depth_limit_does_not_fake_coverage(self):
        x=run(max_depth=0)
        self.assertTrue(x["closure_truncated"])
        self.assertFalse(x["all_original_direct_calls_closed_to_known_unwind_entries"])
        self.assertEqual(x["reachable_original_functions_inspected"],1)
        self.assertEqual(x["unvisited_required_original_callees"],
                         [hex(y) for y in (B,C,D)])
        self.assertFalse(x["topological_native_translation_batches"][0]["fully_translated_to_native_arm64"])

    def test_strict_bounds_and_unwind_ownership(self):
        pe,unwind,priority,imports=mapping()
        with self.assertRaises(ValueError):
            analyze_native_boot_closure(pe,unwind,priority,imports,
                                         base=BASE,max_depth=99)
        with self.assertRaises(ValueError):
            analyze_native_boot_closure(pe,{A:A+0x120,B:B+32},
                                         priority,imports,base=BASE)
        with self.assertRaises(ValueError):
            analyze_native_boot_closure(pe,unwind,
                {"prioritized_original_functions":[{"original_function_entry_rva":"0x1001"}]},
                imports,base=BASE)
        with self.assertRaises(ValueError):
            analyze_native_boot_closure(pe,unwind,priority,
                imports+[(IAT_WIN,"OTHER.dll","SameSlot")],base=BASE)

    def test_scc_merge_and_condensation(self):
        self.assertIn((1,2),_scc({1:{2},2:{1},3:{2}}))
        self.assertIn((3,),_scc({1:{2},2:{1},3:{2}}))

if __name__=="__main__":
    unittest.main()
