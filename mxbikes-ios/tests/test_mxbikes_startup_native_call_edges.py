"""Original x64 startup call graph planner, never a native completion proof."""
from pathlib import Path
import sys,unittest

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"scripts"))
from mxbikes_startup_native_call_edges import classify_original_startup_calls

BASE=0x140000000

class FakePE:
    def __init__(self,contents):self.contents=contents
    def read_rva(self,entry,length):
        if entry not in self.contents:raise ValueError("Original interval not mapped")
        item=self.contents[entry]
        if len(item)!=length:raise ValueError("Original interval length mismatch")
        return item

def row(addr,code):
    return {"original_function_entry_rva":hex(addr),
            "original_unwind_end_rva":hex(addr+len(code)),
            "post_main_instruction_hits":40}

class StartupNativeCallEdges(unittest.TestCase):
    def test_actual_direct_and_rip_iat_and_unresolved_indirect_edges(self):
        # direct CALL 0x1010 then RIP-relative CALL to IAT slot 0x1020.
        one=bytes.fromhex("e80b000000ff1515000000c3")
        two=bytes.fromhex("ffd0c3")
        pe=FakePE({0x1000:one,0x2000:two})
        p={"prioritized_original_functions":[row(0x1000,one),row(0x2000,two)]}
        result=classify_original_startup_calls(
            pe,p,[(0x1020,"KERNEL32.dll","GetStartupInfoA")],base=BASE)
        self.assertEqual(result["original_function_windows_examined"],2)
        self.assertEqual(result["functions_with_original_direct_calls"],1)
        self.assertEqual(result["functions_with_original_IAT_imports"],1)
        a,b=result["startup_original_function_dependencies"]
        self.assertEqual(a["direct_original_callee_rvas"],["0x1010"])
        self.assertEqual(a["named_iat_imports"],["KERNEL32.dll::GetStartupInfoA"])
        self.assertEqual(b["call_edge_classes"]["unresolved_indirect_CALL"],1)
        self.assertFalse(a["native_function_verified"])
        self.assertEqual(result["native_ARM64_original_functions_verified_by_this_scan"],0)
        self.assertFalse(result["steamworks_authorization_bypassed"])

    def test_authorization_is_external_boundary_not_fake_native_callee(self):
        code=bytes.fromhex("ff150a000000c3")
        result=classify_original_startup_calls(
            FakePE({0x3000:code}),
            {"prioritized_original_functions":[row(0x3000,code)]},
            [(0x3010,"steam_api64.dll","SteamAPI_RestartAppIfNecessary")],base=BASE)
        info=result["startup_original_function_dependencies"][0]
        self.assertEqual(info["call_edge_classes"],{
            "Steamworks_authorization_external":1})
        self.assertFalse(info["native_function_verified"])

    def test_fail_closed_on_bad_original_inputs(self):
        missing=classify_original_startup_calls(FakePE({}),
            {"prioritized_original_functions":[row(1,b"x")]},[],
            base=BASE)
        self.assertEqual(
            missing["startup_original_function_dependencies"][0]["status"],
            "original_unwind_window_unreadable")
        self.assertFalse(
            missing["startup_original_function_dependencies"][0]["native_function_verified"])
        code=b"\xc3"
        with self.assertRaises(ValueError):
            classify_original_startup_calls(FakePE({0x1000:code}),
                {"prioritized_original_functions":[row(0x1000,code)]},
                [(0x1020,"A","b"),(0x1020,"C","d")],base=BASE)
        with self.assertRaises(ValueError):
            classify_original_startup_calls(FakePE({}),
                {"prioritized_original_functions":[]},[(i,"A","b")
                 for i in range(4097)],base=BASE)

if __name__=="__main__":
    unittest.main()
