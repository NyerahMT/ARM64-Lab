"""Full original-function native compiler tests with synthetic only x64 bytes."""
from pathlib import Path
import sys
import unittest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"scripts"))
import mxbikes_whole_function_factory as factory
from mxbikes_whole_game_map import INPUT_SHA

SHAPES={
    0x220000:bytes.fromhex("53 4883ec20 4889d9 31c0 4883c420 5b c3"),
    0x220100:bytes.fromhex("4883ec28 48894c2420 488b442420 4883c428 c3"),
    0x220200:bytes.fromhex("4883ec28 488d6c2420 488b4500 4883c428 c3"),
    0x220300:bytes.fromhex("4885c9 4889ca c3"),
    0x220400:bytes.fromhex("488d6424d8 488d642428 c3"),
    0x220500:bytes.fromhex("4889c8 c3"),
}

class FakePE:
    def read_rva(self,rva,size):
        return SHAPES[rva][:size]

def synthetic_item(rva,body):
    item,reason=factory.whole_candidate(body,rva,len(body))
    if reason is not None:
        raise AssertionError(reason)
    return item

class OriginalWholeFunctionFactoryTests(unittest.TestCase):
    def test_complete_function_ends_with_exact_guest_return(self):
        for addr,body in SHAPES.items():
            with self.subTest(rva=hex(addr)):
                item=synthetic_item(addr,body)
                self.assertEqual(item["boundary"],"exact_original_pdata_interval")
                self.assertEqual(item["callsite"],factory.SENTINEL)
                self.assertTrue(item["complete_function"])
                self.assertGreater(item["insns"],1)

    def test_rejects_early_ret_calls_and_control(self):
        invalid=[
            bytes.fromhex("4889c8 c3 90"),
            bytes.fromhex("4889c8 e800000000 c3"),
            bytes.fromhex("4889c8 7501 90 c3"),
            bytes.fromhex("488b01 c3"),
            bytes.fromhex("4889c8 ffd0 c3"),
        ]
        for blob in invalid:
            item,reason=factory.whole_candidate(blob,0x300000,len(blob))
            self.assertIsNone(item)
            self.assertIsNotNone(reason)

    def test_guards_stack_balance_and_unsafe_uncompared_memory(self):
        # Plain RET after a synthetic uncompensated stack allocation is not
        # a full callable Win64 function; refuse it before native promotion.
        bad=bytes.fromhex("4883ec28 c3")
        item,why=factory.whole_candidate(bad,0x230000,len(bad))
        self.assertIsNone(item)
        self.assertEqual(why,"original_function_stack_not_statistically_restored")
        # Original base frame pointer was never proven to equal guest RSP.
        invalid=bytes.fromhex("488b4500 c3")
        item,why=factory.whole_candidate(invalid,0x230100,len(invalid))
        self.assertIsNone(item)
        self.assertEqual(why,"guest_memory_outside_compared_window")

    def test_inventory_sweeps_all_pdata_intervals_and_skips_existing(self):
        mapping={
            "original_file_verified":True,"input_sha256":INPUT_SHA,
            "interval_map":[
                {"rva":hex(rva),"bytes":len(body),"status":"decoded_linear",
                 "ret_count":1,"direct_calls":0,"indirect_calls":0,
                 "import_thunk_calls":0,"internal_branches":0,
                 "escaping_branches":0,"indirect_jumps":0}
                for rva,body in SHAPES.items()
            ],
            "direct_call_graph":{"0x136710":[hex(x) for x in SHAPES]},
        }
        proofs=[{"original_rva":"0x220100",
                 "full_function_behavior_verified":True,
                 "win64_guest_call_abi_verified":True}]
        sel,blocked,total=factory.iter_whole_candidates(FakePE(),mapping,proofs)
        self.assertEqual(total,6)
        self.assertEqual(len(sel),5)
        self.assertEqual(blocked["already_whole_native_verified"],1)
        with self.assertRaises(ValueError):
            factory.iter_whole_candidates(FakePE(),{"input_sha256":"bad"})

    def test_original_win64_entire_returns_match_executed_native_arm64(self):
        selected=[synthetic_item(rva,blob) for rva,blob in SHAPES.items()]
        refs={}
        for item in selected:
            references=[factory.original_full_reference(item,k)
                        for k in range(factory.FULL_FIXTURES)]
            self.assertTrue(all(sample is not None for sample in references))
            refs[item["rva"]]=references
        factory.compile_and_execute(selected,refs)

    def test_failed_native_batch_bisects_and_never_promotes_failure(self):
        original=[{"rva":v} for v in range(11)]
        seen=[]
        def checker(batch,refs):
            seen.append(tuple(v["rva"] for v in batch))
            if any(v["rva"]==7 for v in batch):
                raise RuntimeError("arm64_differential_error: synthetic mismatch")
        passed,failed,jobs=factory.verify_wave(original,{},checker=checker)
        self.assertEqual(len(passed),10)
        self.assertEqual(failed,[{"rva":"0x7","reason":"arm64_differential_error"}])
        self.assertGreater(jobs["failed_batches_recursively_split"],0)
        self.assertNotIn(7,{v["rva"] for v in passed})

if __name__=="__main__":
    unittest.main()
