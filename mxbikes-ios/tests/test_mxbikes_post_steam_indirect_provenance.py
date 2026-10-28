"""Synthetic x64 provenance regression. Never execute Steam or original game."""
import struct
import sys
import unittest
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"scripts"))
from mxbikes_post_steam_indirect_provenance import analyze,static_paths

CALL=0x1000
RETURN=0x1006
INIT_SLOT=0x3008
CONTEXT_SLOT=0x3010
STEAM_SLOT=0x3000
BASE=0x140000000

def iat_call(pc,slot):
    return b"\xff\x15"+struct.pack("<i",slot-(pc+6))

class OriginalShape:
    def __init__(self, *,mode="register",corrupt=False):
        head = iat_call(CALL,STEAM_SLOT)
        init = iat_call(RETURN,INIT_SLOT)
        move = b"\x48\x89\xc3" # mov rbx,rax (callee-saved across future call)
        context = iat_call(RETURN+len(init)+len(move),CONTEXT_SLOT)
        prefix = head + init + move + context
        self.target=CALL+len(prefix)
        if mode=="register":
            self.target+=4
            body=b"\x48\x8b\x43\x10" + b"\xff\xd0" # mov rax,[rbx+16];call rax
        elif mode=="memory":
            body=b"\xff\x53\x10"  # call qword ptr [rbx+16]
        elif mode=="unknown":
            body=b"\x41\xff\xd2"  # call r10, no preceding definition
        else:
            raise ValueError("Unknown test shape")
        if corrupt:prefix=b"\x90"+prefix[1:]
        self.code=prefix+body+b"\xc3"
        self.memory={0x80:struct.pack("<III",CALL,CALL+len(self.code),0),
                     CALL:self.code}
    def directory(self,number):
        assert number==3
        return 0x80,12
    def read_rva(self,start,size):
        for addr,data in self.memory.items():
            if addr<=start and start+size<=addr+len(data):
                return data[start-addr:start-addr+size]
        raise ValueError("Unmapped synthetic original code")

def inspect(pe):
    return analyze(pe,[
        (STEAM_SLOT,"steam_api64.dll","SteamAPI_RestartAppIfNecessary"),
        (INIT_SLOT,"steam_api64.dll","SteamAPI_Init"),
        (CONTEXT_SLOT,"steam_api64.dll","SteamInternal_ContextInit"),
    ],base=BASE,call_rva=CALL,return_rva=RETURN,target_rva=pe.target,
    expected_slot=STEAM_SLOT,
    expected_symbol=("steam_api64.dll","SteamAPI_RestartAppIfNecessary"))

class IndirectProvenanceTests(unittest.TestCase):
    def test_register_indirect_resolves_load_source_not_dynamic_target(self):
        rep=inspect(OriginalShape())
        self.assertEqual(rep["bounded_possible_paths"],1)
        self.assertEqual(rep["unique_provenance_variants"],1)
        t=rep["candidate_provenances"][0]
        self.assertEqual(t["target_operand"]["type"],"register")
        self.assertEqual(t["target_operand"]["register"],"rax")
        move=t["target_provenance"]
        self.assertEqual(move["source"]["kind"],"guest_memory_load")
        self.assertEqual(move["source"]["memory"]["base"],"rbx")
        self.assertEqual(move["source"]["memory"]["displacement"],16)
        # The RBX source ultimately came from an *unknown* Steam init result.
        origin=move["source"]["base_origin"]
        self.assertEqual(origin["source"]["source"]["kind"],"unobserved_call_result")
        self.assertEqual(origin["source"]["source"]["symbol"],"SteamAPI_Init")
        self.assertTrue(rep["all_prior_calls_hypothetical"])
        self.assertFalse(rep["actual_indirect_target_resolved"])
        self.assertFalse(rep["native_engine_execution_verified"])

    def test_memory_indirect_preserves_unverified_base_source(self):
        rep=inspect(OriginalShape(mode="memory"))
        origin=rep["candidate_provenances"][0]["target_provenance"]
        self.assertEqual(origin["kind"],"indirect_memory_target")
        self.assertEqual(origin["memory"]["base"],"rbx")
        self.assertEqual(origin["memory"]["displacement"],16)
        self.assertEqual(origin["base_origin"]["source"]["source"]["symbol"],"SteamAPI_Init")

    def test_uninitialized_register_remains_unproven(self):
        rep=inspect(OriginalShape(mode="unknown"))
        source=rep["candidate_provenances"][0]["target_provenance"]
        self.assertEqual(source,{"kind":"call_clobbered","site_rva":"0x100f"})
        # r10 is caller-volatile: unknown after the external call, not a stable entry value.
        self.assertFalse(rep["actual_indirect_target_resolved"])

    def test_wrong_original_steam_call_opcode_is_rejected(self):
        with self.assertRaises(ValueError):
            inspect(OriginalShape(corrupt=True))

    def test_unknown_stream_target_and_faked_iat_are_rejected(self):
        pe=OriginalShape()
        with self.assertRaises(ValueError):
            analyze(pe,[(STEAM_SLOT,"steam_api64.dll","SteamAPI_Init")],
                    base=BASE,call_rva=CALL,return_rva=RETURN,
                    target_rva=pe.target,expected_slot=STEAM_SLOT,
                    expected_symbol=("steam_api64.dll","SteamAPI_RestartAppIfNecessary"))

if __name__=="__main__":
    unittest.main()
