"""Synthetic Windows x64 .pdata/.xdata plus real Unicorn prologue verification.

No original MX Bikes instructions or owned executable bytes are embedded.
"""
from pathlib import Path
import struct
import sys
import unittest

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"scripts"))
from mxbikes_win64_unwind_frame import (
    pdata_index,decode_unwind,validate_prologue,analyze,INPUT_SHA
)

PARENT=0x200000
CHILD=0x200800
META=0x6000
PDATA=0x5000
# push rbp ; sub rsp, 0x20 ; lea rbp, [rsp+0x20] ; ret
PROLOG=bytes.fromhex("55 4883ec20 488d6c2420")
GOOD_BODY=PROLOG+b"\xc3"
# Windows unwind codes: SET_FPREG at 10, ALLOC_SMALL 32 at 5, PUSH RBP at 1.
XDATA=bytes([1,len(PROLOG),3,0x25,10,3,5,0x32,1,0x50])


class SyntheticPE:
    def __init__(self,body=GOOD_BODY,xdata=XDATA):
        self.body=body
        self.xdata=xdata
        self.pdata=struct.pack("<III",PARENT,PARENT+len(body),META)

    def directory(self,index):
        assert index==3
        return PDATA,len(self.pdata)

    def read_rva(self,rva,size):
        for base,data in ((PDATA,self.pdata),(META,self.xdata),(PARENT,self.body)):
            pos=rva-base
            if 0<=pos<=len(data) and 0<=size<=len(data)-pos:
                return data[pos:pos+size]
        raise ValueError("Unknown synthetic original RVA")


def mapping():
    return {"input_sha256":INPUT_SHA, "original_file_verified":True,
            "direct_call_graph":{hex(PARENT):[hex(CHILD)]}}


def verified():
    return [{"original_rva":hex(CHILD),
             "full_function_behavior_verified":True,
             "win64_guest_call_abi_verified":True,
             "code_presence":"ephemeral_ci_elf_only"}]


class Win64UnwindFrameTests(unittest.TestCase):
    def test_parses_pdata_and_exact_frame_operations(self):
        pe=SyntheticPE()
        self.assertEqual(pdata_index(pe)[PARENT],(PARENT+len(GOOD_BODY),META))
        frame=decode_unwind(pe,META)
        self.assertTrue(frame["eligible"])
        self.assertEqual(frame["prologue_bytes"],10)
        self.assertEqual(frame["nonvolatile_pushes"],1)
        self.assertEqual(frame["stack_decrement_bytes"],40)
        self.assertEqual(frame["frame_offset_bytes"],32)
        self.assertEqual(frame["frame_rbp_offset_from_entry_rsp"],-8)

    def test_actual_original_x64_matches_win64_metadata(self):
        pe=SyntheticPE()
        frame=decode_unwind(pe,META)
        self.assertEqual(validate_prologue(pe,PARENT,PARENT+len(pe.body),frame),
                         "original_x64_rbp_prologue_matches_unwind")
        report=analyze(pe,mapping(),verified())
        self.assertEqual(report["caller_function_intervals_with_verified_native_leaf_edges"],1)
        self.assertEqual(report["original_x64_prologues_matching_win64_unwind"],1)
        self.assertFalse(report["actual_original_callsite_rsp_rbp_traced"])
        self.assertEqual(report["complete_caller_functions_native_verified"],0)
        self.assertFalse(report["original_executable_bytes_exported"])

    def test_real_x64_frameless_stack_allocation_matches_win64_unwind(self):
        # push rbx; sub rsp, 32. No RBP frame register is declared.
        body=bytes.fromhex("53 4883ec20 c3")
        xdata=bytes([1,5,2,0,5,0x32,1,0x30])
        pe=SyntheticPE(body=body,xdata=xdata)
        frame=decode_unwind(pe,META)
        self.assertTrue(frame["eligible"])
        self.assertFalse(frame["has_declared_rbp_frame"])
        self.assertIsNone(frame["frame_rbp_offset_from_entry_rsp"])
        self.assertEqual(frame["stack_decrement_bytes"],40)
        self.assertEqual(validate_prologue(pe,PARENT,PARENT+len(body),frame),
                         "original_x64_frameless_prologue_matches_unwind")
        result=analyze(pe,mapping(),verified())
        self.assertEqual(result["frameless_prologues_metadata_parsed"],1)
        self.assertEqual(result["original_x64_frameless_prologues_matching_win64_unwind"],1)
        self.assertEqual(result["complete_caller_functions_native_verified"],0)

    def test_fails_closed_on_mismatched_stack_allocation(self):
        pe=SyntheticPE(body=bytes.fromhex("55 4883ec30 488d6c2420 c3"))
        frame=decode_unwind(pe,META)
        self.assertEqual(validate_prologue(pe,PARENT,PARENT+len(pe.body),frame),
                         "unwind_stack_allocation_disagrees_with_x64")

    def test_unsupported_chained_or_missing_frame_rejected(self):
        changed=bytes([0x21])+XDATA[1:]  # CHAININFO flag.
        frame=decode_unwind(SyntheticPE(xdata=changed),META)
        self.assertFalse(frame["eligible"])
        self.assertEqual(frame["reason"],"chained_unwind_info")
        changed=XDATA[:3]+bytes([0x00])+XDATA[4:]
        frame=decode_unwind(SyntheticPE(xdata=changed),META)
        self.assertEqual(frame["reason"],"frameless_record_declares_setfp")
        changed=XDATA[:4]+bytes([10,0x07])+XDATA[6:]
        frame=decode_unwind(SyntheticPE(xdata=changed),META)
        self.assertEqual(frame["reason"],"unsupported_unwind_opcode")

    def test_unverified_callee_cannot_start_prologue_audit(self):
        report=analyze(SyntheticPE(),mapping(),[])
        self.assertEqual(report["caller_function_intervals_with_verified_native_leaf_edges"],0)
        self.assertEqual(report["original_x64_prologues_matching_win64_unwind"],0)
        with self.assertRaises(ValueError):
            analyze(SyntheticPE(),{"input_sha256":"untrusted"},verified())


if __name__=="__main__":
    unittest.main()
