"""Provenance contract: only a REAL original RIP-relative IAT CALL is renderable."""
import struct
import sys
import unittest
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"scripts"))
from mxbikes_main_joined_callee_native import BASE
from mxbikes_original_game_graphics_handoff import VerifiedGameGL

RVA=0x1200
SLOT=0x2900
class PE:
 def __init__(self,code):
  self.b=b"MZ"+b"\0"*0x200000
  self.code=code
 def read_rva(self,rva,size):
  if rva!=RVA or size!=6:raise ValueError("Unmapped original bytes")
  return self.code

class TestRealOriginalOpenGLProvenance(unittest.TestCase):
 def obj(self,blob,iat=None):
  bridge=VerifiedGameGL.__new__(VerifiedGameGL)
  bridge.pe=PE(blob)
  bridge.iat=iat if iat is not None else {
   SLOT:("opengl32.dll","glDrawElements")
  }
  return bridge
 def test_exact_original_iat_call_and_correct_stack_return(self):
  blob=b"\xff\x15"+struct.pack("<i",SLOT-RVA-6)
  report=self.obj(blob).prove_original_callsite(
   BASE+RVA+6,"OPENGL32.dll","glDrawElements")
  self.assertEqual(report["original_call_rva"],hex(RVA))
  self.assertEqual(report["original_iat_rva"],hex(SLOT))
 def test_mismatched_import_is_not_original_graphics(self):
  blob=b"\xff\x15"+struct.pack("<i",SLOT-RVA-6)
  b=self.obj(blob)
  self.assertIsNone(b.prove_original_callsite(
   BASE+RVA+6,"OPENGL32.dll","glTexImage2D"))
  self.assertIsNone(b.prove_original_callsite(
   BASE+RVA+6,"steam_api64.dll","glDrawElements"))
 def test_wrong_opcode_stack_pc_and_iat_fail_closed(self):
  blob=b"\xff\x15"+struct.pack("<i",SLOT-RVA-6)
  self.assertIsNone(self.obj(b"\x90"+blob[1:]).prove_original_callsite(
   BASE+RVA+6,"OPENGL32.dll","glDrawElements"))
  self.assertIsNone(self.obj(blob).prove_original_callsite(
   BASE+RVA+7,"OPENGL32.dll","glDrawElements"))
  self.assertIsNone(self.obj(blob,{SLOT+8:("opengl32.dll","glDrawElements")})
   .prove_original_callsite(BASE+RVA+6,"OPENGL32.dll","glDrawElements"))
  self.assertIsNone(self.obj(blob).prove_original_callsite(
   0,"OPENGL32.dll","glDrawElements"))

if __name__=="__main__":unittest.main()
