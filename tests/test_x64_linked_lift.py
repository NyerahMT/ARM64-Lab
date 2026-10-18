import unittest
from tools.x64_linked_lift import translate_linked_pair,synthetic_pair,UnsupportedLinkedCall

class LinkedTests(unittest.TestCase):
 def test_genuine_callee_invocation_generated(self):
  r,c,t,d=synthetic_pair()
  src,meta=translate_linked_pair(c,r,d,t)
  self.assertEqual(meta["original_decoded_instructions"],7)
  self.assertTrue(meta["actual_linked_callee_emitted"])
  self.assertIn("lifted_callee(s,mem)",src)
  self.assertIn("original_rsp-40",src)
  self.assertIn("s->rsp+=8",src)
 def test_wrong_call_target_rejected(self):
  r,c,t,d=synthetic_pair()
  with self.assertRaises(UnsupportedLinkedCall):
   translate_linked_pair(c,r,d,t+64)
 def test_unrecognized_callee_rejected(self):
  r,c,t,d=synthetic_pair()
  with self.assertRaises(UnsupportedLinkedCall):
   translate_linked_pair(c,r,b"\x90"+d,t)

if __name__=="__main__":unittest.main()
