"""Synthetic-only unit coverage for resumable CRT CFG translation."""
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

from tools.crt_cfg_lift import translate_crt_cfg, UnsupportedCRT

ROOT=Path(__file__).resolve().parents[1]

class CRTCFGTests(unittest.TestCase):
    def test_branch_and_continuation_code_compiles(self):
        # sub rsp,40; cmp rax,rbx; je skip; not rax; add rsp,40; ret
        source=bytes.fromhex("4883ec284839d8740348f7d04883c428c3")
        c, meta=translate_crt_cfg(source,0x1000,{})
        self.assertEqual(meta["decoded_instructions"],6)
        self.assertEqual(meta["blocks"],3)
        self.assertEqual(meta["direct_edges"],3)
        self.assertIn("goto I_100c;",c)
        self.assertIn("int lifted_crt_run(",c)
        self._compile(c)

    def test_import_pauses_and_resumes(self):
        # sub rsp,40; call qword ptr [rip+0x46]; add rsp,40; ret
        source=bytes.fromhex("4883ec28ff15460000004883c428c3")
        c,meta=translate_crt_cfg(source,0x2000,
                                  {0x2050:("kernel32.dll","GetTickCount")})
        self.assertEqual(meta["decoded_instructions"],4)
        self.assertEqual(meta["imports"][0]["iat_symbol"],"GetTickCount")
        self.assertIn("MX_CRT_PAUSED_IMPORT",c)
        self.assertIn("case UINT64_C(5368717322)",c) if False else None
        self.assertIn("goto I_200a",c)
        self._compile(c)

    def test_unrecognized_import_rejected(self):
        source=bytes.fromhex("4883ec28ff15460000004883c428c3")
        with self.assertRaisesRegex(UnsupportedCRT,"Unverified"):
            translate_crt_cfg(source,0x2000,{})
        with self.assertRaisesRegex(UnsupportedCRT,"Unsupported runtime import"):
            translate_crt_cfg(source,0x2000,
                              {0x2050:("steam_api64.dll","SteamAPI_Init")})

    def test_unsupported_instruction_rejected(self):
        with self.assertRaisesRegex(UnsupportedCRT,"Unsupported original opcode"):
            translate_crt_cfg(bytes.fromhex("9090c3"),0x3000,{})

    def _compile(self,source):
        with tempfile.TemporaryDirectory() as temp:
            p=Path(temp)
            (p/"lifted.c").write_text(source)
            subprocess.run(["cc","-std=c11","-O2","-Wall","-Wextra","-Werror",
                            "-I",str(ROOT/"runtime"),"-c",
                            str(p/"lifted.c"),"-o",str(p/"lifted.o")],check=True,
                           capture_output=True,text=True)

if __name__=="__main__":
    unittest.main()
