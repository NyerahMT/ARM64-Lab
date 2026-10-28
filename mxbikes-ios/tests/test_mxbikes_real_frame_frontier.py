"""Synthetic x64 CALL graphs only; no original or copyrighted game bytes."""
import importlib.util
from pathlib import Path
import struct
import unittest

SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "mxbikes_real_frame_frontier.py"
spec = importlib.util.spec_from_file_location("mxb_frontier", SCRIPT)
subject = importlib.util.module_from_spec(spec)
spec.loader.exec_module(subject)


class FakePE:
    """Miniature, constructed x64 PE-style function bytes + .pdata."""
    def __init__(self, *, false_positive=False):
        main = b"\xe8\xfb\x00\x00\x00\xc3"  # CALL 0x1100; RET
        sub = b"\xe8\xfb\x00\x00\x00"  # CALL 0x1200
        sub += b"\xff\x15\xf5\x0e\x00\x00\xc3"  # IAT steam at 0x2000; RET
        # glDrawElements slot at 0x2008
        graphics = b"\xff\x15\x02\x0e\x00\x00\xc3"
        self.regions = [
            (0x1000, main),
            (0x1100, sub),
            (0x1200, graphics)
        ]
        if false_positive:
            # CALL [RIP] byte sequence embedded inside a MOV immediate.
            self.regions.append((0x1300, b"\xb8\xff\x15\x02\x0e\xc3"))
        pdata = b"".join(struct.pack("<III",start,start+len(raw),0x3000)
                         for start,raw in self.regions)
        self.tables = {0x3000: pdata}
        for start,raw in self.regions:
            self.tables[start] = raw
        self.sections = [(".text", 0x1000, 0x1000, 0x1000, 0, 0x60000020),
                         (".pdata", 0x100, 0x3000, 0x100, 0, 0x40000040)]
    def directory(self,n):
        return ((0x3000,len(self.tables[0x3000])) if n==3 else (0,0))
    def read_rva(self,rva,size):
        for start,data in self.tables.items():
            if start <= rva and 0 <= size <= len(data)-(rva-start):
                return data[rva-start:rva-start+size]
        raise ValueError("fixture RVA unavailable")


IAT = [(0x2000,"steam_api64.dll","SteamAPI_Init"),
       (0x2008,"OPENGL32.dll","glDrawElements")]


class FrameFrontierTests(unittest.TestCase):
    def test_direct_call_graph_static_only(self):
        result=subject.static_index(FakePE(),IAT,main_rva=0x1000)
        self.assertEqual(result["static_main_direct_call_graph_nodes"],3)
        self.assertEqual(result["function_linear_decodes_completed"],3)
        g=result["candidate_imports_on_direct_call_graph"]["graphics"]
        s=result["candidate_imports_on_direct_call_graph"]["steam"]
        self.assertEqual(g["candidate_import_calls_from_main_graph"],1)
        self.assertEqual(g["shortest_direct_call_depth"],2)
        self.assertEqual(g["examples"][0]["static_call_chain"],
                         ["0x1000","0x1100","0x1200"])
        self.assertEqual(s["shortest_direct_call_depth"],1)
        self.assertFalse(g["examples"][0]["executed"])
        self.assertEqual(result["actual_game_frames_rendered"],0)

    def test_no_false_call_inside_instruction_immediate(self):
        result=subject.static_index(FakePE(false_positive=True),IAT,main_rva=0x1000)
        self.assertEqual(result["function_linear_decodes_completed"],4)
        self.assertEqual(result["candidate_imports_across_all_decoded_functions"].get("graphics"),1)

    def test_missing_main_and_duplicate_import_fail(self):
        pe=FakePE()
        with self.assertRaisesRegex(ValueError,"main_function_not_decoded"):
            subject.static_index(pe,IAT,main_rva=0x200)
        with self.assertRaisesRegex(ValueError,"duplicate_original_IAT"):
            subject.static_index(pe,IAT+[IAT[0]],main_rva=0x1000)

    def test_bounded_decode_and_bounded_depth(self):
        pe=FakePE()
        result=subject.static_index(pe,IAT,main_rva=0x1000,max_depth=1)
        self.assertEqual(result["static_main_direct_call_graph_nodes"],2)
        self.assertEqual(result["candidate_imports_on_direct_call_graph"]["graphics"]
                         ["candidate_import_calls_from_main_graph"],0)
        with self.assertRaisesRegex(ValueError,"invalid_max_depth"):
            subject.static_index(pe,IAT,main_rva=0x1000,max_depth=100)
        with self.assertRaisesRegex(ValueError,"main_function_not_decoded"):
            subject.static_index(pe,IAT,main_rva=0x1000,max_total=2)

if __name__ == "__main__":
    unittest.main()
