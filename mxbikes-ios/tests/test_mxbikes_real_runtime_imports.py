"""Import all ORIGINAL-code local runtime dependencies without game inputs.

This catches path/layout regressions after the migration to ARM64-Lab. This
test does not load any commercial DLL or game EXE, nor execute guest code.
"""
import inspect
from pathlib import Path
import sys
import unittest

REPO=Path(__file__).resolve().parents[2]
SCRIPTS=Path(__file__).resolve().parents[1]/"scripts"
for path in (str(REPO),str(SCRIPTS)):
    if path not in sys.path:sys.path.insert(0,path)

class RuntimeImportTests(unittest.TestCase):
    def test_authentic_guest_runtime_modules_import_from_new_public_layout(self):
        import mxbikes_original_game_graphics_handoff as handoff
        import mxbikes_startup_fast_blocks as blocks
        import mxbikes_startup_batch_runner as batch
        import mxbikes_steam_fopen_result_probe as fopen
        import mxbikes_real_frame_frontier as frontier
        from tools.pe_probe import PE
        self.assertTrue(callable(handoff.run))
        self.assertTrue(callable(blocks.execute))
        self.assertTrue(callable(batch.install_import_dispatch))
        self.assertTrue(callable(fopen.original_case))
        self.assertTrue(callable(frontier.static_index))
        self.assertTrue(callable(PE))
        self.assertTrue((SCRIPTS.parent / "arm64-lab" / "tools" / "pe_probe.py").is_file())
        self.assertTrue((SCRIPTS.parent / "arm64-lab" / "runtime" / "mx_guest_imports.c").is_file())
        self.assertIn("graphics_handler",inspect.signature(blocks.execute).parameters)

if __name__=="__main__":
    unittest.main()
