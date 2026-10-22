"""Fail-closed and bounded ARM64 guest execution budget input checks."""
from pathlib import Path
import unittest
from tools.import_aot_smoke import execute_arm64_elf

class ARM64BudgetTests(unittest.TestCase):
    def test_rejects_excessive_instructions_and_timeouts_before_loading(self):
        missing=Path("/tmp/this-aarch64-test-elf-does-not-exist")
        for count in (0,999,6000001,10000000,True):
            with self.subTest(count=count), self.assertRaises(ValueError):
                execute_arm64_elf(missing,instruction_budget=count)
        for us in (0,999999,15000001,True):
            with self.subTest(timeout_us=us), self.assertRaises(ValueError):
                execute_arm64_elf(missing,timeout_us=us)

    def test_explicit_new_limit_is_accepted_but_requires_real_guest_elf(self):
        missing=Path("/tmp/this-aarch64-test-elf-does-not-exist")
        with self.assertRaises(FileNotFoundError):
            execute_arm64_elf(missing,instruction_budget=6000000,
                              timeout_us=15000000)

if __name__=="__main__":
    unittest.main()
