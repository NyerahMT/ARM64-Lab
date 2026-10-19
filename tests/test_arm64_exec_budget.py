"""Bounded ARM64 execution budget configuration regressions."""
from pathlib import Path
import unittest
from tools.import_aot_smoke import execute_arm64_elf

class ARM64BudgetTests(unittest.TestCase):
    def test_reject_unbounded_or_non_integer_execution_limits(self):
        missing=Path("/tmp/no-arm64-elf-required-for-limit-check")
        for count in (0,1,999,2000001,-50,True,1000.5):
            with self.subTest(instruction_budget=count):
                with self.assertRaisesRegex(ValueError,"instruction budget"):
                    execute_arm64_elf(missing,instruction_budget=count)
        for timeout in (0,999999,15000001,-1,False,3.3):
            with self.subTest(timeout_us=timeout):
                with self.assertRaisesRegex(ValueError,"timeout"):
                    execute_arm64_elf(missing,timeout_us=timeout)

    def test_extended_but_bounded_budget_still_requires_real_elf(self):
        with self.assertRaises(FileNotFoundError):
            execute_arm64_elf(Path("/tmp/no-arm64-elf-expected"),
                              instruction_budget=650000,timeout_us=9000000)
