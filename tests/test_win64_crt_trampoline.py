"""Verify Win64 initializer thunk calls real synthetic callbacks in order."""
import struct
import unittest

from unicorn import Uc, UC_ARCH_X86, UC_MODE_64, UC_HOOK_CODE
from unicorn.x86_const import UC_X86_REG_EAX, UC_X86_REG_RIP, UC_X86_REG_RSP

from tools.win64_crt_trampoline import build_initializer_trampoline

CODE = 0x100000
CALL_A = 0x101000
CALL_B = 0x102000
SENTINEL = 0x103000
STACK = 0x200000


def execute(result_a, result_b, propagate=True):
    uc = Uc(UC_ARCH_X86, UC_MODE_64)
    uc.mem_map(CODE, 0x10000)
    uc.mem_map(STACK, 0x10000)
    uc.mem_write(CODE, build_initializer_trampoline([CALL_A, CALL_B], propagate))
    uc.mem_write(CALL_A, b"\xb8" + struct.pack("<I", result_a) + b"\xc3")
    uc.mem_write(CALL_B, b"\xb8" + struct.pack("<I", result_b) + b"\xc3")
    initial_rsp = STACK + 0xf008  # 8 mod 16: Win64 function-entry stack
    uc.mem_write(initial_rsp, struct.pack("<Q", SENTINEL))
    uc.reg_write(UC_X86_REG_RSP, initial_rsp)
    uc.reg_write(UC_X86_REG_RIP, CODE)
    visit = []
    def trace(_, address, size, __):
        if address in (CALL_A, CALL_B):
            visit.append(address)
    uc.hook_add(UC_HOOK_CODE, trace)
    uc.emu_start(CODE, SENTINEL, timeout=1_000_000, count=250)
    if uc.reg_read(UC_X86_REG_RIP) != SENTINEL:
        raise RuntimeError("Synthetic _initterm thunk failed to return")
    return visit, uc.reg_read(UC_X86_REG_EAX), uc.reg_read(UC_X86_REG_RSP)


class CRTThunkTests(unittest.TestCase):
    def test_success_calls_all_initializers(self):
        order, result, rsp = execute(0, 0)
        self.assertEqual(order, [CALL_A, CALL_B])
        self.assertEqual(result, 0)
        self.assertEqual(rsp, STACK + 0xf010)

    def test_failed_initializer_skips_next(self):
        order, result, rsp = execute(7, 0)
        self.assertEqual(order, [CALL_A])
        self.assertEqual(result, 7)
        self.assertEqual(rsp, STACK + 0xf010)

    def test_void_initializer_calls_everything(self):
        order, result, _ = execute(7, 9, False)
        self.assertEqual(order, [CALL_A, CALL_B])

    def test_rejects_invalid_targets(self):
        with self.assertRaises(ValueError):
            build_initializer_trampoline([-1])
        with self.assertRaises(ValueError):
            build_initializer_trampoline([CALL_A]*65)


if __name__ == "__main__":
    unittest.main()
