"""Tiny, bounded Win64 CRT initializer trampoline assembler.

Builds synthetic x86-64 machine code for _initterm_e (stop at first nonzero
callback result) or _initterm (invoke every callback). This DOES NOT translate
original application code or stand in for executing callbacks.
"""
import struct

MAX_CALLBACKS = 64


def build_initializer_trampoline(callbacks, error_return=True):
    addresses = list(callbacks)
    if len(addresses) > MAX_CALLBACKS:
        raise ValueError("Initializer callback table too large")
    if any(not isinstance(addr, int) or addr <= 0 or addr > 0xffffffffffffffff for addr in addresses):
        raise ValueError("Unmapped or invalid initializer callback")
    code = bytearray(b"\x48\x83\xec\x28")  # Win64 shadow space and stack alignment
    error_jumps = []
    for addr in addresses:
        code += b"\x48\xb8" + struct.pack("<Q", addr)  # movabs rax, callback
        code += b"\xff\xd0"  # call rax
        if error_return:
            code += b"\x85\xc0"  # test eax, eax
            code += b"\x0f\x85\x00\x00\x00\x00"  # jne end (rel32 patch later)
            error_jumps.append(len(code)-4)
    if error_return:
        code += b"\x31\xc0"  # xor eax, eax (all callbacks succeeded)
    end = len(code)
    code += b"\x48\x83\xc4\x28\xc3"  # restore shadow space; ret
    for imm_offset in error_jumps:
        struct.pack_into("<i", code, imm_offset, end - (imm_offset + 4))
    if len(code) > 4096:
        raise ValueError("Generated thunk exceeded bounded code page")
    return bytes(code)
