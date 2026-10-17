"""Deterministic reversible pointer-token codec for isolated Win64 CRT testing.

NOT Microsoft's undocumented EncodePointer algorithm and NOT an iOS
security mechanism. Only suitable when both encode/decode are emulated using
the same synthetic process-local key; it cannot decode genuine Windows tokens.
"""
MASK = (1 << 64) - 1
TEST_PROCESS_KEY = 0x91C6_53E8_6DA4_20F7


def encode_pointer(pointer: int, key: int = TEST_PROCESS_KEY) -> int:
    if not (0 <= pointer <= MASK and 0 <= key <= MASK):
        raise ValueError("Expected unsigned 64-bit pointer and key")
    value = (pointer ^ key) & MASK
    return ((value << 17) | (value >> 47)) & MASK


def decode_pointer(token: int, key: int = TEST_PROCESS_KEY) -> int:
    if not (0 <= token <= MASK and 0 <= key <= MASK):
        raise ValueError("Expected unsigned 64-bit token and key")
    value = ((token >> 17) | (token << 47)) & MASK
    return value ^ key
