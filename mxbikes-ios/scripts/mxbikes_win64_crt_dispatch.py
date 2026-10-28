#!/usr/bin/env python3
"""Minimal guest-executed Win64 _initterm/_initterm_e dispatcher thunks.

Synthetic x64 machine code independently assembled from ABI-conforming
source; lives ONLY in bounded Unicorn. Original initializer code runs from
pinned executable, never faked. _initterm_e checks real callback returns;
_initterm runs all nonzero function pointers. Preserves Win64 RSI/RDI and
provides 32 bytes shadow space / correct 16-byte stack alignment.

Not a production Windows CRT, ARM64 code, or a game launch.
"""
from mxbikes_first_callee_emu import STUB_BASE

THUNK_E_VA=STUB_BASE+0x8000
THUNK_VOID_VA=STUB_BASE+0x8100

# Win64: push rsi/rdi; sub rsp,40; copy RCX/RDX pointer bounds;
# iterate qwords, call real callbacks, obey _initterm_e int return,
# restore stack and saved registers, return.
THUNK_E=bytes.fromhex(
    "56574883ec284889ce4889d74839fe7314488b064883c6084885c0"
    "74efffd085c07504ebe731c04883c4285f5ec3"
)
THUNK_VOID=bytes.fromhex(
    "56574883ec284889ce4889d74839fe7310488b064883c6084885c0"
    "74efffd0ebeb4883c4285f5ec3"
)
assert len(THUNK_E)==46 and len(THUNK_VOID)==40

def install_original_crt_dispatch_thunks(uc):
    # Above 2048 synthetic import slots, 16 bytes each.
    uc.mem_write(THUNK_E_VA,THUNK_E)
    uc.mem_write(THUNK_VOID_VA,THUNK_VOID)
    return {
        THUNK_E_VA:("msvcr90.dll","_initterm_e"),
        THUNK_VOID_VA:("msvcr90.dll","_initterm"),
    }

def synthesized_dispatch_address(lib,name):
    if lib.lower()!="msvcr90.dll":return None
    if name.lower()=="_initterm_e":return THUNK_E_VA
    if name.lower()=="_initterm":return THUNK_VOID_VA
    return None

def inside_synthetic_crt_dispatch(addr):
    return (THUNK_E_VA<=addr<THUNK_E_VA+len(THUNK_E) or
            THUNK_VOID_VA<=addr<THUNK_VOID_VA+len(THUNK_VOID))
