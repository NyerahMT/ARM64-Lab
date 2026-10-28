#!/usr/bin/env python3
"""Typed Win64 MSVCR90 DATA import slots for original x64 startup.

Windows IAT entries for imported DLL data point to a variable's storage, not
to executable RET stubs. Treating them as callable functions corrupts the
original CRT (e.g. _acmdln becomes pointer 0xc3). This is a minimal test-only
typed CRT data page; never claim a real Windows CRT or process environment.
"""
import struct
from mxbikes_win64_thread_env import CRT_EXE_STRING

CRT_DATA_BASE=0x760000000
WIDE_CMDLINE=CRT_DATA_BASE+0x100
CRT_DATA_SYMBOLS={"_acmdln":CRT_DATA_BASE+0x00,
                  "_wcmdln":CRT_DATA_BASE+0x08}

def install_crt_data_globals(uc):
    uc.mem_map(CRT_DATA_BASE,4096)
    uc.mem_write(CRT_DATA_BASE,
        struct.pack("<QQ",CRT_EXE_STRING,WIDE_CMDLINE))
    uc.mem_write(WIDE_CMDLINE,"mxbikes.exe\x00".encode("utf-16le"))
    return {"simulated_crt_data_imports":len(CRT_DATA_SYMBOLS),
            "typed_data_import_not_executable":True,
            "real_msvcr90_dll_mapped":False}

def address_for_original_crt_data_import(lib,symbol):
    if lib.lower()!="msvcr90.dll":return None
    return CRT_DATA_SYMBOLS.get(symbol.lower())
