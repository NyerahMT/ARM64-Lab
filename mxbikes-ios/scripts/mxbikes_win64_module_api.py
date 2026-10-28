#!/usr/bin/env python3
"""Fail-closed Win64 GetModuleFileNameA test shim for SHA-pinned x64 smoke.

A real Windows loader exposes the module file name from the loader entry;
this bounded emulator uses the same deterministic program name given to
__getmainargs and the CRT data globals. Only hModule == NULL or the original
mapped main executable base is accepted. No arbitrary fake DLL handles.
"""
from unicorn.x86_const import UC_X86_REG_RAX

GUEST_EXE_FILENAME=b"C:\\MXBikes\\mxbikes.exe"
GUEST_WORKING_DIRECTORY=b"C:\\MXBikes"
MAX_GUEST_PATH=32768

def _writable(ptr,size,stack_start,stack_size,writable_sections):
    return (size>=0 and ptr>=0 and
        ((stack_start<=ptr and ptr+size<=stack_start+stack_size) or
         any(lo<=ptr and ptr+size<=hi for lo,hi in writable_sections)))

def model_getmodulefilenamea(uc,module,buffer,size,*,image_base,
                             stack_base,stack_size,writable_sections):
    """Write a NUL-terminated exact guest ANSI pathname and Win32 length.

    Return False instead of inventing results for truncation, unknown module
    handles, wrong memory permissions, zero capacity or implausible lengths.
    """
    if module not in (0,image_base) or not 0<size<=MAX_GUEST_PATH:
        return False
    raw=GUEST_EXE_FILENAME+b"\x00"
    if len(raw)>size or not _writable(buffer,len(raw),stack_base,stack_size,
                                     writable_sections):
        return False
    uc.mem_write(buffer,raw)
    uc.reg_write(UC_X86_REG_RAX,len(GUEST_EXE_FILENAME))
    return True


def model_setcurrentdirectorya(uc,guest_path,*,readable_ranges,process_state):
    """Model only the declared synthetic executable directory.

    This is a bounded pseudo-filesystem, not a claim about the user's drive.
    Never report an arbitrary unverified game asset directory as present.
    """
    max_length=260
    allowed=[hi-guest_path for lo,hi in readable_ranges if lo<=guest_path<hi]
    if not allowed:return False
    try:raw=bytes(uc.mem_read(guest_path,min(max_length,max(allowed))))
    except (ValueError,Exception) as exc:
        # Unicorn's unmapped-memory error subclasses Exception; return safely.
        return False
    ending=raw.find(b"\x00")
    if ending<=0:return False
    path=raw[:ending].rstrip(b"\\/").lower()
    if path!=GUEST_WORKING_DIRECTORY.lower():
        return False
    process_state["cwd"]=GUEST_WORKING_DIRECTORY.decode("ascii")
    process_state["changes"]=process_state.get("changes",0)+1
    uc.reg_write(UC_X86_REG_RAX,1)
    return True
