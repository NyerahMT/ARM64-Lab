#!/usr/bin/env python3
"""Bounded deterministic x64 Windows TEB/PEB guest state for startup probes.

This is a *test-only approximation* of essential thread/process structures.
It is not Windows kernel initialization, loader emulation, exception handling,
heap allocation, TLS callbacks, CRT runtime or a production iOS compatibility
layer. Unimplemented OS services still cause the parent probe to stop.
"""
import struct
from unicorn.x86_const import UC_X86_REG_GS_BASE

TEB_BASE=0x740000000
PEB_BASE=0x740010000
PARAMS_BASE=0x740020000
HEAP_BASE=0x740030000
THREAD_ENV_PAGE=0x1000
PROCESS_ID=0x1234
THREAD_ID=0x5678

def build_win64_thread_environment(uc, *, stack_base, stack_size, image_base):
    if (stack_size<0x1000 or stack_base%0x1000 or stack_size%0x1000
        or image_base<0x10000 or image_base%0x1000):
        raise ValueError("Win64 modeled thread requires mapped aligned image and stack")
    for addr in (TEB_BASE,PEB_BASE,PARAMS_BASE,HEAP_BASE):
        uc.mem_map(addr,THREAD_ENV_PAGE)
    def writeq(addr,offset,value):
        uc.mem_write(addr+offset,struct.pack("<Q",value))
    # NT_TIB StackBase/StackLimit and NtTib.Self at x64 offsets 08/10/30.
    writeq(TEB_BASE,0x08,stack_base+stack_size)
    writeq(TEB_BASE,0x10,stack_base)
    writeq(TEB_BASE,0x30,TEB_BASE)
    # _CLIENT_ID at +0x40 (UniqueProcess), +0x48 (UniqueThread) in x64 TEB.
    writeq(TEB_BASE,0x40,PROCESS_ID)
    writeq(TEB_BASE,0x48,THREAD_ID)
    writeq(TEB_BASE,0x60,PEB_BASE)
    # PEB image, process parameters and process heap pointers.
    writeq(PEB_BASE,0x10,image_base)
    writeq(PEB_BASE,0x20,PARAMS_BASE)
    writeq(PEB_BASE,0x30,HEAP_BASE)
    # RTL_USER_PROCESS_PARAMETERS.Length, MaximumLength (minimal initialized block).
    uc.mem_write(PARAMS_BASE,struct.pack("<II",0x100,THREAD_ENV_PAGE))
    uc.reg_write(UC_X86_REG_GS_BASE,TEB_BASE)
    return {
        "synthetic_teb_mapped":True,
        "synthetic_peb_mapped":True,
        "synthetic_process_parameter_buffer_mapped":True,
        "synthetic_process_heap_first_page_mapped":True,
        "win64_gs_base_initialized":True,
        "real_windows_teb_or_peb_created":False,
        "native_arm64_teb_implemented":False,
    }


# Minimal, deterministic test-only argv/envp vector in a separate guest page.
CRT_ARGS_BASE=0x750000000
CRT_ARGV_ARRAY=CRT_ARGS_BASE
CRT_ENVP_ARRAY=CRT_ARGS_BASE+0x40
CRT_EXE_STRING=CRT_ARGS_BASE+0x100

def install_guest_main_arguments(uc):
    uc.mem_map(CRT_ARGS_BASE,THREAD_ENV_PAGE)
    uc.mem_write(CRT_ARGV_ARRAY,struct.pack("<QQ",CRT_EXE_STRING,0))
    uc.mem_write(CRT_ENVP_ARRAY,struct.pack("<Q",0))
    uc.mem_write(CRT_EXE_STRING,b"mxbikes.exe\x00")
    return {"synthetic_argv_count":1,"synthetic_argv0":"mxbikes.exe",
            "synthetic_environment_entries":0,
            "actual_windows_command_line_parsed":False}

def _guest_can_write(ptr,nbytes,writable_sections,stack_base,stack_size):
    return (
        stack_base<=ptr and ptr+nbytes<=stack_base+stack_size or
        any(lo<=ptr and ptr+nbytes<=hi for lo,hi in writable_sections)
    )

def model_win64_crt_getmainargs(uc,argc_ptr,argv_ptr,env_ptr,writable_sections,
                               *,stack_base,stack_size,wildcard):
    """Write real Win64 argc/argv/envp output shapes, not real user CLI/env."""
    if wildcard not in (0,1):
        return False
    for ptr,size in ((argc_ptr,4),(argv_ptr,8),(env_ptr,8)):
        if not _guest_can_write(ptr,size,writable_sections,stack_base,stack_size):
            return False
    uc.mem_write(argc_ptr,struct.pack("<I",1))
    uc.mem_write(argv_ptr,struct.pack("<Q",CRT_ARGV_ARRAY))
    uc.mem_write(env_ptr,struct.pack("<Q",CRT_ENVP_ARRAY))
    return True
