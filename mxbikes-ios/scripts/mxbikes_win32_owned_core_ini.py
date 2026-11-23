#!/usr/bin/env python3
"""Original-game read-only Win32 CreateFileA for user-owned core.ini bytes.

Research-only Win64 ABI shim. Guest core.ini data was privately read from
the owned archive and never stored in source, logs, or public artifacts.
No host CreateFileA/Steam API is invoked and writes are not supported.
"""
from __future__ import annotations
import struct
from unicorn.x86_const import (
    UC_X86_REG_RSP,UC_X86_REG_RAX,UC_X86_REG_RCX,
    UC_X86_REG_RDX,UC_X86_REG_R8,UC_X86_REG_R9,
)
from mxbikes_owned_file_crt import read_guest_cstring,GuestServiceBlocked

IMAGE_BASE=0x140000000
CORE_INI_WIN32_HANDLE=0x730070000
CREATEFILEA_ORIGINAL_CALL_RVA=0x1578c2
CREATEFILEA_ORIGINAL_RETURN_RVA=CREATEFILEA_ORIGINAL_CALL_RVA+6
GENERIC_READ=0x80000000
FILE_SHARE_READ=0x1
OPEN_EXISTING=3
CORE_INI_NAME="core.ini"
MAX_CORE_BYTES=64*1024

class CoreIniWin32Rejected(ValueError):
    pass

class OwnedCoreIniWin32Research:
    def __init__(self,content):
        if not isinstance(content,bytes) or not 0<len(content)<=MAX_CORE_BYTES:
            raise CoreIniWin32Rejected("invalid_private_core_ini_owned_bytes")
        self.content=content
        self.cursor=0
        self.open=False
        self.calls=[]

    def handle_createfilea(self,u,pe,slots,lib,symbol,verify):
        if lib.lower()!="kernel32.dll" or symbol!="CreateFileA":
            return False
        if self.open or self.calls:
            raise CoreIniWin32Rejected("original_core_ini_win32_open_budget")
        stack=u.reg_read(UC_X86_REG_RSP)
        path=u.reg_read(UC_X86_REG_RCX)
        access=u.reg_read(UC_X86_REG_RDX)
        sharing=u.reg_read(UC_X86_REG_R8)
        security=u.reg_read(UC_X86_REG_R9)
        if stack&15!=8:
            raise CoreIniWin32Rejected("original_win64_createfile_stack_alignment")
        if not path or security:
            raise CoreIniWin32Rejected("original_createfile_path_or_security_mismatch")
        try:
            ret=struct.unpack("<Q",bytes(u.mem_read(stack,8)))[0]
            creation,flags,template=struct.unpack(
                "<QQQ",bytes(u.mem_read(stack+0x28,24)))
            filename=read_guest_cstring(u,path)
        except (ValueError,GuestServiceBlocked,struct.error) as exc:
            raise CoreIniWin32Rejected("original_createfile_unmapped_guest_args") from exc
        if (ret!=IMAGE_BASE+CREATEFILEA_ORIGINAL_RETURN_RVA or
            verify(pe,ret,lib,symbol,slots)!=hex(CREATEFILEA_ORIGINAL_CALL_RVA)):
            raise CoreIniWin32Rejected("original_createfile_iat_callsite_unverified")
        if (filename!=CORE_INI_NAME or access!=GENERIC_READ or
            sharing!=FILE_SHARE_READ or creation!=OPEN_EXISTING or
            flags!=0 or template!=0):
            raise CoreIniWin32Rejected("unexpected_createfile_requested_access_or_file")
        u.reg_write(UC_X86_REG_RAX,CORE_INI_WIN32_HANDLE)
        self.open=True
        self.cursor=0
        self.calls.append({
            "original_call_rva":hex(CREATEFILEA_ORIGINAL_CALL_RVA),
            "path":CORE_INI_NAME,
            "original_owned_bytes":len(self.content),
            "read_only":True,
            "host_windows_file_api_called":False,
        })
        return True

    def summary(self):
        return {
            "original_core_ini_win32_createfile_count":len(self.calls),
            "original_core_ini_win32_calls":list(self.calls),
            "win32_guest_handle_currently_open":self.open,
            "win32_guest_file_cursor":self.cursor,
            "no_host_file_api_called":True,
            "no_original_game_bytes_published":True,
        }
