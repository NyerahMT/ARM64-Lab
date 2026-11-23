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
GETFILETIME_ORIGINAL_CALL_RVA=0x1578dd
GETFILETIME_ORIGINAL_RETURN_RVA=GETFILETIME_ORIGINAL_CALL_RVA+6
GENERIC_READ=0x80000000
FILE_SHARE_READ=0x1
OPEN_EXISTING=3
CORE_INI_NAME="core.ini"
MAX_CORE_BYTES=64*1024

class CoreIniWin32Rejected(ValueError):
    pass

class OwnedCoreIniWin32Research:
    def __init__(self,content,*,last_write_filetime_100ns=None):
        if not isinstance(content,bytes) or not 0<len(content)<=MAX_CORE_BYTES:
            raise CoreIniWin32Rejected("invalid_private_core_ini_owned_bytes")
        if (last_write_filetime_100ns is not None and
            (not isinstance(last_write_filetime_100ns,int) or
             not 0<last_write_filetime_100ns<2**64)):
            raise CoreIniWin32Rejected("invalid_private_core_ini_filetime")
        self.content=content
        self.last_write_filetime_100ns=last_write_filetime_100ns
        self.cursor=0
        self.open=False
        self.calls=[]
        self.filetime_calls=[]

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

    def handle_getfiletime(self,u,pe,slots,lib,symbol,verify):
        """Serve only the original core.ini last-write FILETIME output.

        Timestamp is derived from user-owned file metadata. A ZIP timestamp
        is timezone-naive; the private extraction explicitly interprets its
        wall clock as UTC. Creation and access times are never manufactured.
        """
        if lib.lower()!="kernel32.dll" or symbol!="GetFileTime":
            return False
        if (not self.open or len(self.calls)!=1 or self.filetime_calls):
            raise CoreIniWin32Rejected("original_getfiletime_file_not_open_or_budget")
        if self.last_write_filetime_100ns is None:
            raise CoreIniWin32Rejected("original_getfiletime_metadata_not_available")
        rsp=u.reg_read(UC_X86_REG_RSP)
        handle=u.reg_read(UC_X86_REG_RCX)
        created=u.reg_read(UC_X86_REG_RDX)
        accessed=u.reg_read(UC_X86_REG_R8)
        modified=u.reg_read(UC_X86_REG_R9)
        if (rsp&15!=8 or handle!=CORE_INI_WIN32_HANDLE or
            created!=0 or accessed!=0 or not modified or modified&3):
            raise CoreIniWin32Rejected("original_getfiletime_win64_abi_mismatch")
        try:
            ret=struct.unpack("<Q",bytes(u.mem_read(rsp,8)))[0]
        except Exception as exc:
            raise CoreIniWin32Rejected("original_getfiletime_return_unmapped") from exc
        if (ret!=IMAGE_BASE+GETFILETIME_ORIGINAL_RETURN_RVA or
            verify(pe,ret,lib,symbol,slots)!=hex(GETFILETIME_ORIGINAL_CALL_RVA)):
            raise CoreIniWin32Rejected("original_getfiletime_import_callsite_unverified")
        if IMAGE_BASE<=modified<IMAGE_BASE+0x8000000:
            rva=modified-IMAGE_BASE
            if not any((rva>=base and rva-base<=max(vsize,rawsize)-8
                        and flags&0x80000000 and not flags&0x20000000)
                       for _,vsize,base,rawsize,_,flags in pe.sections):
                raise CoreIniWin32Rejected("original_getfiletime_output_not_writable_pe_data")
        try:
            if len(u.mem_read(modified,8))!=8:
                raise CoreIniWin32Rejected("original_getfiletime_output_short")
        except CoreIniWin32Rejected:
            raise
        except Exception as exc:
            raise CoreIniWin32Rejected("original_getfiletime_output_unmapped") from exc
        try:
            u.mem_write(modified,struct.pack("<Q",self.last_write_filetime_100ns))
        except Exception as exc:
            raise CoreIniWin32Rejected("original_getfiletime_guest_write_failed") from exc
        u.reg_write(UC_X86_REG_RAX,1)
        self.filetime_calls.append({
            "original_call_rva":hex(GETFILETIME_ORIGINAL_CALL_RVA),
            "owned_file_lastwrite_time_supplied":True,
            "creation_or_access_time_supplied":False,
            "guest_filetime_bytes_written":8,
            "host_win32_file_api_called":False,
        })
        return True

    def summary(self):
        return {
            "original_core_ini_win32_createfile_count":len(self.calls),
            "original_core_ini_win32_calls":list(self.calls),
            "original_core_ini_win32_getfiletime_count":len(self.filetime_calls),
            "original_core_ini_win32_getfiletime_calls":list(self.filetime_calls),
            "win32_guest_handle_currently_open":self.open,
            "win32_guest_file_cursor":self.cursor,
            "no_host_file_api_called":True,
            "no_original_game_bytes_published":True,
        }
