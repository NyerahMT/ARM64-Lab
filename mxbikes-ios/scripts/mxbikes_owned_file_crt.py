#!/usr/bin/env python3
"""Minimal, actual-byte-backed, read-only Win64 CRT FILE* service.

Designed for SHA-pinned owned MX Bikes private CI. All guest-facing pointers
are Win64 x64 virtual addresses. Exposes ONLY the original read operations;
no SteamAPI_Init emulation, DLL code execution, DRM bypass, or fake auth.

No host paths, archive payload bytes, or file buffer contents are emitted
to reports. Unsupported services and invalid guest accesses fail closed.
"""
from dataclasses import dataclass
from pathlib import Path

MAX_OWNED_FILE=64*1024*1024
MAX_READ=8*1024*1024
MAX_TOTAL_READ=64*1024*1024
MAX_CSTRING=256
FILE_HANDLE=0x730050000


class GuestServiceBlocked(Exception):
    """A service cannot be represented faithfully using known inputs."""


@dataclass
class OwnedReadOnlyFile:
    content: bytes
    handle: int=FILE_HANDLE
    cursor: int=0
    open: bool=True
    total_read: int=0

    @classmethod
    def from_private_path(cls, path, expected_size):
        p=Path(path)
        if (not isinstance(expected_size,int) or
            not 0<expected_size<=MAX_OWNED_FILE or
            not p.is_file() or p.stat().st_size!=expected_size):
            raise GuestServiceBlocked("owned_file_missing_or_size_mismatch")
        return cls(p.read_bytes())

    def require_handle(self, handle):
        if not self.open or handle!=self.handle:
            raise GuestServiceBlocked("invalid_or_closed_guest_FILE_pointer")

    def seek(self, handle, offset, origin):
        self.require_handle(handle)
        if origin not in (0,1,2):
            return -1
        anchor=(0,self.cursor,len(self.content))[origin]
        next_cursor=anchor+offset
        if next_cursor<0 or next_cursor>len(self.content):
            return -1
        self.cursor=next_cursor
        return 0

    def tell(self,handle):
        self.require_handle(handle)
        if self.cursor>0x7fffffff:
            return -1
        return self.cursor

    def read(self,handle,item_size,item_count):
        self.require_handle(handle)
        if (item_size<0 or item_count<0 or
            item_size*item_count>MAX_READ or
            self.total_read+item_size*item_count>MAX_TOTAL_READ):
            raise GuestServiceBlocked("read_budget_exceeded")
        if not item_size or not item_count:
            return b"",0
        wanted=item_size*item_count
        buf=self.content[self.cursor:self.cursor+wanted]
        self.cursor+=len(buf)
        self.total_read+=len(buf)
        return buf,len(buf)//item_size

    def getc(self,handle):
        self.require_handle(handle)
        if self.cursor>=len(self.content):
            return -1
        result=self.content[self.cursor]
        self.cursor+=1
        self.total_read+=1
        if self.total_read>MAX_TOTAL_READ:
            raise GuestServiceBlocked("read_budget_exceeded")
        return result

    def close(self,handle):
        self.require_handle(handle)
        self.open=False
        return 0

    def reopen(self, filename, mode):
        if filename!="steam_api64.dll" or mode!="rb" or self.open:
            raise GuestServiceBlocked("unproven_file_open_or_second_stream")
        self.cursor=0
        self.open=True
        return self.handle


def signed32(x):
    value=x&0xffffffff
    return value-0x100000000 if value&0x80000000 else value


def read_guest_cstring(uc, pointer):
    if not pointer:
        raise GuestServiceBlocked("null_guest_cstring")
    output=bytearray()
    for i in range(MAX_CSTRING):
        try:
            ch=bytes(uc.mem_read(pointer+i,1))[0]
        except Exception as exc:
            raise GuestServiceBlocked("unmapped_guest_cstring") from exc
        if ch==0:
            try:return output.decode("ascii")
            except UnicodeDecodeError as exc:
                raise GuestServiceBlocked("non_ascii_guest_filename") from exc
        if not 32<=ch<127:
            raise GuestServiceBlocked("unsafe_guest_filename")
        output.append(ch)
    raise GuestServiceBlocked("unterminated_guest_cstring")


class ReadOnlyCRT:
    """Win64 calling-convention adapter with explicit supported symbol set."""
    SUPPORTED=frozenset(("fopen","fseek","ftell","fread","fclose",
                        "rewind","fgetc","feof"))

    def __init__(self,file):
        self.file=file
        self.calls={}
        self.bytes_returned=0

    def dispatch(self, uc, symbol, rcx, rdx, r8, r9):
        name=symbol.lower()
        if name not in self.SUPPORTED:
            raise GuestServiceBlocked("unimplemented_import")
        self.calls[name]=self.calls.get(name,0)+1
        stream=self.file
        if name=="fopen":
            name_arg=read_guest_cstring(uc,rcx)
            mode_arg=read_guest_cstring(uc,rdx)
            return stream.reopen(name_arg,mode_arg)
        if name=="fseek":
            return stream.seek(rcx,signed32(rdx),r8&0xffffffff)
        if name=="ftell":
            return stream.tell(rcx)
        if name=="fread":
            data,count=stream.read(r9,rdx,r8)
            if data:
                try:uc.mem_write(rcx,data)
                except Exception as exc:
                    raise GuestServiceBlocked("unmapped_guest_read_destination") from exc
            self.bytes_returned+=len(data)
            return count
        if name=="fclose":
            return stream.close(rcx)
        if name=="rewind":
            result=stream.seek(rcx,0,0)
            if result:return -1
            return 0
        if name=="fgetc":
            return stream.getc(rcx)
        if name=="feof":
            stream.require_handle(rcx)
            return int(stream.cursor>=len(stream.content))
        raise GuestServiceBlocked("unimplemented_import")
