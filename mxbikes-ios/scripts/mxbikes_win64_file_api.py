#!/usr/bin/env python3
"""Read-only, original-file-backed CRT I/O for private x64 MX Bikes smoke.

Only steam_api64.dll from the user-supplied Game.zip may be opened. The actual
file bytes are loaded transiently by CI, never uploaded, patched, executed, or
invented. This does not model Steam authentication, a full MSVCR90 FILE layout,
or native ARM64 execution. Unrecognized file paths, modes, handles, memory
addresses and file offsets fail closed.
"""
from pathlib import Path
from unicorn.x86_const import UC_X86_REG_RAX

FILE_HANDLE_PAGE=0x770000000
MAX_ORIGINAL_DLL_SIZE=64*1024*1024
MAX_GUEST_READ_SIZE=65536
MAX_OPEN_HANDLES=16

def can_write(ranges,address,width):
    return address>0 and width>=0 and any(
        lo<=address and address+width<=hi for lo,hi in ranges)

class OriginalGuestFileIO:
    def __init__(self,original_dll_bytes):
        if not isinstance(original_dll_bytes,bytes):
            raise TypeError("Original supplied file data must be immutable bytes")
        if not 0<len(original_dll_bytes)<=MAX_ORIGINAL_DLL_SIZE:
            raise ValueError("Missing or oversized original DLL input")
        self.files={"steam_api64.dll":original_dll_bytes}
        self.handles={}
        self.next_handle=0
        self.events={"open":0,"read":0,"seek":0,"tell":0,"close":0,
                     "original_bytes_read":0}
    @classmethod
    def from_private_game_directory(cls,root):
        file=Path(root)/"steam_api64.dll"
        if not file.is_file() or not 0<file.stat().st_size<=MAX_ORIGINAL_DLL_SIZE:
            raise ValueError("Original Steam API DLL not available in private archive")
        return cls(file.read_bytes())
    def install(self,uc):
        uc.mem_map(FILE_HANDLE_PAGE,4096)
    def _handle(self,stream):
        return self.handles.get(stream)
    def fopen(self,uc,path,mode,*,cwd):
        if not isinstance(path,str) or not isinstance(mode,str):
            return False
        normalized=path.replace("/","\\").lower()
        wanted="steam_api64.dll"
        valid_paths={wanted,"c:\\mxbikes\\"+wanted}
        if (normalized not in valid_paths or mode!="rb" or
            cwd!="C:\\MXBikes" or
            self.next_handle>=MAX_OPEN_HANDLES):
            return False
        stream=FILE_HANDLE_PAGE+0x100+self.next_handle*0x40
        self.next_handle+=1
        self.handles[stream]={"path":wanted,"position":0}
        uc.mem_write(stream,b"\x00"*0x40)
        uc.reg_write(UC_X86_REG_RAX,stream)
        self.events["open"]+=1
        return True
    def fread(self,uc,buffer,size,count,stream,*,writable_ranges):
        handle=self._handle(stream)
        if handle is None or size<0 or count<0:return False
        if not size or not count:
            uc.reg_write(UC_X86_REG_RAX,0)
            self.events["read"]+=1
            return True
        if size>MAX_GUEST_READ_SIZE or count>MAX_GUEST_READ_SIZE:
            return False
        total=size*count
        if total>MAX_GUEST_READ_SIZE:return False
        data=self.files[handle["path"]]
        offset=handle["position"]
        consumed=min(total,max(0,len(data)-offset))
        if consumed and not can_write(writable_ranges,buffer,consumed):
            return False
        if consumed:
            uc.mem_write(buffer,data[offset:offset+consumed])
        handle["position"]=offset+consumed
        self.events["read"]+=1
        self.events["original_bytes_read"]+=consumed
        uc.reg_write(UC_X86_REG_RAX,consumed//size)
        return True
    def fseek(self,uc,stream,offset,origin):
        handle=self._handle(stream)
        if handle is None:return False
        offset32=offset&0xffffffff
        if offset32>=0x80000000:offset32-=0x100000000
        length=len(self.files[handle["path"]])
        if origin==0:start=0
        elif origin==1:start=handle["position"]
        elif origin==2:start=length
        else:return False
        target=start+offset32
        if not 0<=target<=MAX_ORIGINAL_DLL_SIZE:
            return False
        handle["position"]=target
        uc.reg_write(UC_X86_REG_RAX,0)
        self.events["seek"]+=1
        return True
    def ftell(self,uc,stream):
        handle=self._handle(stream)
        if handle is None:return False
        pos=handle["position"]
        if pos>0x7fffffff:return False
        uc.reg_write(UC_X86_REG_RAX,pos)
        self.events["tell"]+=1
        return True
    def fclose(self,uc,stream):
        if stream not in self.handles:return False
        del self.handles[stream]
        uc.reg_write(UC_X86_REG_RAX,0)
        self.events["close"]+=1
        return True
