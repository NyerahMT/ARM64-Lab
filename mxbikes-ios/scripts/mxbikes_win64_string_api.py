#!/usr/bin/env python3
"""Bounded Win64 CRT strcpy for original private x64 startup smoke.

Only copies actual NUL-terminated guest bytes from explicitly readable mapped
regions into verified writable guest memory. Strictly refuses invalid inputs,
source/destination overlap, unbounded strings, or unmapped addresses. Does not
substitute invented strings or translate any original functions to ARM64.
"""
from unicorn import UcError
from unicorn.x86_const import UC_X86_REG_RAX

MAX_CRT_COPY_BYTES=4096

def contains(regions,ptr,length):
    return (ptr>0 and length>=0 and
            any(lo<=ptr and ptr+length<=hi for lo,hi in regions))

def model_guest_strcpy(uc,destination,source,*,readable_ranges,writable_ranges,
                      max_bytes=MAX_CRT_COPY_BYTES):
    if not (1<=max_bytes<=MAX_CRT_COPY_BYTES and
            contains(readable_ranges,source,1) and
            contains(writable_ranges,destination,1)):
        return False
    # Only read up to the end of this explicit guest input segment.
    src_remaining=max(hi-source for lo,hi in readable_ranges
                      if lo<=source<hi)
    limit=min(max_bytes,src_remaining)
    if limit<=0:return False
    try:
        raw=bytes(uc.mem_read(source,limit))
    except (UcError,ValueError):
        return False
    nul=raw.find(b"\x00")
    if nul<0:return False
    count=nul+1
    if not contains(writable_ranges,destination,count):
        return False
    if destination<source+count and source<destination+count:
        return False
    try:uc.mem_write(destination,raw[:count])
    except (UcError,ValueError):return False
    uc.reg_write(UC_X86_REG_RAX,destination)
    return True


def model_guest_strrchr(uc,source,character,*,readable_ranges,
                       max_bytes=MAX_CRT_COPY_BYTES):
    """Exact bounded CRT strrchr: return last byte address or NULL.

    Search includes the NUL terminator when (character & 0xff) == 0.
    Unknown source bounds or unterminated guest strings fail closed.
    """
    if not (1<=max_bytes<=MAX_CRT_COPY_BYTES and
            contains(readable_ranges,source,1)):
        return False
    remaining=max(hi-source for lo,hi in readable_ranges if lo<=source<hi)
    n=min(remaining,max_bytes)
    try:raw=bytes(uc.mem_read(source,n))
    except (UcError,ValueError):return False
    ending=raw.find(b"\x00")
    if ending<0:return False
    target=character&0xff
    where=ending if target==0 else raw[:ending].rfind(bytes([target]))
    uc.reg_write(UC_X86_REG_RAX,source+where if where>=0 else 0)
    return True


def _bounded_original_c_string(uc,source,readable_ranges,
                               max_bytes=MAX_CRT_COPY_BYTES):
    if not (1<=max_bytes<=MAX_CRT_COPY_BYTES and
            contains(readable_ranges,source,1)):
        return None
    available=max(hi-source for lo,hi in readable_ranges if lo<=source<hi)
    try:data=bytes(uc.mem_read(source,min(available,max_bytes)))
    except (UcError,ValueError):return None
    ending=data.find(b"\x00")
    return data[:ending+1] if ending>=0 else None

def model_guest_strlen(uc,source,*,readable_ranges):
    raw=_bounded_original_c_string(uc,source,readable_ranges)
    if raw is None:return False
    uc.reg_write(UC_X86_REG_RAX,len(raw)-1)
    return True

def model_guest_strchr(uc,source,character,*,readable_ranges):
    raw=_bounded_original_c_string(uc,source,readable_ranges)
    if raw is None:return False
    where=raw.find(bytes([character&255]))
    uc.reg_write(UC_X86_REG_RAX,source+where if where>=0 else 0)
    return True

def model_guest_strcmp(uc,a,b,*,readable_ranges):
    first=_bounded_original_c_string(uc,a,readable_ranges)
    second=_bounded_original_c_string(uc,b,readable_ranges)
    if first is None or second is None:return False
    for left,right in zip(first,second):
        if left!=right:
            result=left-right
            break
        if left==0:
            result=0
            break
    else:
        return False
    uc.reg_write(UC_X86_REG_RAX,result&0xffffffff)
    return True
