#!/usr/bin/env python3
"""Single SHA-verified original CRT malloc research bridge.

Provides bounded guest virtual RAM to the already running original x64
Unicorn interpreter. This is intentionally a one-call diagnostic, not a
general Windows malloc replacement, not a game patch and not an iOS heap.
"""
from __future__ import annotations
import struct
from unicorn.x86_const import UC_X86_REG_RSP,UC_X86_REG_RAX,UC_X86_REG_RCX,UC_X86_REG_RDX,UC_X86_REG_R8

IMAGE_BASE=0x140000000
MALLOC_ORIGINAL_CALL_RVA=0x283956
MALLOC_ORIGINAL_RETURN_RVA=0x28395B
MEMSET_ORIGINAL_CALL_RVA=0x28396D
MEMSET_ORIGINAL_RETURN_RVA=0x283972
SECOND_MEMSET_CALL_RVA=0x284CF9
SECOND_MEMSET_RETURN_RVA=SECOND_MEMSET_CALL_RVA+5
SECOND_MEMSET_LENGTH=400
IMAGE_SCN_MEM_WRITE=0x80000000
IMAGE_SCN_MEM_EXECUTE=0x20000000
EXPECTED_ALLOC_BYTES=0x2580
HEAP_BASE=0x790000000
HEAP_BYTES=0x100000
HEAP_RESULT=HEAP_BASE+0x100

class GuestHeapResearchRejected(ValueError):pass

class SingleGuestMallocResearch:
    def __init__(self):
        self.called=False
        self.events=[]
        self.memset_events=[]
        self.image_memset_events=[]

    def handle(self,u,pe,slots,library,symbol,verify):
        if library.lower()!="msvcr90.dll" or symbol!="malloc":
            return False
        if self.called:
            raise GuestHeapResearchRejected("unexpected_second_malloc")
        rsp=u.reg_read(UC_X86_REG_RSP)
        size=u.reg_read(UC_X86_REG_RCX)
        if (rsp&0xf)!=8:
            raise GuestHeapResearchRejected("original_malloc_stack_alignment")
        if size!=EXPECTED_ALLOC_BYTES:
            raise GuestHeapResearchRejected("original_malloc_alloc_size_drift")
        try:
            ret=struct.unpack("<Q",bytes(u.mem_read(rsp,8)))[0]
        except Exception as exc:
            raise GuestHeapResearchRejected("malloc_guest_stack_unmapped") from exc
        if (ret!=IMAGE_BASE+MALLOC_ORIGINAL_RETURN_RVA or
            verify(pe,ret,library,symbol,slots)!=hex(MALLOC_ORIGINAL_CALL_RVA)):
            raise GuestHeapResearchRejected("original_malloc_import_thunk_mismatch")
        try:
            u.mem_map(HEAP_BASE,HEAP_BYTES)
        except Exception as exc:
            raise GuestHeapResearchRejected("bounded_heap_mapping_unavailable") from exc
        # Unicorn initializes this guest page to zero; that is a deterministic
        # fixture property, NOT a Windows CRT guarantee for malloc.
        u.reg_write(UC_X86_REG_RAX,HEAP_RESULT)
        self.called=True
        self.events.append({
            "original_call_rva":hex(MALLOC_ORIGINAL_CALL_RVA),
            "requested_bytes":size,
            "guest_heap_mapped_bytes":HEAP_BYTES,
            "original_msvcr90_malloc_executed":False,
        })
        return True

    def handle_memset(self,u,pe,slots,library,symbol,verify):
        if library.lower()!="msvcr90.dll" or symbol!="memset":
            return False
        if not self.called or self.memset_events:
            raise GuestHeapResearchRejected("malloc_backed_memset_outside_one_call")
        rsp=u.reg_read(UC_X86_REG_RSP)
        ptr=u.reg_read(UC_X86_REG_RCX)
        value=u.reg_read(UC_X86_REG_RDX)
        length=u.reg_read(UC_X86_REG_R8)
        if (rsp&15)!=8 or ptr!=HEAP_RESULT or value!=0 or length!=EXPECTED_ALLOC_BYTES:
            raise GuestHeapResearchRejected("unexpected_original_memset_guest_arguments")
        try:
            ret=struct.unpack("<Q",bytes(u.mem_read(rsp,8)))[0]
        except Exception as exc:
            raise GuestHeapResearchRejected("memset_guest_stack_unmapped") from exc
        if (ret!=IMAGE_BASE+MEMSET_ORIGINAL_RETURN_RVA or
            verify(pe,ret,library,symbol,slots)!=hex(MEMSET_ORIGINAL_CALL_RVA)):
            raise GuestHeapResearchRejected("original_memset_import_thunk_mismatch")
        try:
            u.mem_write(ptr,bytes(EXPECTED_ALLOC_BYTES))
        except Exception as exc:
            raise GuestHeapResearchRejected("memset_unmapped_malloc_result") from exc
        u.reg_write(UC_X86_REG_RAX,ptr)
        self.memset_events.append({
            "original_call_rva":hex(MEMSET_ORIGINAL_CALL_RVA),
            "zeroed_guest_bytes":length,
            "original_msvcr90_memset_executed":False,
        })
        return True

    def handle_image_memset(self,u,pe,slots,library,symbol,verify):
        """One audited original 400-byte zeroing of non-executable PE data.

        The entire destination must fit inside a declared, writable,
        non-executable original section; guest CPU/memory remain untouched
        if the original CALL source, Win64 ABI, or size differs.
        """
        if library.lower()!="msvcr90.dll" or symbol!="memset":
            return False
        if self.image_memset_events or not self.memset_events:
            raise GuestHeapResearchRejected("second_memset_order_or_budget")
        rsp=u.reg_read(UC_X86_REG_RSP)
        dest=u.reg_read(UC_X86_REG_RCX)
        fill=u.reg_read(UC_X86_REG_RDX)
        length=u.reg_read(UC_X86_REG_R8)
        if rsp&15!=8 or not dest or fill!=0 or length!=SECOND_MEMSET_LENGTH:
            raise GuestHeapResearchRejected("original_second_memset_abi_mismatch")
        try:
            ret=struct.unpack("<Q",bytes(u.mem_read(rsp,8)))[0]
        except Exception as exc:
            raise GuestHeapResearchRejected("second_memset_unreadable_return") from exc
        if (ret!=IMAGE_BASE+SECOND_MEMSET_RETURN_RVA or
            verify(pe,ret,library,symbol,slots)!=hex(SECOND_MEMSET_CALL_RVA)):
            raise GuestHeapResearchRejected("second_memset_original_callsite_mismatch")
        section=None
        rva=dest-IMAGE_BASE
        for name,vsize,base,rawsize,_,flags in pe.sections:
            span=max(vsize,rawsize)
            if (rva>=base and rva-base<=span-SECOND_MEMSET_LENGTH and
                flags&IMAGE_SCN_MEM_WRITE and not flags&IMAGE_SCN_MEM_EXECUTE):
                section=name
                break
        if section is None:
            raise GuestHeapResearchRejected("second_memset_not_verified_writable_pe_data")
        try:
            if len(u.mem_read(dest,SECOND_MEMSET_LENGTH))!=SECOND_MEMSET_LENGTH:
                raise GuestHeapResearchRejected("second_memset_guest_range_short")
        except GuestHeapResearchRejected:
            raise
        except Exception as exc:
            raise GuestHeapResearchRejected("second_memset_guest_range_unmapped") from exc
        try:
            u.mem_write(dest,bytes(SECOND_MEMSET_LENGTH))
        except Exception as exc:
            raise GuestHeapResearchRejected("second_memset_guest_write_rejected") from exc
        u.reg_write(UC_X86_REG_RAX,dest)
        self.image_memset_events.append({
            "original_call_rva":hex(SECOND_MEMSET_CALL_RVA),
            "writable_data_section_name":section,
            "zeroed_original_guest_data_bytes":length,
            "original_msvcr90_memset_executed":False,
        })
        return True

    def summary(self):
        return {"synthetic_original_malloc_count":len(self.events),
                "synthetic_original_memset_count":len(self.memset_events),
                "allocations":list(self.events),
                "memset_events":list(self.memset_events),
                "synthetic_original_image_memset_count":len(self.image_memset_events),
                "original_image_memset_events":list(self.image_memset_events),
                "guest_malloc_semantics_are_synthetic":True,
                "original_windows_crt_executed":False}
