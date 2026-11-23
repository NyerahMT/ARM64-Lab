#!/usr/bin/env python3
"""Single SHA-verified original CRT malloc research bridge.

Provides bounded guest virtual RAM to the already running original x64
Unicorn interpreter. This is intentionally a one-call diagnostic, not a
general Windows malloc replacement, not a game patch and not an iOS heap.
"""
from __future__ import annotations
import struct
from unicorn.x86_const import UC_X86_REG_RSP,UC_X86_REG_RAX,UC_X86_REG_RCX,UC_X86_REG_RDX,UC_X86_REG_R8,UC_X86_REG_R9

IMAGE_BASE=0x140000000
MALLOC_ORIGINAL_CALL_RVA=0x283956
MALLOC_ORIGINAL_RETURN_RVA=0x28395B
SECOND_MALLOC_CALL_RVA=0x2DCDC9
SECOND_MALLOC_RETURN_RVA=SECOND_MALLOC_CALL_RVA+5
SECOND_MALLOC_BYTES=48
SECOND_HEAP_BASE=0x7B0000000
SECOND_HEAP_MAP_SIZE=0x1000
SECOND_HEAP_RESULT=SECOND_HEAP_BASE+0x100
# A deterministic guest-only bump heap for further ORIGINAL imported malloc
# calls. No host allocation pointers ever cross this Win64 ABI boundary.
FOLLOWUP_HEAP_BASE=0x7C0000000
FOLLOWUP_HEAP_MAX_CALLS=32
FOLLOWUP_HEAP_MAX_SINGLE_BYTES=2*1024*1024
FOLLOWUP_HEAP_MAX_TOTAL_BYTES=16*1024*1024
FOLLOWUP_HEAP_GUEST_OFFSET=0x100
MEMMOVE_ZERO_ORIGINAL_CALL_RVA=0x15C1AA
MEMMOVE_ZERO_ORIGINAL_RETURN_RVA=MEMMOVE_ZERO_ORIGINAL_CALL_RVA+5
INITIALIZE_296_MEMSET_CALL_RVA=0x15C1F2
INITIALIZE_296_MEMSET_RETURN_RVA=INITIALIZE_296_MEMSET_CALL_RVA+5
INITIALIZE_296_BYTES=296

MEMSET_ORIGINAL_CALL_RVA=0x28396D
MEMSET_ORIGINAL_RETURN_RVA=0x283972
SPRINTF_ORIGINAL_CALL_RVA=0x285469
SPRINTF_ORIGINAL_RETURN_RVA=SPRINTF_ORIGINAL_CALL_RVA+5
SPRINTF_IPV4_FORMAT=b"%lu.%lu.%lu.%lu"+bytes((0,))
SPRINTF_IPV4_OUTPUT=b"127.0.0.1"+bytes((0,))
SECOND_MEMSET_CALL_RVA=0x284CF9
SECOND_MEMSET_RETURN_RVA=SECOND_MEMSET_CALL_RVA+5
SECOND_MEMSET_LENGTH=400
THIRD_MEMSET_CALL_RVA=0x2A7D03
THIRD_MEMSET_RETURN_RVA=THIRD_MEMSET_CALL_RVA+5
THIRD_MEMSET_LENGTH=3776
FOURTH_MEMSET_CALL_RVA=0x297857
FOURTH_MEMSET_RETURN_RVA=FOURTH_MEMSET_CALL_RVA+5
FOURTH_MEMSET_LENGTH=4666112
FIFTH_MEMSET_CALL_RVA=0x297885
FIFTH_MEMSET_RETURN_RVA=FIFTH_MEMSET_CALL_RVA+5
FIFTH_MEMSET_LENGTH=45056
SIXTH_MEMSET_CALL_RVA=0x2AEF6D
SIXTH_MEMSET_RETURN_RVA=SIXTH_MEMSET_CALL_RVA+5
SIXTH_MEMSET_LENGTH=5184
# Exact original verified PE-image zero-fill import sites, in execution order.
# These are not general-purpose memset aliases; unknown sites fail closed.
IMAGE_MEMSET_STEPS=(
    (SECOND_MEMSET_CALL_RVA,SECOND_MEMSET_RETURN_RVA,SECOND_MEMSET_LENGTH),
    (THIRD_MEMSET_CALL_RVA,THIRD_MEMSET_RETURN_RVA,THIRD_MEMSET_LENGTH),
    (FOURTH_MEMSET_CALL_RVA,FOURTH_MEMSET_RETURN_RVA,FOURTH_MEMSET_LENGTH),
    (FIFTH_MEMSET_CALL_RVA,FIFTH_MEMSET_RETURN_RVA,FIFTH_MEMSET_LENGTH),
    (SIXTH_MEMSET_CALL_RVA,SIXTH_MEMSET_RETURN_RVA,SIXTH_MEMSET_LENGTH),
)
IMAGE_SCN_MEM_WRITE=0x80000000
IMAGE_SCN_MEM_EXECUTE=0x20000000
BOUNDED_IMAGE_MEMSET_MAX_CALLS=24
BOUNDED_IMAGE_MEMSET_MAX_BYTES=8*1024*1024
BOUNDED_IMAGE_MEMSET_TOTAL_LIMIT=32*1024*1024

EXPECTED_ALLOC_BYTES=0x2580
HEAP_BASE=0x790000000
HEAP_BYTES=0x100000
HEAP_RESULT=HEAP_BASE+0x100

class GuestHeapResearchRejected(ValueError):pass

class SingleGuestMallocResearch:
    def __init__(self):
        self.called=False
        self.events=[]
        self.second_malloc_events=[]
        self.followup_malloc_events=[]
        self.zero_len_memmove_events=[]
        self.followup_heap_memset_events=[]
        self.followup_heap_cursor=0
        self.memset_events=[]
        self.image_memset_events=[]
        self.bounded_image_memset_events=[]
        self.sprintf_events=[]

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

    def handle_second_malloc(self,u,pe,slots,library,symbol,verify):
        """One 48-byte guest allocation through verified original lazy CRT wrapper.

        Validates the original E8 CALL to 0x2BD710, complete lazy-wrapper
        shape, original import-slot identity (via verify), and Win64 ABI.
        The guest receives a new mapped page, never a host pointer.
        """
        if library.lower()!="msvcr90.dll" or symbol!="malloc":
            return False
        if (not self.called or self.second_malloc_events or
            len(self.image_memset_events)!=4):
            raise GuestHeapResearchRejected("second_malloc_original_order_or_budget")
        rsp=u.reg_read(UC_X86_REG_RSP)
        size=u.reg_read(UC_X86_REG_RCX)
        if rsp&15!=8 or size!=SECOND_MALLOC_BYTES:
            raise GuestHeapResearchRejected("second_malloc_original_size_or_stack_mismatch")
        try:
            ret=struct.unpack("<Q",bytes(u.mem_read(rsp,8)))[0]
        except Exception as exc:
            raise GuestHeapResearchRejected("second_malloc_unreadable_original_stack") from exc
        if (ret!=IMAGE_BASE+SECOND_MALLOC_RETURN_RVA or
            verify(pe,ret,library,symbol,slots)!=hex(SECOND_MALLOC_CALL_RVA)):
            raise GuestHeapResearchRejected("second_malloc_original_lazy_wrapper_not_verified")
        try:
            u.mem_map(SECOND_HEAP_BASE,SECOND_HEAP_MAP_SIZE)
        except Exception as exc:
            raise GuestHeapResearchRejected("second_malloc_guest_page_unavailable") from exc
        u.reg_write(UC_X86_REG_RAX,SECOND_HEAP_RESULT)
        self.second_malloc_events.append({
            "original_call_rva":hex(SECOND_MALLOC_CALL_RVA),
            "malloc_wrapper_target_rva":"0x2bd710",
            "requested_bytes":SECOND_MALLOC_BYTES,
            "guest_heap_mapping_bytes":SECOND_HEAP_MAP_SIZE,
            "original_msvcr90_malloc_executed":False,
        })
        return True

    def handle_followup_malloc(self,u,pe,slots,library,symbol,verify):
        """Bounded guest RAM malloc from the exact original lazy CRT wrapper.

        Only callable after the original 48-byte allocation and the first
        verified *additional* image memset. This handles a real original PE
        CALL via the original SHA-pinned 0x2bd710 lazy malloc wrapper, not a
        generic pointer trampoline. No host memory is exposed to the game.
        """
        if library.lower()!="msvcr90.dll" or symbol!="malloc":
            return False
        if (len(self.second_malloc_events)!=1
            or len(self.image_memset_events)!=len(IMAGE_MEMSET_STEPS)
            or not self.bounded_image_memset_events):
            raise GuestHeapResearchRejected("followup_malloc_original_sequence")
        if len(self.followup_malloc_events)>=FOLLOWUP_HEAP_MAX_CALLS:
            raise GuestHeapResearchRejected("followup_malloc_call_budget")
        rsp=u.reg_read(UC_X86_REG_RSP)
        request=u.reg_read(UC_X86_REG_RCX)
        if rsp&15!=8 or not isinstance(request,int):
            raise GuestHeapResearchRejected("followup_malloc_original_win64_abi")
        if request<=0 or request>FOLLOWUP_HEAP_MAX_SINGLE_BYTES:
            raise GuestHeapResearchRejected("followup_malloc_size_budget")
        try:
            ret=struct.unpack("<Q",bytes(u.mem_read(rsp,8)))[0]
        except Exception as exc:
            raise GuestHeapResearchRejected("followup_malloc_unreadable_return") from exc
        call=verify(pe,ret,library,symbol,slots)
        if call is None:
            raise GuestHeapResearchRejected("followup_malloc_original_import_unverified")
        try:
            call_rva=int(call,16)
        except (TypeError,ValueError) as exc:
            raise GuestHeapResearchRejected("followup_malloc_original_callsite_invalid") from exc
        if call_rva in (MALLOC_ORIGINAL_CALL_RVA,SECOND_MALLOC_CALL_RVA):
            raise GuestHeapResearchRejected("followup_malloc_prior_callsite_repeated")
        size_to_map=(request+FOLLOWUP_HEAP_GUEST_OFFSET+0xfff)&~0xfff
        if self.followup_heap_cursor+size_to_map>FOLLOWUP_HEAP_MAX_TOTAL_BYTES:
            raise GuestHeapResearchRejected("followup_malloc_aggregate_memory_budget")
        map_address=FOLLOWUP_HEAP_BASE+self.followup_heap_cursor
        guest_ptr=map_address+FOLLOWUP_HEAP_GUEST_OFFSET
        try:
            u.mem_map(map_address,size_to_map)
        except Exception as exc:
            raise GuestHeapResearchRejected("followup_malloc_guest_mapping_failed") from exc
        u.reg_write(UC_X86_REG_RAX,guest_ptr)
        self.followup_heap_cursor+=size_to_map
        self.followup_malloc_events.append({
            "original_call_rva":hex(call_rva),
            "requested_bytes":request,
            "mapped_guest_bytes":size_to_map,
            "synthetic_guest_pointer_valid":True,
            "original_windows_crt_executed":False,
        })
        return True

    def handle_zero_len_memmove(self,u,pe,slots,library,symbol,verify):
        """One authentic Win64 CRT memmove(dst,src,0), no guest memory touched.

        Validate call from exact original code; both pointers must be in the
        mapped, bounded guest heap that this research runner allocated. The
        Windows CRT return value is dst. Unknown lengths and destinations
        remain unsupported.
        """
        if library.lower()!="msvcr90.dll" or symbol!="memmove":
            return False
        if not self.followup_malloc_events or self.zero_len_memmove_events:
            raise GuestHeapResearchRejected("zero_memmove_original_order_or_budget")
        rsp=u.reg_read(UC_X86_REG_RSP)
        dest=u.reg_read(UC_X86_REG_RCX)
        src=u.reg_read(UC_X86_REG_RDX)
        n=u.reg_read(UC_X86_REG_R8)
        heap_end=FOLLOWUP_HEAP_BASE+self.followup_heap_cursor
        if (rsp&15!=8 or n!=0 or
            not FOLLOWUP_HEAP_BASE<=dest<heap_end or
            not FOLLOWUP_HEAP_BASE<=src<heap_end):
            raise GuestHeapResearchRejected("zero_memmove_original_abi_or_pointer_unverified")
        try:
            ret=struct.unpack("<Q",bytes(u.mem_read(rsp,8)))[0]
        except Exception as exc:
            raise GuestHeapResearchRejected("zero_memmove_guest_return_unreadable") from exc
        if (ret!=IMAGE_BASE+MEMMOVE_ZERO_ORIGINAL_RETURN_RVA or
            verify(pe,ret,library,symbol,slots)!=hex(MEMMOVE_ZERO_ORIGINAL_CALL_RVA)):
            raise GuestHeapResearchRejected("zero_memmove_original_import_not_verified")
        u.reg_write(UC_X86_REG_RAX,dest)
        self.zero_len_memmove_events.append({
            "original_call_rva":hex(MEMMOVE_ZERO_ORIGINAL_CALL_RVA),
            "bytes_moved":0,
            "guest_memory_read_or_written":False,
            "host_crt_used":False,
        })
        return True

    def handle_followup_heap_memset(self,u,pe,slots,library,symbol,verify):
        """Original single 296-byte memset on the most recent 296-byte malloc.

        No PE data / host pointer may be touched; the entire zero fill must
        fit the LAST allocation's recorded requested bounds (not page slack).
        """
        if library.lower()!="msvcr90.dll" or symbol!="memset":
            return False
        if (not self.zero_len_memmove_events or self.followup_heap_memset_events
            or not self.followup_malloc_events):
            raise GuestHeapResearchRejected("followup_heap_memset_original_sequence_or_budget")
        last=self.followup_malloc_events[-1]
        requested=last.get("requested_bytes")
        mapped=last.get("mapped_guest_bytes")
        if requested!=INITIALIZE_296_BYTES or not isinstance(mapped,int):
            raise GuestHeapResearchRejected("followup_heap_memset_last_allocation_mismatch")
        last_ptr=(FOLLOWUP_HEAP_BASE+self.followup_heap_cursor-mapped
                  +FOLLOWUP_HEAP_GUEST_OFFSET)
        rsp=u.reg_read(UC_X86_REG_RSP)
        dest=u.reg_read(UC_X86_REG_RCX)
        fill=u.reg_read(UC_X86_REG_RDX)
        length=u.reg_read(UC_X86_REG_R8)
        if (rsp&15!=8 or dest!=last_ptr or fill!=0
            or length!=INITIALIZE_296_BYTES):
            raise GuestHeapResearchRejected("followup_heap_memset_original_abi_or_bounds")
        try:
            ret=struct.unpack("<Q",bytes(u.mem_read(rsp,8)))[0]
        except Exception as exc:
            raise GuestHeapResearchRejected("followup_heap_memset_unreadable_return") from exc
        if (ret!=IMAGE_BASE+INITIALIZE_296_MEMSET_RETURN_RVA or
            verify(pe,ret,library,symbol,slots)!=hex(INITIALIZE_296_MEMSET_CALL_RVA)):
            raise GuestHeapResearchRejected("followup_heap_memset_original_callsite_unverified")
        try:
            if len(u.mem_read(dest,length))!=length:
                raise GuestHeapResearchRejected("followup_heap_memset_guest_buffer_short")
        except GuestHeapResearchRejected:
            raise
        except Exception as exc:
            raise GuestHeapResearchRejected("followup_heap_memset_guest_buffer_unmapped") from exc
        try:
            u.mem_write(dest,bytes(length))
        except Exception as exc:
            raise GuestHeapResearchRejected("followup_heap_memset_guest_write_failed") from exc
        u.reg_write(UC_X86_REG_RAX,dest)
        self.followup_heap_memset_events.append({
            "original_call_rva":hex(INITIALIZE_296_MEMSET_CALL_RVA),
            "zeroed_bytes":length,
            "bounded_to_last_guest_allocation":True,
            "host_memory_or_CRT_used":False,
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
        """Five independently verified original PE-data zero-fills.

        The first clears 400 writable bytes; following original IPv4 formatting,
        subsequent calls clear 3776, 4666112, and 45056 bytes. Never clear
        arbitrary regions or write to executable or read-only PE sections.
        """
        if library.lower()!="msvcr90.dll" or symbol!="memset":
            return False
        count=len(self.image_memset_events)
        if not self.memset_events or count>=len(IMAGE_MEMSET_STEPS):
            raise GuestHeapResearchRejected("image_memset_order_or_budget")
        if count==0:
            if self.sprintf_events:
                raise GuestHeapResearchRejected("image_memset_wrong_stage")
        elif len(self.sprintf_events)!=1:
            raise GuestHeapResearchRejected("image_memset_before_original_ipv4_sprintf")
        if count==4 and len(self.second_malloc_events)!=1:
            raise GuestHeapResearchRejected("sixth_memset_before_verified_second_malloc")
        call,ret_rva,length=IMAGE_MEMSET_STEPS[count]
        rsp=u.reg_read(UC_X86_REG_RSP)
        dest=u.reg_read(UC_X86_REG_RCX)
        fill=u.reg_read(UC_X86_REG_RDX)
        requested=u.reg_read(UC_X86_REG_R8)
        if rsp&15!=8 or not dest or fill!=0 or requested!=length:
            raise GuestHeapResearchRejected("original_image_memset_abi_mismatch")
        try:
            return_pc=struct.unpack("<Q",bytes(u.mem_read(rsp,8)))[0]
        except Exception as exc:
            raise GuestHeapResearchRejected("original_image_memset_unreadable_return") from exc
        if (return_pc!=IMAGE_BASE+ret_rva or
            verify(pe,return_pc,library,symbol,slots)!=hex(call)):
            raise GuestHeapResearchRejected("original_image_memset_callsite_mismatch")
        section=None
        rva=dest-IMAGE_BASE
        for name,vsize,base,rawsize,_,flags in pe.sections:
            span=max(vsize,rawsize)
            if (rva>=base and rva-base<=span-length and
                flags&IMAGE_SCN_MEM_WRITE and not flags&IMAGE_SCN_MEM_EXECUTE):
                section=name
                break
        if section is None:
            raise GuestHeapResearchRejected("original_image_memset_not_safe_pe_data")
        try:
            if len(u.mem_read(dest,length))!=length:
                raise GuestHeapResearchRejected("original_image_memset_guest_range_short")
        except GuestHeapResearchRejected:
            raise
        except Exception as exc:
            raise GuestHeapResearchRejected("original_image_memset_guest_range_unmapped") from exc
        try:
            u.mem_write(dest,bytes(length))
        except Exception as exc:
            raise GuestHeapResearchRejected("original_image_memset_guest_write_rejected") from exc
        u.reg_write(UC_X86_REG_RAX,dest)
        self.image_memset_events.append({
            "original_call_rva":hex(call),
            "writable_data_section_name":section,
            "zeroed_original_guest_data_bytes":length,
            "original_msvcr90_memset_executed":False,
        })
        return True

    def handle_bounded_image_memset(self,u,pe,slots,library,symbol,verify):
        """Guest-only CRT zero-fill for later proven original import CALLs.

        Only after the five fixed, verified initializer CALLs (including the
        second 48-byte malloc) may the research runner accept additional
        original-image zero fills. Every individual call must come from the
        unmodified original PE IAT (or its authenticated jump thunk), target
        exactly one mapped writable/non-executable image section, request zero
        fill, and stay within per-call and aggregate budgets. No host memory
        or original file bytes are modified. This is not a general game loader.
        """
        if library.lower()!="msvcr90.dll" or symbol!="memset":
            return False
        if (len(self.image_memset_events)!=len(IMAGE_MEMSET_STEPS)
            or len(self.second_malloc_events)!=1
            or len(self.sprintf_events)!=1):
            raise GuestHeapResearchRejected("bounded_memset_original_startup_prerequisite")
        if len(self.bounded_image_memset_events)>=BOUNDED_IMAGE_MEMSET_MAX_CALLS:
            raise GuestHeapResearchRejected("bounded_memset_call_budget")
        rsp=u.reg_read(UC_X86_REG_RSP)
        dest=u.reg_read(UC_X86_REG_RCX)
        fill=u.reg_read(UC_X86_REG_RDX)
        size=u.reg_read(UC_X86_REG_R8)
        if rsp&15!=8 or fill!=0 or not dest or not isinstance(size,int):
            raise GuestHeapResearchRejected("bounded_memset_original_win64_abi")
        if size<=0 or size>BOUNDED_IMAGE_MEMSET_MAX_BYTES:
            raise GuestHeapResearchRejected("bounded_memset_invalid_size")
        used=sum(item["zeroed_original_guest_data_bytes"]
                 for item in self.bounded_image_memset_events)
        if used+size>BOUNDED_IMAGE_MEMSET_TOTAL_LIMIT:
            raise GuestHeapResearchRejected("bounded_memset_aggregate_budget")
        try:
            ret=struct.unpack("<Q",bytes(u.mem_read(rsp,8)))[0]
        except Exception as exc:
            raise GuestHeapResearchRejected("bounded_memset_unreadable_stack_return") from exc
        exact_call=verify(pe,ret,library,symbol,slots)
        if exact_call is None:
            raise GuestHeapResearchRejected("bounded_memset_original_import_unverified")
        try:
            call_rva=int(exact_call,16)
        except (ValueError,TypeError) as exc:
            raise GuestHeapResearchRejected("bounded_memset_import_provenance_malformed") from exc
        if call_rva in {original for original,_,_ in IMAGE_MEMSET_STEPS}:
            raise GuestHeapResearchRejected("bounded_memset_prior_initializer_repeated")
        rva=dest-IMAGE_BASE
        section=None
        for name,vsize,start,rawsize,_,flags in pe.sections:
            span=max(vsize,rawsize)
            if (rva>=start and rva-start<=span-size and
                flags&IMAGE_SCN_MEM_WRITE and not flags&IMAGE_SCN_MEM_EXECUTE):
                section=name
                break
        if section is None:
            raise GuestHeapResearchRejected("bounded_memset_outside_safe_original_pe_data")
        try:
            if len(u.mem_read(dest,size))!=size:
                raise GuestHeapResearchRejected("bounded_memset_short_guest_range")
        except GuestHeapResearchRejected:
            raise
        except Exception as exc:
            raise GuestHeapResearchRejected("bounded_memset_guest_range_unmapped") from exc
        try:
            u.mem_write(dest,bytes(size))
        except Exception as exc:
            raise GuestHeapResearchRejected("bounded_memset_guest_write_failed") from exc
        u.reg_write(UC_X86_REG_RAX,dest)
        self.bounded_image_memset_events.append({
            "original_call_rva":hex(call_rva),
            "writable_data_section_name":section,
            "zeroed_original_guest_data_bytes":size,
            "original_msvcr90_memset_executed":False,
        })
        return True

    def handle_sprintf_ipv4(self,u,pe,slots,library,symbol,verify):
        """ONE authentic MSVCR90 sprintf using original IPv4 %lu form.

        The only supported format is the SHA-pinned game's exact 4-argument
        dotted decimal sequence. This is NOT an arbitrary format interpreter:
        it performs no percent-n, pointer dereferences, Unicode, or host CRT.
        """
        if library.lower()!="msvcr90.dll" or symbol!="sprintf":
            return False
        if len(self.image_memset_events)!=1 or self.sprintf_events:
            raise GuestHeapResearchRejected("sprintf_original_order_or_budget")
        rsp=u.reg_read(UC_X86_REG_RSP)
        dst=u.reg_read(UC_X86_REG_RCX)
        fmt=u.reg_read(UC_X86_REG_RDX)
        if rsp&15!=8 or not dst or not fmt or dst&7:
            raise GuestHeapResearchRejected("sprintf_original_abi_or_alignment")
        try:
            ret=struct.unpack("<Q",bytes(u.mem_read(rsp,8)))[0]
            args=struct.unpack("<QQ",bytes(u.mem_read(rsp+0x28,16)))
            fmt_bytes=bytes(u.mem_read(fmt,len(SPRINTF_IPV4_FORMAT)))
        except Exception as exc:
            raise GuestHeapResearchRejected("sprintf_original_guest_operand_unmapped") from exc
        if (ret!=IMAGE_BASE+SPRINTF_ORIGINAL_RETURN_RVA or
            verify(pe,ret,library,symbol,slots)!=hex(SPRINTF_ORIGINAL_CALL_RVA)):
            raise GuestHeapResearchRejected("sprintf_original_callsite_mismatch")
        if fmt_bytes!=SPRINTF_IPV4_FORMAT:
            raise GuestHeapResearchRejected("sprintf_unexpected_original_format")
        octets=(u.reg_read(UC_X86_REG_R8)&0xffffffff,
                u.reg_read(UC_X86_REG_R9)&0xffffffff,
                args[0]&0xffffffff,args[1]&0xffffffff)
        if octets!=(127,0,0,1):
            raise GuestHeapResearchRejected("sprintf_original_address_arguments_changed")
        if IMAGE_BASE<=dst<IMAGE_BASE+0x8000000:
            raise GuestHeapResearchRejected("sprintf_unexpected_original_image_destination")
        try:
            if len(u.mem_read(dst,len(SPRINTF_IPV4_OUTPUT)))!=len(SPRINTF_IPV4_OUTPUT):
                raise GuestHeapResearchRejected("sprintf_guest_destination_short")
        except GuestHeapResearchRejected:
            raise
        except Exception as exc:
            raise GuestHeapResearchRejected("sprintf_guest_destination_unmapped") from exc
        try:
            u.mem_write(dst,SPRINTF_IPV4_OUTPUT)
        except Exception as exc:
            raise GuestHeapResearchRejected("sprintf_guest_destination_not_writable") from exc
        u.reg_write(UC_X86_REG_RAX,len(SPRINTF_IPV4_OUTPUT)-1)
        self.sprintf_events.append({
            "original_call_rva":hex(SPRINTF_ORIGINAL_CALL_RVA),
            "formatted_verified_ipv4_octets":4,
            "guest_output_bytes_including_nul":len(SPRINTF_IPV4_OUTPUT),
            "synthetic_guest_crt_only":True,
        })
        return True

    def summary(self):
        return {"synthetic_original_malloc_count":len(self.events),
                "synthetic_original_second_malloc_count":len(self.second_malloc_events),
                "second_malloc_events":list(self.second_malloc_events),
                "bounded_followup_malloc_count":len(self.followup_malloc_events),
                "bounded_followup_malloc_events":list(self.followup_malloc_events),
                "bounded_followup_malloc_mapped_bytes":self.followup_heap_cursor,
                "original_zero_length_memmove_count":len(self.zero_len_memmove_events),
                "original_zero_length_memmove_events":list(self.zero_len_memmove_events),
                "original_followup_heap_memset_count":len(self.followup_heap_memset_events),
                "original_followup_heap_memset_events":list(self.followup_heap_memset_events),
                "synthetic_original_memset_count":len(self.memset_events),
                "allocations":list(self.events),
                "memset_events":list(self.memset_events),
                "synthetic_original_image_memset_count":len(self.image_memset_events),
                "original_image_memset_events":list(self.image_memset_events),
                "bounded_original_image_memset_count":len(self.bounded_image_memset_events),
                "bounded_original_image_memset_events":list(self.bounded_image_memset_events),
                "bounded_original_image_memset_total_bytes":sum(
                    e["zeroed_original_guest_data_bytes"]
                    for e in self.bounded_image_memset_events),
                "original_ipv4_sprintf_count":len(self.sprintf_events),
                "sprintf_events":list(self.sprintf_events),
                "guest_malloc_semantics_are_synthetic":True,
                "original_windows_crt_executed":False}
