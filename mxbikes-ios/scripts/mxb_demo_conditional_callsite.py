"""Verify a narrowly scoped conditional Win64 import wrapper using dynamic trace.

No general indirect branch permission. Disk and mapped bytes must match, the
fallback pointer must be zero, and the observed path must take the IAT jump.
"""
import struct


def prove_conditional_callsite(pe,iat,base,read_guest,return_va,import_pc,library,symbol,recent):
    ret=return_va-base
    if not 5<=ret<2**32 or not 0<import_pc<2**64:return None
    executable=[(rva,rva+raw) for _,_,rva,raw,_,flags in pe.sections if flags&0x20000000 and raw]
    def verified(rva,n):
        if not any(lo<=rva and rva+n<=hi for lo,hi in executable):return None
        a=bytes(pe.read_rva(rva,n));b=bytes(read_guest(base+rva,n))
        return a if len(a)==n and a==b else None
    try:
        call=verified(ret-5,5)
        if not call or call[0]!=0xe8:return None
        start=ret+struct.unpack_from('<i',call,1)[0]
        body=verified(start,22)
        if not body or body[:3]!=b'\x48\x8b\x05' or body[7:18]!=b'\x48\x85\xc0\x74\x03\x48\xff\xe0\x48\xff\x25':return None
        if list(recent[-5:])!=[ret-5,start,start+7,start+10,start+15]:return None
        pointer=start+7+struct.unpack_from('<i',body,3)[0]
        slot=start+22+struct.unpack_from('<i',body,18)[0]
        if not 0<=pointer<=2**32-8 or not 0<=slot<=2**32-8:return None
        if bytes(read_guest(base+pointer,8))!=bytes(8):return None
        if iat.get(slot)!=(library.lower(),symbol) or bytes(read_guest(base+slot,8))!=struct.pack('<Q',import_pc):return None
    except (ValueError,KeyError,IndexError,TypeError,struct.error,OSError):return None
    # Unicorn's UcError is not part of this dependency-free verifier; the
    # calling runner catches memory-access exceptions at its import boundary.
    return {'original_call_rva':hex(ret-5),'original_thunk_rva':hex(start),
            'original_iat_rva':hex(slot),'import':library+'!'+symbol,
            'call_form':'conditional_null_pointer_iat_fallback','trace_verified':True}
