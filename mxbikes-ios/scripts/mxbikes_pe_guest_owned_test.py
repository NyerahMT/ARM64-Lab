#!/usr/bin/env python3
"""Private actual-file PE guest mapping differential; metadata-only output.

No original code is executed, exported or authenticated. Host C loader maps
the owned file at its preferred guest VA and compares against independent PE
header parsing and raw/zero-filled section contents.
"""
import argparse, ctypes as C, hashlib, json, subprocess, sys, tempfile
from pathlib import Path
from mxbikes_native_slice_lift import ROOT,SHA
sys.path.insert(0,str(ROOT.parent))
from tools.pe_probe import PE

class Region(C.Structure):
    _fields_=[("base",C.c_uint64),("length",C.c_uint64),
              ("bytes",C.c_void_p),("permissions",C.c_uint)]
class Memory(C.Structure):
    _fields_=[("regions",Region*64),("count",C.c_uint)]
class Section(C.Structure):
    _fields_=[(n,C.c_uint32) for n in ("rva","virtual_size","raw_offset",
                                      "raw_size","mapped_size","permissions")]
class Plan(C.Structure):
    _fields_=[("image_base",C.c_uint64)]+[(n,C.c_uint32) for n in
        ("image_size","header_size","header_mapped_size","entry_rva","section_count")]+[
        ("sections",Section*48)]

def run(path):
    raw=path.read_bytes()
    if hashlib.sha256(raw).hexdigest()!=SHA:raise ValueError("Wrong owned executable")
    pe=PE(path)
    base=pe.u64(pe.opt+24);size=pe.u32(pe.opt+56);header=pe.u32(pe.opt+60)
    alignment=pe.u32(pe.opt+32)
    if not 0<size<=128*1024*1024:raise ValueError("Image size budget")
    with tempfile.TemporaryDirectory(prefix="mxb-private-native-pe-") as d:
        so=Path(d)/"loader.so"
        subprocess.run(["cc","-O2","-std=c11","-Wall","-Wextra","-Werror",
            "-fPIC","-shared","-I"+str(ROOT/"runtime"),
            str(ROOT/"runtime/mxb_guest_memory.c"),str(ROOT/"runtime/mxb_pe_guest_image.c"),
            "-o",str(so)],check=True)
        lib=C.CDLL(str(so))
        lib.mxb_pe_map.argtypes=[C.POINTER(Memory),C.c_void_p,C.c_size_t,C.c_void_p,
                                 C.c_size_t,C.POINTER(Plan)]
        lib.mxb_pe_map.restype=C.c_int
        lib.mxb_guest_read.argtypes=[C.POINTER(Memory),C.c_uint64,C.c_void_p,C.c_size_t]
        lib.mxb_guest_read.restype=C.c_int
        lib.mxb_guest_write.argtypes=list(lib.mxb_guest_read.argtypes)
        lib.mxb_guest_write.restype=C.c_int
        lib.mxb_guest_check.argtypes=[C.POINTER(Memory),C.c_uint64,C.c_size_t,C.c_uint]
        lib.mxb_guest_check.restype=C.c_int
        file=C.create_string_buffer(raw);backing=C.create_string_buffer(size)
        mem=Memory();plan=Plan()
        if not lib.mxb_pe_map(C.byref(mem),file,len(raw),backing,size,C.byref(plan)):
            raise ValueError("Native PE loader rejected owned preferred-base image")
        if (plan.image_base,plan.image_size,plan.header_size,plan.entry_rva,plan.section_count)!=(
            base,size,header,pe.u32(pe.opt+16),len(pe.sections)):
            raise ValueError("Native PE header mapping mismatch")
        if mem.count!=len(pe.sections)+1 or backing[:header]!=raw[:header]:
            raise ValueError("Native headers mismatch")
        zero_bytes=plan.header_mapped_size-header;raw_bytes=header
        if any(backing[header:plan.header_mapped_size]):raise ValueError("Nonzero header padding")
        permission_checks=0
        for i,(_,vsize,rva,n,offset,flags) in enumerate(pe.sections):
            sec=plan.sections[i]
            span=(max(vsize,n)+alignment-1)&~(alignment-1)
            perm=((flags>>30)&1)|(((flags>>31)&1)<<1)|(((flags>>29)&1)<<2)
            if (sec.rva,sec.virtual_size,sec.raw_offset,sec.raw_size,
                sec.mapped_size,sec.permissions)!=(rva,vsize,offset,n,span,perm):
                raise ValueError("Native PE section plan mismatch")
            if backing[rva:rva+n]!=raw[offset:offset+n]:
                raise ValueError("Native section payload mismatch")
            if any(backing[rva+n:rva+span]):raise ValueError("Nonzero section padding")
            raw_bytes+=n;zero_bytes+=span-n
            for bit in (1,2,4):
                if bool(lib.mxb_guest_check(C.byref(mem),base+rva,span,bit))!=bool(perm&bit):
                    raise ValueError("Native section permission mismatch")
                permission_checks+=1
            b=C.c_uint8()
            if perm&1:
                if not lib.mxb_guest_read(C.byref(mem),base+rva,C.byref(b),1):
                    raise ValueError("Native section read failed")
                if b.value!=backing[rva:rva+1][0]:raise ValueError("Guest read payload mismatch")
            b.value=backing[rva:rva+1][0]
            if bool(lib.mxb_guest_write(C.byref(mem),base+rva,C.byref(b),1))!=bool(perm&2):
                raise ValueError("Native section write permission mismatch")
            permission_checks+=1
        print(json.dumps({"mode":"private_actual_pe_native_mapping","sha_pinned":True,
            "image_base":hex(base),"image_bytes":size,"mapped_regions":mem.count,
            "sections_verified":plan.section_count,"original_raw_bytes_compared":raw_bytes,
            "zero_fill_bytes_compared":zero_bytes,"permission_checks":permission_checks,
            "entry_is_executable_guest_data":bool(lib.mxb_guest_check(C.byref(mem),base+plan.entry_rva,1,4)),
            "original_code_executed":False,"host":"pass"},indent=2))
if __name__=="__main__":
    p=argparse.ArgumentParser();p.add_argument("--owned-exe",type=Path,required=True);run(p.parse_args().owned_exe)
