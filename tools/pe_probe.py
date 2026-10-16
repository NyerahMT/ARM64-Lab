#!/usr/bin/env python3
"""Read-only Windows PE32+ x86-64 inspection. No external dependencies."""
from __future__ import annotations
import argparse
import hashlib
import json
import pathlib
import struct

class PE:
    def __init__(self, path):
        self.path = pathlib.Path(path)
        self.b = self.path.read_bytes()
        b = self.b
        if len(b) < 0x100 or b[:2] != b'MZ':
            raise ValueError('Not an MZ executable')
        p = self.u32(0x3c)
        if p > len(b)-24 or b[p:p+4] != b'PE\x00\x00':
            raise ValueError('Invalid PE header')
        if self.u16(p+4) != 0x8664:
            raise ValueError('Expected x86-64 PE')
        self.pe = p
        n = self.u16(p+6)
        sz = self.u16(p+20)
        self.opt = p+24
        if sz < 240 or self.opt+sz > len(b) or self.u16(self.opt)!=0x20b:
            raise ValueError('Invalid PE32+ optional header')
        if n > 96 or n == 0 or self.opt+sz+40*n > len(b):
            raise ValueError('Invalid section table')
        self.sections=[]
        for i in range(n):
            o = self.opt+sz+i*40
            vsize,rva,rawsize,rawptr = struct.unpack_from('<IIII',b,o+8)
            name=b[o:o+8].split(b'\0',1)[0].decode('ascii','replace')
            self.sections.append((name,vsize,rva,rawsize,rawptr,self.u32(o+36)))

    def u16(self,o):
        return struct.unpack_from('<H',self.b,o)[0]
    def u32(self,o):
        return struct.unpack_from('<I',self.b,o)[0]
    def u64(self,o):
        return struct.unpack_from('<Q',self.b,o)[0]
    def directory(self,n):
        return self.u32(self.opt+112+8*n),self.u32(self.opt+116+8*n)
    def read_rva(self,rva,size):
        for name,vsize,base,rawsize,off,flags in self.sections:
            if rva >= base and rva-base < rawsize and size <= rawsize-(rva-base):
                start=off+rva-base
                if start <= len(self.b) and size <= len(self.b)-start:
                    return self.b[start:start+size]
        raise ValueError('Unmapped or truncated RVA 0x%x'%rva)
    def string(self,rva):
        for n in range(1,4097):
            buf=self.read_rva(rva,n)
            if buf[-1]==0:
                return buf[:-1].decode('ascii','replace')
        raise ValueError('Unterminated string')
    def text_section(self):
        for name,vsize,rva,size,off,flags in self.sections:
            if name=='.text' and (flags & 0x20000000):
                return self.read_rva(rva,size),rva
        raise ValueError('No executable .text')
    def inventory(self):
        imports={}
        imp,_=self.directory(1)
        if imp:
            for i in range(500):
                ilt,stamp,fwd,name,iat=struct.unpack('<IIIII',self.read_rva(imp+20*i,20))
                if not (ilt or stamp or fwd or name or iat):
                    break
                lib=self.string(name)
                funcs=[]
                for j in range(10000):
                    v=struct.unpack('<Q',self.read_rva((ilt or iat)+8*j,8))[0]
                    if v==0:
                        break
                    funcs.append('#ordinal:'+str(v & 65535) if v >> 63 else self.string(v+2))
                else:
                    raise ValueError('Excessive import thunks')
                imports[lib]=funcs
            else:
                raise ValueError('Excessive import descriptors')
        pdata,plen=self.directory(3)
        n=0
        if pdata and plen:
            if plen%12:
                raise ValueError('Invalid .pdata size')
            tab=self.read_rva(pdata,plen)
            for o in range(0,len(tab),12):
                begin,end,unwind=struct.unpack_from('<III',tab,o)
                if begin and end>begin:
                    n+=1
        base=self.u64(self.opt+24)
        entry=self.u32(self.opt+16)
        return {
            'sha256': hashlib.sha256(self.b).hexdigest(),
            'size_bytes':len(self.b),
            'architecture':'x86-64 PE32+',
            'linker_version':f'{self.b[self.opt+2]}.{self.b[self.opt+3]}',
            'image_base':hex(base),
            'entry_rva':hex(entry),
            'entry_virtual_address':hex(base+entry),
            'exception_record_count':n,
            'import_library_count':len(imports),
            'import_function_count':sum(map(len,imports.values())),
            'imports':imports,
            'sections':[{'name':name,'rva':hex(rva),'raw_size':size,
                         'virtual_size':vsize} for name,vsize,rva,size,off,flags in self.sections]
        }

def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('exe',type=pathlib.Path)
    ap.add_argument('--json',type=pathlib.Path,help='output path; otherwise stdout')
    args=ap.parse_args()
    try:
        obj=PE(args.exe).inventory()
    except (OSError, ValueError, struct.error) as e:
        ap.error(str(e))
    result=json.dumps(obj,indent=2)+'\n'
    if args.json:
        args.json.write_text(result)
        print(f'Wrote {args.json}')
    else:
        print(result)

if __name__=='__main__':
    main()
