#!/usr/bin/env python3
"""Very limited x86-64 return-sequence lift; NOT a whole-program recompilator.

Recognizes only: xor eax,eax;ret / mov eax,imm32;ret. Raw byte matches
are candidate sequences, NOT verified callable function boundaries.
"""
from __future__ import annotations
import argparse
import json
import pathlib
import re
from .pe_probe import PE

ZERO=bytes.fromhex('33c0c3')

def recognize(code: bytes) -> int:
    if code==ZERO:
        return 0
    if len(code)==6 and code[0]==0xb8 and code[-1]==0xc3:
        return int.from_bytes(code[1:5],'little')
    raise ValueError('Unsupported x86-64 instruction sequence')

def lift_to_c(code: bytes) -> str:
    val=recognize(code)
    return (
        '/* Models only the zero-extended return value, not full CPU state. */\n'
        'typedef unsigned long long guest_u64;\n'
        'guest_u64 lifted_leaf_return(void) {\n'
        f'    return (guest_u64)0x{val:08x}ULL;\n'
        '}\n'
    )

def candidate_patterns(blob: bytes):
    for m in re.finditer(re.escape(ZERO),blob):
        yield m.start(),m.group(),0
    for m in re.finditer(rb'\xb8[\x00-\xff]{4}\xc3',blob,re.DOTALL):
        yield m.start(),m.group(),recognize(m.group())

def main():
    ap=argparse.ArgumentParser(description=__doc__)
    src=ap.add_mutually_exclusive_group(required=True)
    src.add_argument('--exe',type=pathlib.Path,help='local original executable')
    src.add_argument('--hex',dest='test_hex',help='synthetic test sequence')
    ap.add_argument('--rva',type=lambda x:int(x,0),help='candidate RVA to lift')
    ap.add_argument('--emit-c',type=pathlib.Path)
    ap.add_argument('--limit',type=int,default=10)
    a=ap.parse_args()
    if a.limit<0 or a.limit>1000:
        ap.error('Invalid --limit')
    code=None
    if a.test_hex is not None:
        if a.rva is not None:
            ap.error('--rva requires --exe')
        try:
            code=bytes.fromhex(a.test_hex)
            val=recognize(code)
        except ValueError as e:
            ap.error(str(e))
        result={'mode':'synthetic_sequence','return_rax':val}
    else:
        try:
            section,base=PE(a.exe).text_section()
            hits=sorted((base+i,raw,val) for i,raw,val in candidate_patterns(section))
        except (OSError,ValueError) as e:
            ap.error(str(e))
        result={
            'mode':'local_pe_byte_scan','candidate_count':len(hits),
            'examples':[{'rva':hex(rva),'return_rax':val} for rva,_,val in hits[:a.limit]],
            'entry_points_verified':False,
            'note':'Byte patterns are not proof of actual callable functions.'
        }
        if a.rva is not None:
            selected=[row for row in hits if row[0]==a.rva]
            if not selected:
                ap.error('RVA does not begin a supported sequence')
            code=selected[0][1]
        if a.emit_c and a.rva is None:
            ap.error('--emit-c with --exe requires --rva')
    if a.emit_c:
        a.emit_c.parent.mkdir(parents=True,exist_ok=True)
        a.emit_c.write_text(lift_to_c(code),encoding='utf-8')
        result['output_file']=str(a.emit_c)
    print(json.dumps(result,indent=2))

if __name__=='__main__':
    main()
