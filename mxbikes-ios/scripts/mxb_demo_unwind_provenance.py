"""Classify PE64 runtime function records, including chained unwind ranges.

An unwind range with UNW_FLAG_CHAININFO is not an independently proven
callable function. Resolve its parent record without interpreting prologues.
Only metadata is emitted; no executable bytes or generated code.
"""
from collections import Counter
import argparse
import hashlib
import json
from pathlib import Path
import struct

SHA='b75ba091fea6425ea9e5e372d2c41bf19f7d3f20a1ff1890130389e9f51f8742'

def classify(data):
    if len(data)<256 or data[:2]!=b'MZ':raise ValueError('invalid MZ')
    p=struct.unpack_from('<I',data,0x3c)[0];o=p+24
    if p>len(data)-264 or data[p:p+4]!=b'PE\0\0' or struct.unpack_from('<H',data,p+4)[0]!=0x8664:raise ValueError('invalid PE64')
    n=struct.unpack_from('<H',data,p+6)[0];opt=struct.unpack_from('<H',data,p+20)[0]
    if not 0<n<=96 or opt<240 or o+opt+40*n>len(data) or struct.unpack_from('<H',data,o)[0]!=0x20b:raise ValueError('invalid sections')
    sections=[struct.unpack_from('<IIII',data,o+opt+40*i+8) for i in range(n)]
    def at(a,n):
        for _,lo,raw,off in sections:
            if lo<=a and n<=raw and a-lo<=raw-n and off+raw<=len(data):return data[off+a-lo:off+a-lo+n]
        raise ValueError('unmapped unwind data')
    a,n=struct.unpack_from('<II',data,o+112+3*8)
    if not n or n%12 or n//12>100000:raise ValueError('invalid runtime function directory')
    records={}
    for begin,end,u in struct.iter_unpack('<III',at(a,n)):
        if not 0<begin<end or not u:raise ValueError('invalid runtime function')
        if begin in records and records[begin]!=(end,u):raise ValueError('conflicting runtime function')
        records[begin]=(end,u)
    info={}
    for begin,(end,u) in records.items():
        header=at(u,4);version=header[0]&7;flags=header[0]>>3
        if version not in (1,2) or flags&~7 or flags&4 and flags&3:raise ValueError('unsupported unwind info')
        parent=None
        if flags&4:
            count=header[2];parent,pend,pu=struct.unpack('<III',at(u+4+2*((count+1)&~1),12))
            if records.get(parent)!=(pend,pu):raise ValueError('unknown chained parent')
        info[begin]={'rva':begin,'end_rva':end,'flags':flags,'chained':bool(flags&4),'parent_rva':parent}
    for begin,row in info.items():
        parent=begin;seen=set()
        while info[parent]['chained']:
            if parent in seen or len(seen)>=32:raise ValueError('chained unwind cycle or depth')
            seen.add(parent);parent=info[parent]['parent_rva']
        row['root_rva']=parent;row['chain_depth']=len(seen)
    return info

def report(exe,metadata):
    data=Path(exe).read_bytes()
    if hashlib.sha256(data).hexdigest()!=SHA:raise ValueError('demo hash mismatch')
    raw=json.loads(Path(metadata).read_text())
    if raw.get('sha256')!=SHA:raise ValueError('metadata hash mismatch')
    info=classify(data);rows=[]
    for row in raw['candidates']:
        rva=int(row['rva'],16)
        if rva not in info:raise ValueError('candidate lacks unwind record')
        r=info[rva];rows.append({**row,'unwind_chained':r['chained'],'unwind_root_rva':hex(r['root_rva']),'chain_depth':r['chain_depth']})
    return {'sha256':SHA,'candidate_graphs':len(rows),'chained_regions':sum(r['unwind_chained'] for r in rows),
        'unchained_regions':sum(not r['unwind_chained'] for r in rows),'direct_call_target_candidates':sum(bool(r['direct_references']) for r in rows),
        'represented_unwind_roots':len({r['unwind_root_rva'] for r in rows}),
        'root_entry_proof':False,'candidates':rows}

if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('exe');p.add_argument('metadata');p.add_argument('--out',type=Path);a=p.parse_args()
    r=report(a.exe,a.metadata)
    if a.out:a.out.write_text(json.dumps(r,indent=2)+'\n')
    print(json.dumps({k:v for k,v in r.items() if k!='candidates'},indent=2))
