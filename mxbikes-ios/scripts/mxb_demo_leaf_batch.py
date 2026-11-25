"""Automated standalone leaf-function pilot using LLVM's x64 disassembler.

Only direct-CALL target candidates with straight-line scalar operations
and a plain RET are accepted. Bounded memory callbacks, no calls, branches,
stack changes or flag inputs; flags and RET control effects are not modeled. Generated
source and compiled objects stay in caller-selected private working storage.
"""
import argparse
from collections import Counter, deque
from bisect import bisect_right
import hashlib
import json
from pathlib import Path
import re
import struct
import subprocess

SHA = 'b75ba091fea6425ea9e5e372d2c41bf19f7d3f20a1ff1890130389e9f51f8742'
LINE = re.compile(r'^\s*([0-9a-fA-F]+):\s+((?:[0-9a-fA-F]{2}\s+)+)(\S+)(?:\s+(.*))?$')
GPRS = ('rax','rcx','rdx','rbx','rsp','rbp','rsi','rdi','r8','r9','r10','r11','r12','r13','r14','r15')
VOLATILE = {'rax','rcx','rdx','r8','r9','r10','r11'}
REGS = {r: (i, 64) for i,r in enumerate(GPRS)}
for bits,names in [(32,('eax','ecx','edx','ebx','esp','ebp','esi','edi')),
                   (16,('ax','cx','dx','bx','sp','bp','si','di')),
                   (8,('al','cl','dl','bl','spl','bpl','sil','dil'))]:
    REGS.update({n:(i,bits) for i,n in enumerate(names)})
    suffix={32:'d',16:'w',8:'b'}[bits]
    REGS.update({f'r{i}{suffix}':(i,bits) for i in range(8,16)})
MEM = re.compile(r'(?:(byte|word|dword|qword) ptr )?\[(.+)\]$')
WIDTHS={'byte':8,'word':16,'dword':32,'qword':64}
PREAMBLE = """#include <stdint.h>
#include <stddef.h>
typedef struct { uint64_t r[16]; void *ctx;
 int (*read)(void *,uint64_t,unsigned,uint64_t *);
 int (*write)(void *,uint64_t,unsigned,uint64_t); } mxb_leaf_state;
"""


def decode(lines):
    """Parse address, instruction length, and Intel operands from LLVM output."""
    instructions = {}; targets = Counter()
    for line in lines:
        m = LINE.match(line)
        if not m: continue
        address, raw, op, operands = m.groups()
        pc = int(address, 16); blob = bytes.fromhex(raw)
        operands = (operands or '').split('#',1)[0].strip()
        instructions[pc] = (blob, op, operands)
        if op == 'call' and len(blob)==5 and blob[0]==0xe8:
            target = pc+5+struct.unpack_from('<i',blob,1)[0]
            targets[target] += 1
    return instructions, targets


def lift(instructions, start, name):
    """Emit straight-line volatile GPR operations with bounded guest memory callbacks."""
    body=[]; pc=start
    def address(token, next_pc):
        match=MEM.fullmatch(token)
        if not match:raise ValueError('unsupported_address')
        width,expr=match.groups(); terms=expr.replace(' ','').replace('-', '+-').split('+')
        acc=[]
        for term in terms:
            if not term:raise ValueError('unsupported_address')
            if term=='rip': acc.append(f'UINT64_C({next_pc})');continue
            factors=term.split('*')
            if len(factors)==1 and term in REGS and REGS[term][1]==64:
                acc.append(f's->r[{REGS[term][0]}]');continue
            if len(factors)==2:
                reg=next((x for x in factors if x in REGS and REGS[x][1]==64),None)
                scale=next((x for x in factors if x in ('1','2','4','8')),None)
                if reg is None or scale is None:raise ValueError('unsupported_address')
                acc.append(f's->r[{REGS[reg][0]}]*UINT64_C({scale})');continue
            try:v=int(term,0)
            except ValueError:raise ValueError('unsupported_address') from None
            acc.append(f'UINT64_C({v & ((1<<64)-1)})')
        return '('+' + '.join(acc)+')',WIDTHS.get(width)
    def get(token,bits):
        if token in REGS:
            i,w=REGS[token]
            if w!=bits:raise ValueError('width_mismatch')
            return f'(uint{bits}_t)s->r[{i}]'
        try: val=int(token,0)
        except ValueError: raise ValueError('unsupported_operand') from None
        return f'UINT{bits}_C({val & ((1<<bits)-1)})'
    def store(dst,bits,expr):
        if bits>=32:return f' s->r[{dst}]=(uint{bits}_t)({expr});\n'
        mask=(1<<bits)-1
        return f' s->r[{dst}]=(s->r[{dst}] & ~UINT64_C({mask})) | (uint{bits}_t)({expr});\n'
    for n in range(1,65):
        if pc not in instructions: raise ValueError('decode_gap')
        raw,op,operand=instructions[pc]; pc+=len(raw)
        if op=='ret':
            if raw!=b'\xc3' or operand:raise ValueError('unsupported_return')
            return ('int '+name+'(mxb_leaf_state *s){\n if(!s)return 0;\n'+''.join(body)+' return 1;\n}\n',n,pc)
        if op=='nop':continue
        parts=[p.strip() for p in operand.split(',')]
        if op=='mov' and len(parts)==2 and MEM.fullmatch(parts[0]):
            addr,bits=address(parts[0],pc)
            if not bits:raise ValueError('unknown_memory_width')
            v=get(parts[1],bits)
            body.append(f' if(!s->write || !s->write(s->ctx,{addr},{bits//8},(uint{bits}_t)({v})))return 0;\n');continue
        if not parts or parts[0] not in REGS:raise ValueError('unsupported_destination')
        dst,bits=REGS[parts[0]]
        if GPRS[dst] not in VOLATILE:raise ValueError('nonvolatile_write')
        if op=='lea' and len(parts)==2 and bits>=32:
            expr,_=address(parts[1],pc)
        elif op in ('mov','movzx','movsx','movsxd') and len(parts)==2:
            src=parts[1]; source_bits=bits
            if MEM.fullmatch(src):
                addr,source_bits=address(src,pc)
                if not source_bits:raise ValueError('unknown_memory_width')
                body.append(f' uint64_t v{n}=0; if(!s->read || !s->read(s->ctx,{addr},{source_bits//8},&v{n}))return 0;\n')
                expr=f'(uint{source_bits}_t)v{n}'
            else:
                if src in REGS:source_bits=REGS[src][1]
                expr=get(src,source_bits)
            if op=='mov' and source_bits!=bits or op!='mov' and source_bits>=bits:
                raise ValueError('width_mismatch')
            if op in ('movsx','movsxd'):
                # Explicit unsigned sign extension; avoid implementation-defined casts.
                sign=1<<(source_bits-1)
                expr=f'((uint{bits}_t)({expr}) ^ UINT{bits}_C({sign})) - UINT{bits}_C({sign})'
        elif op in ('xor','sub') and len(parts)==2 and parts[0]==parts[1]:expr='0'
        elif op in ('add','sub','and','or','xor','imul') and len(parts)==2 and bits>=32:
            sym={'add':'+','sub':'-','and':'&','or':'|','xor':'^','imul':'*'}[op]
            expr=f'{get(parts[0],bits)} {sym} {get(parts[1],bits)}'
        elif op in ('not','neg','inc','dec') and len(parts)==1 and bits>=32:
            a=get(parts[0],bits)
            expr={'not':f'~{a}','neg':f'0 - {a}','inc':f'{a} + 1','dec':f'{a} - 1'}[op]
        elif op in ('shl','shr') and len(parts)==2 and bits>=32:
            try: shift=int(parts[1],0)&(bits-1)
            except ValueError:raise ValueError('unsupported_shift') from None
            expr=f'{get(parts[0],bits)} {"<<" if op=="shl" else ">>"} {shift}'
        else:raise ValueError('unsupported_opcode:'+op)
        body.append(store(dst,bits,expr))
    raise ValueError('instruction_limit')


def inventory(data, instructions):
    pe=struct.unpack_from('<I',data,0x3c)[0]; opt=pe+24
    base=struct.unpack_from('<Q',data,opt+24)[0]
    entry=base+struct.unpack_from('<I',data,opt+16)[0]
    section_count=struct.unpack_from('<H',data,pe+6)[0]
    optsize=struct.unpack_from('<H',data,pe+20)[0]
    sections=[]
    for i in range(section_count):
        at=opt+optsize+40*i
        _,rva,raw,off=struct.unpack_from('<IIII',data,at+8)
        flags=struct.unpack_from('<I',data,at+36)[0]
        if raw and off+raw<=len(data):sections.append((base+rva,base+rva+raw,off,flags))
    def raw_at(address,n,executable=False):
        for lo,hi,off,flags in sections:
            if lo<=address and address+n<=hi and (not executable or flags&0x20000000):
                return data[off+address-lo:off+address-lo+n]
        return None
    pdata,length=struct.unpack_from('<II',data,opt+112+3*8)
    raw=raw_at(base+pdata,length)
    if not raw or length%12:raise ValueError('invalid_unwind_directory')
    intervals={}
    for begin,end,_ in struct.iter_unpack('<III',raw):
        if begin<end and raw_at(base+begin,end-begin,True) is not None:
            if base+begin in intervals and intervals[base+begin]!=base+end:raise ValueError('conflicting_unwind_intervals')
            intervals[base+begin]=base+end
    starts=sorted(intervals)
    def owner(address):
        i=bisect_right(starts,address)-1
        return starts[i] if i>=0 and address<intervals[starts[i]] else None
    # Match every decoded instruction against the mapped raw executable bytes.
    verified={pc:row for pc,row in instructions.items() if row[0]==raw_at(pc,len(row[0]),True)}
    targets=Counter(); graph={}
    for pc,(blob,op,_) in verified.items():
        if op=='call' and len(blob)==5 and blob[0]==0xe8:
            target=pc+5+struct.unpack_from('<i',blob,1)[0]
            targets[target]+=1
            src=owner(pc)
            if src is not None:graph.setdefault(src,set()).add(target)
    # Root reachability follows direct edges from known unwind intervals only;
    # unresolved indirect edges or unwindless subgraphs are not assumed reachable.
    roots=[x for x in (owner(entry),owner(base+0x136c60)) if x is not None]
    depth={x:0 for x in roots};q=deque(roots);reachable=set()
    while q:
        node=q.popleft()
        for target in graph.get(node,()):
            reachable.add(target);next_node=owner(target)
            if next_node is not None and next_node not in depth:
                depth[next_node]=depth[node]+1;q.append(next_node)
    return base,verified,targets,intervals,owner,depth,reachable


def build(exe, destination, llvm='llvm-objdump', clang='clang'):
    exe=Path(exe); destination=Path(destination)
    if exe.stat().st_size!=3878912:raise ValueError('unexpected_demo_size')
    data=exe.read_bytes()
    if hashlib.sha256(data).hexdigest()!=SHA:raise ValueError('unexpected_demo_hash')
    destination.mkdir(parents=True,exist_ok=False,mode=0o700)
    disasm=subprocess.run([llvm,'-d','--x86-asm-syntax=intel',str(exe)],check=True,capture_output=True,text=True,timeout=120)
    decoded,_=decode(disasm.stdout.splitlines())
    base,instructions,targets,intervals,owner,depth,reachable=inventory(data,decoded)
    accepted=[]; rejected=Counter(); code=[PREAMBLE]
    for target,count in sorted(targets.items()):
        if target not in instructions:rejected['no_decoded_target']+=1;continue
        containing=owner(target)
        if containing is not None and containing!=target:
            rejected['inside_unwind_interval']+=1;continue
        name=f'mxb_leaf_{target-base:x}'
        try: source,n,end=lift(instructions,target,name)
        except ValueError as err:rejected[str(err).split(':')[0]]+=1;continue
        if target in intervals and end!=intervals[target]:
            rejected['unwind_end_mismatch']+=1;continue
        accepted.append({'rva':hex(target-base),'instructions':n,'bytes':end-target,'direct_call_references':count,
                         'unwind_interval_matched':target in intervals,'root_graph_candidate':target in reachable})
        code.append(source)
    if not accepted:raise ValueError('no_supported_leaf_candidates')
    source=destination/'private-leaf-batch.c';source.write_text(''.join(code))
    arm=destination/'private-leaf-batch.o';host=destination/'private-leaf-batch.so'
    subprocess.run([clang,'--target=arm64-apple-ios15.0','-ffreestanding','-fno-builtin','-O2','-c',str(source),'-o',str(arm)],check=True)
    subprocess.run([clang,'-shared','-fPIC','-O2',str(source),'-o',str(host)],check=True)
    if arm.read_bytes()[:8]!=b'\xcf\xfa\xed\xfe\x0c\x00\x00\x01':raise ValueError('not_ios_arm64_object')
    report={'verified_demo_sha256':SHA,'linear_decoded_addresses':len(instructions),
            'direct_call_target_candidates':len(targets),'unwind_intervals':len(intervals),
            'root_graph_intervals':len(depth),'root_graph_direct_targets':len(reachable),
            'lifted_leaf_candidates':len(accepted),'root_graph_lifted_candidates':sum(x['root_graph_candidate'] for x in accepted),
            'unwind_matched_lifted_candidates':sum(x['unwind_interval_matched'] for x in accepted),
            'lifted_candidate_instruction_count':sum(x['instructions'] for x in accepted),
            'ios_arm64_object_compiled':True,'host_shared_object_compiled':True,
            'arm64_execution_verified':False,'original_differential_verified':False,
            'native_startup_integrated':False,'rejections':dict(rejected),'candidates':accepted}
    (destination/'metadata.json').write_text(json.dumps(report,indent=2)+'\n')
    return report

if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('exe',type=Path);p.add_argument('private_work_dir',type=Path)
    a=p.parse_args();report=build(a.exe,a.private_work_dir);print(json.dumps({k:v for k,v in report.items() if k!='candidates'},indent=2))
