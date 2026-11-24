"""Discover original local control-flow windows without inventing external services.

This is a build-time instruction boundary discovery tool, not a license or
platform emulator. Its output stays in the private generated module. The
existing native CFG decoder separately validates every instruction semantics.
"""
from capstone import Cs, CS_ARCH_X86, CS_MODE_64, CS_OP_IMM, CS_OP_REG
from mxbikes_native_cfg_lift import CONDS, MAX_STATIC

def discover(read_code, entry, stop, *, register_calls=None, max_nodes=MAX_STATIC):
    if not 1<=max_nodes<=MAX_STATIC:raise ValueError("Invalid discovery budget")
    approved=register_calls or {}
    decoder=Cs(CS_ARCH_X86,CS_MODE_64);decoder.detail=True
    pending=[entry];nodes={}
    while pending:
        pc=pending.pop()
        if pc==stop or pc in nodes:continue
        if len(nodes)>=max_nodes:raise ValueError("Local discovery budget exhausted")
        if any(a<pc<a+len(raw) for a,raw in nodes.items()):
            raise ValueError("Local discovery overlaps an instruction")
        raw=read_code(pc,15)
        ins=next(decoder.disasm(raw,pc,count=1),None)
        if ins is None:raise ValueError("Undecodable local instruction at "+hex(pc))
        nxt=pc+ins.size
        if any(pc<a<nxt for a in nodes):raise ValueError("Overlapping local instructions")
        nodes[pc]=raw[:ins.size]
        mnemonic=ins.mnemonic
        operands=ins.operands
        if mnemonic=="ret" and not operands:continue
        if mnemonic in ("call","jmp",*CONDS):
            if len(operands)!=1:raise ValueError("Invalid local control flow at "+hex(pc))
            op=operands[0]
            if op.type==CS_OP_IMM:target=op.imm
            elif mnemonic=="call" and op.type==CS_OP_REG and pc in approved:
                target=approved[pc]
            else:raise ValueError("Unresolved local control flow at "+hex(pc))
            pending.append(target)
            if mnemonic!="jmp" and (mnemonic!="call" or target!=stop):pending.append(nxt)
        elif mnemonic.startswith(("j","ret","loop","int","sys")) or mnemonic in ("ud2","hlt"):
            raise ValueError("Unsupported local control flow at "+hex(pc))
        else:pending.append(nxt)
    if not nodes:raise ValueError("Empty local discovery")
    # Coalesce only truly adjacent decoded instructions; never export a gap.
    windows=[]
    for pc,raw in sorted(nodes.items()):
        if windows and windows[-1][0]+len(windows[-1][1])==pc:
            a,old=windows[-1];windows[-1]=(a,old+raw)
        else:windows.append((pc,raw))
    return windows

def discover_pe(pe, base, entry, stop, **kwargs):
    # Only executable, file-backed bytes of the already hash-verified PE.
    ranges=[(base+rva,base+rva+raw) for _,_,rva,raw,_,flags in pe.sections
            if flags&0x20000000 and raw]
    def read_code(pc,n):
        found=[(lo,hi) for lo,hi in ranges if lo<=pc<hi]
        if len(found)!=1:raise ValueError("Local discovery target is not file-backed executable code: "+hex(pc))
        return pe.read_rva(pc-base,min(n,found[0][1]-pc))
    return discover(read_code,entry,stop,**kwargs)
