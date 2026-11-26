"""Original-byte-verified block dispatcher for bounded AOT execution.

Generate code only for caller-selected, decoded executable addresses. Direct and
indirect control transfer updates guest RIP/RSP; unknown PCs yield a boundary,
never execute host pointers. Import callbacks must be independently validated.
"""
from collections import Counter
import re,struct
import mxb_demo_cfg_batch as cfg
import mxb_demo_simd_batch as simd
import mxb_demo_hot_string as hot
import mxb_demo_integer_extra as integer_extra
PREAMBLE=simd.PREAMBLE+hot.PREAMBLE+integer_extra.PREAMBLE

def emit(row,pc):
    extra=hot.emit(row,pc)
    if extra is not None:return extra
    extra=integer_extra.emit(row,pc)
    if extra is not None:return extra
    raw,op,args=row;end=pc+len(raw)
    if op in ('call','jmp'):
        # Near indirect FF /2 or /4 only, optional REX. Read target before
        # pushing return so [rsp+...] has the pre-call effective address.
        i=1 if raw and 0x40<=raw[0]<=0x4f else 0
        if len(raw)>i+1 and raw[i]==0xff and ((raw[i+1]>>3)&7)==(2 if op=='call' else 4):
            t=args.strip()
            if t in cfg.GPRS:code=f'uint64_t v=s->r[{cfg.GPRS.index(t)}];'
            elif cfg.MEM.fullmatch(t):
                a,w=cfg.address(t,end)
                if w not in (None,64):raise ValueError('indirect_width')
                code=f'uint64_t v;if(!s->read||!s->read(s->ctx,{a},8,&v))return -2;'
            else:raise ValueError('indirect_operand')
            if op=='call':code+=f'if(!push(s,UINT64_C({end})))return -2;'
            code+='s->rip=v;break;'
            return code,[end] if op=='call' else []
    return simd.emit(row,pc)

def generate(ins,addresses,max_nodes=32768):
    if len(addresses)>max_nodes:raise ValueError('block_address_budget')
    pages={};accepted=set();reject=Counter()
    for pc in sorted(set(addresses)):
        if pc not in ins:reject['unverified_instruction']+=1;continue
        try:code,_=emit(ins[pc],pc)
        except ValueError as e:reject[str(e).split(':')[0]]+=1;continue
        pages.setdefault(pc>>12,[]).append((pc,code));accepted.add(pc)
    if not accepted:raise ValueError('no_supported_blocks')
    src=[PREAMBLE]
    for p,rows in sorted(pages.items()):
        src.append(f'static int page_{p:x}(mxb_cfg*s){{switch(s->rip){{\n')
        src.extend(f'case UINT64_C({pc}):{{{c}}}\n' for pc,c in rows)
        src.append('default:return 2;}return 1;}\n')
    src.append('int mxb_block_step(mxb_cfg*s){if(!s)return -1;switch(s->rip>>12){\n')
    src.extend(f'case UINT64_C({p}):return page_{p:x}(s);\n' for p in sorted(pages))
    src.append('default:return 2;}}\n')
    src.append('int mxb_block_run(mxb_cfg*s,uint64_t stop,unsigned budget){if(!s)return -1;while(budget--){if(s->rip==stop)return 1;int r=mxb_block_step(s);if(r!=1)return r;}return s->rip==stop?1:0;}\n')
    return ''.join(src),accepted,reject

def verified_map(pe,addresses,decoder):
    """Decode at actual observed guest PCs. Require raw executable bytes."""
    base=pe.u64(pe.opt+24);out={}
    ranges=[(base+r,base+r+n) for _,_,r,n,_,flags in pe.sections if n and flags&0x20000000]
    for a in sorted(set(addresses)):
        bounds=[hi for lo,hi in ranges if lo<=a<hi]
        if len(bounds)!=1:continue
        raw=pe.read_rva(a-base,min(15,bounds[0]-a))
        items=list(decoder.disasm(raw,a,count=1))
        if len(items)==1 and bytes(items[0].bytes)==raw[:items[0].size]:
            i=items[0];out[a]=(bytes(i.bytes),i.mnemonic,i.op_str)
    return out
