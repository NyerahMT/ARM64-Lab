"""Bounded SSE/SSE2 AOT extension. No general floating-point arithmetic.

The scalar ABI is extended, not silently changed. 128-bit guest writes require
an atomic write128 callback. XMM registers are private guest state, not host
register aliases. Preserve legacy scalar-move upper-lane behavior exactly.
"""
import argparse
from collections import Counter,deque
import hashlib,json,re,subprocess
from pathlib import Path
import mxb_demo_cfg_batch as cfg

PREAMBLE=cfg.PREAMBLE.replace('typedef struct { uint64_t r[16]', 'typedef struct {uint64_t lo,hi;} mxb_xmm;\ntypedef struct { uint64_t r[16]').replace('unsigned,uint64_t); } mxb_cfg;', '''unsigned,uint64_t);
 mxb_xmm xmm[16]; uint32_t mxcsr;
 int (*write128)(void *,uint64_t,uint64_t,uint64_t); } mxb_cfg;''')+r'''
static inline int xr(mxb_cfg*s,uint64_t p,unsigned n,unsigned align,mxb_xmm*v){
 if((align && p%align)||!s->read||p>UINT64_MAX-(n-1))return 0;
 mxb_xmm x={0,0};if(!s->read(s->ctx,p,n>8?8:n,&x.lo))return 0;
 if(n==16&&!s->read(s->ctx,p+8,8,&x.hi))return 0;
 x.lo&=mask(n>=8?64:n*8);*v=x;return 1;
}
static inline int xw(mxb_cfg*s,uint64_t p,unsigned n,unsigned align,mxb_xmm v){
 if((align&&p%align)||p>UINT64_MAX-(n-1))return 0;
 if(n==16)return s->write128&&s->write128(s->ctx,p,v.lo,v.hi);
 return s->write&&s->write(s->ctx,p,n,v.lo&mask(n*8));
}
static inline mxb_xmm xlogic(mxb_xmm a,mxb_xmm b,unsigned k){
 mxb_xmm r;switch(k){case 0:r=(mxb_xmm){a.lo&b.lo,a.hi&b.hi};break;
 case 1:r=(mxb_xmm){a.lo|b.lo,a.hi|b.hi};break;
 case 2:r=(mxb_xmm){a.lo^b.lo,a.hi^b.hi};break;
 default:r=(mxb_xmm){~a.lo&b.lo,~a.hi&b.hi};break;}return r;
}
static inline uint64_t packed(uint64_t a,uint64_t b,unsigned w,unsigned k){
 uint64_t m=mask(w),v=0;for(unsigned i=0;i<64;i+=w){
 uint64_t x=(a>>i)&m,y=(b>>i)&m,z;
 switch(k){case 0:z=x+y;break;case 1:z=x-y;break;case 2:z=x==y?m:0;break;
 default:z=(x^signbit(w))>(y^signbit(w))?m:0;break;}
 v|=(z&m)<<i;}return v;
}
static inline uint32_t lane32(mxb_xmm a,unsigned i){return (uint32_t)((i<2?a.lo:a.hi)>>(32*(i&1)));}
static inline mxb_xmm lanes32(uint32_t a,uint32_t b,uint32_t c,uint32_t d){return (mxb_xmm){a|((uint64_t)b<<32),c|((uint64_t)d<<32)};}
static inline mxb_xmm shuffle32(mxb_xmm a,mxb_xmm b,unsigned imm){return lanes32(lane32(a,imm&3),lane32(a,(imm>>2)&3),lane32(b,(imm>>4)&3),lane32(b,(imm>>6)&3));}
/* Ordered normal/zero comparisons. Reject NaN, infinity, subnormal and
 * non-default MXCSR controls rather than approximating FP exceptions. */
static inline int xcompare(mxb_cfg*s,uint64_t a,uint64_t b,unsigned w){
 uint64_t sign=signbit(w),frac=w==32?UINT64_C(0x7fffff):UINT64_C(0xfffffffffffff),exp=mask(w)^sign^frac;
 a&=mask(w);b&=mask(w);
 if((s->mxcsr&0xffc0)!=0x1f80||(a&exp)==exp||(b&exp)==exp||(!(a&exp)&&(a&frac))||(!(b&exp)&&(b&frac)))return 0;
 uint64_t f=0;if(a==b||(!(a&~sign)&&!(b&~sign)))f=ZF;
 else if((a&sign)?(!(b&sign)||a>b):(!(b&sign)&&a<b))f=CF;
 flagset(s,STATUS,STATUS,f);return 1;
}
'''
XMM={f'xmm{i}':i for i in range(16)}
XM=re.compile(r'(?:(byte|word|dword|qword|xmmword|oword) ptr )?\[(.+)\]$')
MOVES={'movaps':(16,16),'movapd':(16,16),'movdqa':(16,16),'movups':(16,0),'movupd':(16,0),'movdqu':(16,0),'movss':(4,0),'movsd':(8,0),'movd':(4,0),'movq':(8,0)}
LOGIC={op:k for k,names in enumerate(('pand andps andpd','por orps orpd','pxor xorps xorpd','pandn andnps andnpd')) for op in names.split()}
PACKED={name+suffix:(w,k) for k,name in enumerate(('padd','psub','pcmpeq','pcmpgt')) for suffix,w in zip('bwdq',(8,16,32,64)) if not(w==64 and k>=2)}

def emit(row,pc):
    raw,op,arg=row;end=pc+len(raw);args=[x.strip() for x in arg.split(',')]
    if op not in MOVES and op not in LOGIC and op not in PACKED and op not in ('shufps','pshufd','unpcklps','unpckhps','ucomiss','ucomisd','comiss','comisd'):
        return cfg.emit(row,pc)
    # Only legacy two-operand SSE encodings, no segment/address override or VEX.
    i=0
    if raw[i] in (0x66,0xf2,0xf3):i+=1
    if i<len(raw) and 0x40<=raw[i]<=0x4f:i+=1
    if i>=len(raw) or raw[i]!=0x0f:raise ValueError('sse_encoding')
    code=[]
    def mem(t,n):
        m=XM.fullmatch(t)
        if not m:raise ValueError('sse_memory')
        sizes={'dword':4,'qword':8,'xmmword':16,'oword':16}
        if sizes.get(m[1])!=n:raise ValueError('sse_width')
        return cfg.address('['+m[2]+']',end)[0]
    def read(t,n,align,key,gpr=False):
        if t in XMM:return f's->xmm[{XMM[t]}]'
        if gpr and t in cfg.REGS and cfg.REGS[t][1]==n*8:return f'(mxb_xmm){{s->r[{cfg.REGS[t][0]}]&mask({n*8}),0}}'
        a=mem(t,n);code.append(f'mxb_xmm {key};if(!xr(s,{a},{n},{align},&{key}))return -2;');return key
    def write(t,n,align,value,gpr=False):
        if t in XMM:code.append(f's->xmm[{XMM[t]}]={value};');return
        if gpr and t in cfg.REGS and cfg.REGS[t][1]==n*8:
            code.append(f'regset(s,{cfg.REGS[t][0]},{n*8},({value}).lo);');return
        a=mem(t,n);code.append(f'if(!xw(s,{a},{n},{align},{value}))return -2;')
    if op in MOVES and len(args)==2:
        n,align=MOVES[op];d,b=args
        if d not in XMM and b not in XMM:raise ValueError('sse_operand')
        gpr=op in ('movd','movq');v=read(b,n,align,'v',gpr)
        if d in XMM and n<16:
            idx=XMM[d]
            if op in ('movss','movsd') and b in XMM:
                code.append(f'mxb_xmm x={v};');code.append(f's->xmm[{idx}].lo=(s->xmm[{idx}].lo&~mask({n*8}))|(x.lo&mask({n*8}));')
            else:code.append(f'mxb_xmm x={v};');write(d,n,align,f'(mxb_xmm){{x.lo&mask({n*8}),0}}')
        else:write(d,n,align,v,gpr)
    elif op in LOGIC or op in PACKED:
        if len(args)!=2 or args[0] not in XMM:raise ValueError('sse_operand')
        d,b=args;idx=XMM[d];a=f's->xmm[{idx}]';v=read(b,16,16,'v')
        if op in LOGIC:write(d,16,0,f'xlogic({a},{v},{LOGIC[op]})')
        else:
            w,k=PACKED[op];code.append(f'mxb_xmm x={v};');write(d,16,0,f'(mxb_xmm){{packed({a}.lo,x.lo,{w},{k}),packed({a}.hi,x.hi,{w},{k})}}')
    elif op in ('shufps','pshufd','unpcklps','unpckhps'):
        if len(args)!=(3 if op in ('shufps','pshufd') else 2) or args[0] not in XMM:raise ValueError('sse_operand')
        d,b=args[:2];a=f's->xmm[{XMM[d]}]';v=read(b,16,16,'v');code.append(f'mxb_xmm x={v};')
        if op in ('shufps','pshufd'):
            imm=int(args[2],0)
            if not 0<=imm<=255:raise ValueError('sse_imm')
            write(d,16,0,f'shuffle32({a if op=="shufps" else "x"},x,{imm})')
        else:
            k=2 if op=='unpckhps' else 0
            write(d,16,0,f'lanes32(lane32({a},{k}),lane32(x,{k}),lane32({a},{k+1}),lane32(x,{k+1}))')
    elif op in ('ucomiss','ucomisd','comiss','comisd') and len(args)==2 and args[0] in XMM:
        n=4 if op.endswith('ss') else 8;v=read(args[1],n,0,'v');code.append(f'mxb_xmm x={v};if(!xcompare(s,s->xmm[{XMM[args[0]]}].lo,x.lo,{n*8}))return -5;')
    else:raise ValueError('sse_operand')
    code.append(f's->rip=UINT64_C({end});break;');return ''.join(code),[end]

def lift(ins,start,name,allowed,max_nodes=256,edge_allowed=None):
    pending=deque([start]);seen={}
    while pending:
        pc=pending.popleft()
        if pc in seen:continue
        if len(seen)>=max_nodes:raise ValueError('graph_limit')
        if pc not in ins or not allowed(pc):raise ValueError('outside_graph')
        code,edges=emit(ins[pc],pc);seen[pc]=code
        if edge_allowed is not None and any(not edge_allowed(pc,d) for d in edges):raise ValueError('invalid_graph_edge')
        pending.extend(edges)
    if not any(ins[pc][1]=='ret' for pc in seen):raise ValueError('no_return')
    body=[f'int {name}(mxb_cfg*s,uint64_t stop,unsigned budget){{if(!s)return -1;while(budget--){{if(s->rip==stop)return 1;switch(s->rip){{\n']
    body.extend(f'case UINT64_C({pc}):{{{code}}}\n' for pc,code in sorted(seen.items()))
    body.append('default:return -4;}}return s->rip==stop?1:0;}\n')
    return ''.join(body),seen

def build(exe,dest):
    exe=Path(exe);dest=Path(dest);data=exe.read_bytes()
    if hashlib.sha256(data).hexdigest()!=cfg.SHA:raise ValueError('demo_hash')
    dest.mkdir(mode=0o700,parents=True,exist_ok=False)
    lines=subprocess.check_output(['llvm-objdump','-d','--x86-asm-syntax=intel',str(exe)],text=True,timeout=120)
    base,ins,targets,intervals=cfg.inventory(data,cfg.decode(lines.splitlines()))
    owner,allowed,edge=cfg.graph_policy(ins,intervals);rows=[];sources=[PREAMBLE];nodes=set();reject=Counter()
    for a,b in sorted(intervals.items()):
        if b-a>4096:continue
        try:src,seen=lift(ins,a,f'mxb_simd_{a-base:x}',allowed,edge_allowed=edge)
        except ValueError as exc:reject[str(exc).split(':')[0]]+=1;continue
        if not any(ins[p][1] in MOVES or ins[p][1] in LOGIC or ins[p][1] in PACKED or 'xmm' in ins[p][2] for p in seen):continue
        rows.append({'rva':hex(a-base),'nodes':len(seen),'direct_references':targets[a]});sources.append(src);nodes.update(seen)
    if not rows:raise ValueError('no_simd_graphs')
    c=dest/'private-simd.c';o=dest/'private-simd.o';c.write_text(''.join(sources))
    subprocess.run(['clang','--target=arm64-apple-ios15.0','-ffreestanding','-fno-builtin','-O2','-c',str(c),'-o',str(o)],check=True,timeout=120)
    if o.read_bytes()[:8]!=b'\xcf\xfa\xed\xfe\x0c\x00\x00\x01':raise ValueError('arm64_object')
    report={'sha256':cfg.SHA,'simd_candidate_graphs':len(rows),'unique_nodes':len(nodes),'summed_nodes':sum(r['nodes'] for r in rows),'rejections':dict(reject),'arm64_executed':False,'candidates':rows}
    (dest/'metadata.json').write_text(json.dumps(report,indent=2)+'\n');return report
if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('exe');p.add_argument('private_dir');a=p.parse_args();r=build(a.exe,a.private_dir);print(json.dumps({k:v for k,v in r.items() if k!='candidates'},indent=2))
