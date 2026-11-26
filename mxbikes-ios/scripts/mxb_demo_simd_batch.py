"""Bounded SSE/SSE2 AOT extension. Normal/zero IEEE754 arithmetic only.

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
/* Deterministic IEEE754 normal/zero SSE arithmetic with round-to-nearest-even.
 * Never depend on the host FP environment. Denormal, NaN, infinity, invalid,
 * underflow and overflow are explicit unsupported cases, not approximations. */
typedef unsigned __int128 u128;
typedef struct {uint64_t sig;int exp;unsigned sign;} fp;
static inline unsigned fp_p(unsigned w){return w==32?24:53;}
static inline unsigned fp_bias(unsigned w){return w==32?127:1023;}
static inline int fp_unpack(uint64_t raw,unsigned w,fp*v){
 unsigned p=fp_p(w);uint64_t frac=mask(p-1);v->sign=!!(raw&signbit(w));v->exp=(int)((raw>>(p-1))&(2*fp_bias(w)+1));v->sig=raw&frac;
 if(v->exp==0)return v->sig==0;
 if(v->exp==(int)(2*fp_bias(w)+1))return 0;
 v->sig|=UINT64_C(1)<<(p-1);return 1;
}
static inline u128 jam(u128 a,unsigned n){
 if(!n)return a;if(n>=128)return a!=0;
 return (a>>n)|((a&(((u128)1<<n)-1))!=0);
}
static inline int fp_pack(uint32_t*csr,unsigned w,unsigned sign,int e,u128 x,uint64_t*out){
 unsigned p=fp_p(w);uint64_t s=sign?signbit(w):0;
 if(!x){*out=s;return 1;}
 while(x>=((u128)1<<(p+3))){x=jam(x,1);++e;}
 while(x<((u128)1<<(p+2))){x<<=1;--e;}
 if(e<=0||e>=(int)(2*fp_bias(w)+1))return 0;
 uint64_t m=(uint64_t)(x>>3),r=(uint64_t)x&7;
 if(r>4||(r==4&&(m&1)))++m;
 if(m==(UINT64_C(1)<<p)){m>>=1;++e;}
 if(e>=(int)(2*fp_bias(w)+1))return 0;
 if(r)*csr|=0x20;
 *out=s|((uint64_t)e<<(p-1))|(m&mask(p-1));return 1;
}
static inline int fp_less(uint64_t a,uint64_t b,unsigned w){
 uint64_t s=signbit(w);a&=mask(w);b&=mask(w);
 if(a==b||(!(a&~s)&&!(b&~s)))return 0;
 return (a&s)?(!(b&s)||a>b):(!(b&s)&&a<b);
}
static inline int fp_bin(uint32_t*csr,unsigned w,unsigned op,uint64_t a,uint64_t b,uint64_t*out){
 fp x,y;unsigned p=fp_p(w);uint64_t s=signbit(w);a&=mask(w);b&=mask(w);
 if((*csr&0xffc0)!=0x1f80||!fp_unpack(a,w,&x)||!fp_unpack(b,w,&y))return 0;
 if(op>=4){*out=op==4?(fp_less(a,b,w)?a:b):(fp_less(b,a,w)?a:b);return 1;}
 if(op==1){y.sign^=1;b^=s;}
 if(op<=1){
  if(!x.sig&&!y.sig){*out=(x.sign&&y.sign)?s:0;return 1;}
  if(!x.sig){*out=b;return 1;}if(!y.sig){*out=a;return 1;}
  if(x.exp<y.exp||(x.exp==y.exp&&x.sig<y.sig)){fp tmp=x;x=y;y=tmp;}
  u128 A=(u128)x.sig<<3,B=jam((u128)y.sig<<3,(unsigned)(x.exp-y.exp));
  u128 z=x.sign==y.sign?A+B:A-B;
  return fp_pack(csr,w,z?x.sign:0,x.exp,z,out);
 }
 unsigned sign=x.sign^y.sign;
 if(op==2){if(!x.sig||!y.sig){*out=sign?s:0;return 1;}
  return fp_pack(csr,w,sign,x.exp+y.exp-(int)fp_bias(w),jam((u128)x.sig*y.sig,p-4),out);
 }
 if(!y.sig)return 0;if(!x.sig){*out=sign?s:0;return 1;}
 int e=x.exp-y.exp+(int)fp_bias(w);
 if(x.sig<y.sig){x.sig<<=1;--e;}
 u128 n=(u128)x.sig<<(p+2),q=n/y.sig;if(n%y.sig)q|=1;
 return fp_pack(csr,w,sign,e,q,out);
}
static inline int xarith(mxb_cfg*s,unsigned w,unsigned scalar,unsigned op,mxb_xmm a,mxb_xmm b,mxb_xmm*out){
 unsigned lanes=scalar?1:128/w;uint32_t csr=s->mxcsr;mxb_xmm r=a;
 for(unsigned i=0;i<lanes;i++){
  unsigned j=i*w,shift=j&63;uint64_t x=j<64?a.lo:a.hi,y=j<64?b.lo:b.hi,v;
  if(!fp_bin(&csr,w,op,x>>shift,y>>shift,&v))return 0;
  uint64_t m=mask(w)<<shift,*dst=j<64?&r.lo:&r.hi;
  *dst=(*dst&~m)|((v&mask(w))<<shift);
 }
 s->mxcsr=csr;*out=r;return 1;
}
static inline int fp_convert(uint32_t*csr,unsigned from,unsigned to,uint64_t a,uint64_t*out){
 fp x;if((*csr&0xffc0)!=0x1f80)return 0;
 a&=mask(from);
 /* Exact signed infinity widening/narrowing does not raise an exception.
  * NaNs, denormals and overflowing finite conversions still stop. */
 uint64_t from_exp=mask(from)^signbit(from)^mask(fp_p(from)-1);
 if((a&~signbit(from))==from_exp){
  *out=(mask(to)^signbit(to)^mask(fp_p(to)-1))|((a&signbit(from))?signbit(to):0);
  return 1;
 }
 if(!fp_unpack(a,from,&x))return 0;
 if(!x.sig){*out=x.sign?signbit(to):0;return 1;}
 int e=x.exp-(int)fp_bias(from)+(int)fp_bias(to);
 int delta=(int)fp_p(from)-(int)fp_p(to)-3;
 u128 sig=delta>=0?jam(x.sig,(unsigned)delta):(u128)x.sig<<-delta;
 return fp_pack(csr,to,x.sign,e,sig,out);
}
static inline int fp_fromint(uint32_t*csr,unsigned from,unsigned to,uint64_t a,uint64_t*out){
 if((*csr&0xffc0)!=0x1f80)return 0;
 a&=mask(from);unsigned sign=!!(a&signbit(from));uint64_t m=sign?(-a)&mask(from):a;
 if(!m){*out=0;return 1;}
 unsigned bit=63-__builtin_clzll(m),p=fp_p(to);int delta=(int)bit-(int)(p+2);
 u128 sig=delta>=0?jam(m,(unsigned)delta):(u128)m<<-delta;
 return fp_pack(csr,to,sign,(int)fp_bias(to)+(int)bit,sig,out);
}
static inline int fp_toint(uint32_t*csr,unsigned from,unsigned to,unsigned truncate,uint64_t a,uint64_t*out){
 fp x;if((*csr&0xffc0)!=0x1f80||!fp_unpack(a,from,&x))return 0;
 if(!x.sig){*out=0;return 1;}
 int shift=x.exp-(int)fp_bias(from)-(int)(fp_p(from)-1);u128 m=0;int inexact=0;
 if(shift>=0){if(shift>=64)return 0;m=(u128)x.sig<<shift;}
 else {unsigned n=(unsigned)-shift;uint64_t v=x.sig;
  if(n>=64){m=0;inexact=1;}
  else {uint64_t rem=v&mask(n),half=UINT64_C(1)<<(n-1);m=v>>n;inexact=rem!=0;
   if(!truncate&&(rem>half||(rem==half&&(m&1))))++m;}
 }
 u128 limit=(u128)1<<(to-1);if(m>limit||(!x.sign&&m==limit))return 0;
 if(inexact)*csr|=0x20;*out=(x.sign?-(uint64_t)m:(uint64_t)m)&mask(to);return 1;
}
'''
XMM={f'xmm{i}':i for i in range(16)}
XM=re.compile(r'(?:(byte|word|dword|qword|xmmword|oword) ptr )?\[(.+)\]$')
MOVES={'movaps':(16,16),'movapd':(16,16),'movdqa':(16,16),'movups':(16,0),'movupd':(16,0),'movdqu':(16,0),'movss':(4,0),'movsd':(8,0),'movd':(4,0),'movq':(8,0)}
LOGIC={op:k for k,names in enumerate(('pand andps andpd','por orps orpd','pxor xorps xorpd','pandn andnps andnpd')) for op in names.split()}
PACKED={name+suffix:(w,k) for k,name in enumerate(('padd','psub','pcmpeq','pcmpgt')) for suffix,w in zip('bwdq',(8,16,32,64)) if not(w==64 and k>=2)}

ARITH={name+suffix:(w,scalar,k) for k,name in enumerate(('add','sub','mul','div','min','max')) for suffix,w,scalar in (('ss',32,1),('sd',64,1),('ps',32,0),('pd',64,0))}
CONVERT=('cvtss2sd','cvtsd2ss','cvtsi2ss','cvtsi2sd','cvtss2si','cvtsd2si','cvttss2si','cvttsd2si','cvtps2pd','cvtdq2ps','cvtdq2pd')

def emit(row,pc):
    raw,op,arg=row;end=pc+len(raw);args=[x.strip() for x in arg.split(',')]
    if op not in MOVES and op not in LOGIC and op not in PACKED and op not in ARITH and op not in CONVERT and op not in ('shufps','pshufd','unpcklps','unpckhps','ucomiss','ucomisd','comiss','comisd'):
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
    elif op in ARITH and len(args)==2 and args[0] in XMM:
        w,scalar,k=ARITH[op];d,b=args;a=f's->xmm[{XMM[d]}]';v=read(b,w//8 if scalar else 16,0 if scalar else 16,'v')
        code.append(f'mxb_xmm x={v},r;if(!xarith(s,{w},{scalar},{k},{a},x,&r))return -5;');write(d,16,0,'r')
    elif op in CONVERT and len(args)==2:
        d,b=args
        if op in ('cvtps2pd','cvtdq2ps','cvtdq2pd') and d in XMM:
            if op=='cvtdq2pd':
                if raw[0]!=0xf3 or raw[i+1]!=0xe6:raise ValueError('sse_encoding')
                v=read(b,8,0,'v')
                code.append(f'mxb_xmm x={v};uint64_t a,b;uint32_t csr=s->mxcsr;if(!fp_fromint(&csr,32,64,x.lo&UINT32_MAX,&a)||!fp_fromint(&csr,32,64,x.lo>>32,&b))return -5;s->mxcsr=csr;')
                write(d,16,0,'(mxb_xmm){a,b}')
            elif op=='cvtps2pd':
                v=read(b,8,0,'v')
                code.append(f'mxb_xmm x={v};uint64_t a,b;uint32_t csr=s->mxcsr;if(!fp_convert(&csr,32,64,x.lo&UINT32_MAX,&a)||!fp_convert(&csr,32,64,x.lo>>32,&b))return -5;s->mxcsr=csr;')
                write(d,16,0,'(mxb_xmm){a,b}')
            else:
                v=read(b,16,16,'v')
                code.append(f'mxb_xmm x={v};uint64_t z[4];uint32_t csr=s->mxcsr;for(unsigned j=0;j<4;j++)if(!fp_fromint(&csr,32,32,lane32(x,j),&z[j]))return -5;s->mxcsr=csr;')
                write(d,16,0,'lanes32(z[0],z[1],z[2],z[3])')
        elif op in ('cvtss2sd','cvtsd2ss') and d in XMM:
            w=32 if op=='cvtss2sd' else 64;to=96-w;v=read(b,w//8,0,'v')
            code.append(f'mxb_xmm x={v};uint64_t r;if(!fp_convert(&s->mxcsr,{w},{to},x.lo,&r))return -5;')
            i=XMM[d];code.append(f's->xmm[{i}].lo=(s->xmm[{i}].lo&~mask({to}))|r;')
        elif op in ('cvtsi2ss','cvtsi2sd') and d in XMM:
            w=cfg.REGS[b][1] if b in cfg.REGS else (32 if b.startswith('dword ptr ') else 64 if b.startswith('qword ptr ') else 0)
            if w not in (32,64):raise ValueError('sse_conversion_width')
            to=32 if op.endswith('ss') else 64;v=read(b,w//8,0,'v',True)
            code.append(f'mxb_xmm x={v};uint64_t r;if(!fp_fromint(&s->mxcsr,{w},{to},x.lo,&r))return -5;')
            i=XMM[d];code.append(f's->xmm[{i}].lo=(s->xmm[{i}].lo&~mask({to}))|r;')
        elif op.endswith('2si') and d in cfg.REGS and cfg.REGS[d][1] in (32,64):
            w=32 if 'ss' in op else 64;i,to=cfg.REGS[d];v=read(b,w//8,0,'v')
            code.append(f'mxb_xmm x={v};uint64_t r;if(!fp_toint(&s->mxcsr,{w},{to},{int(op.startswith("cvtt"))},x.lo,&r))return -5;regset(s,{i},{to},r);')
        else:raise ValueError('sse_conversion_operand')
    elif op in ('ucomiss','ucomisd','comiss','comisd') and len(args)==2 and args[0] in XMM:
        n=4 if op.endswith('ss') else 8
        source=args[1]
        # Capstone can label the memory operand of legacy COMISD as
        # xmmword. The actual 66 0F 2F /r encoding reads only m64.
        # Normalize only this verified encoding and memory ModRM form.
        if op=='comisd' and source.startswith('xmmword ptr '):
            if raw[0]!=0x66 or raw[i:i+2]!=b'\x0f\x2f' or len(raw)<=i+2 or raw[i+2]>=0xc0:raise ValueError('sse_compare_encoding')
            source='qword ptr '+source[len('xmmword ptr '):]
        v=read(source,n,0,'v');code.append(f'mxb_xmm x={v};if(!xcompare(s,s->xmm[{XMM[args[0]]}].lo,x.lo,{n*8}))return -5;')
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
