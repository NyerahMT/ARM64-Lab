"""Additional scalar semantics for the observed x64 startup frontier.

Explicit divide faults, no undefined signed C division, no compiler runtime
128-bit division dependency. Memory operands use guest callbacks.
"""
import mxb_demo_cfg_batch as cfg
PREAMBLE=r'''
static inline uint64_t mx_rotate(mxb_cfg*s,unsigned w,unsigned right,uint64_t a,uint64_t count){
 unsigned n=(unsigned)(count&(w==64?63:31));n%=w;
 uint64_t m=mask(w);a&=m;if(!n)return a;
 uint64_t v=right?((a>>n)|(a<<(w-n)))&m:((a<<n)|(a>>(w-n)))&m;
 unsigned cf=right?!!(v&signbit(w)):(unsigned)(v&1);
 unsigned of=right?(!!(v&signbit(w))^!!(v&(signbit(w)>>1))):(!!(v&signbit(w))^cf);
 flagset(s,CF|OF,CF|(n==1?OF:0),(cf?CF:0)|(n==1&&of?OF:0));return v;
}
static inline void mx_mul(mxb_cfg*s,unsigned w,uint64_t b){
 __uint128_t p=(__uint128_t)(s->r[0]&mask(w))*(b&mask(w));
 uint64_t lo=(uint64_t)p&mask(w),hi=(uint64_t)(p>>w)&mask(w);
 if(w==8)regset(s,0,16,(hi<<8)|lo);else{regset(s,0,w,lo);regset(s,2,w,hi);}
 flagset(s,STATUS,CF|OF,hi?(CF|OF):0);
}
/* Wide unsigned division with a w-bit divisor and quotient. The precheck
 * excludes quotient overflow; long division uses a 128-bit remainder. */
static inline int mx_udiv(unsigned w,__uint128_t a,uint64_t b,uint64_t*q,uint64_t*r){
 if(!b||(a>>w)>=b)return 0;
 __uint128_t rem=a>>w;uint64_t quotient=0;
 for(unsigned i=w;i--;){rem=(rem<<1)|((a>>i)&1);if(rem>=b){rem-=b;quotient|=UINT64_C(1)<<i;}}
 *q=quotient;*r=(uint64_t)rem;return 1;
}
static inline int mx_div(mxb_cfg*s,unsigned w,unsigned signed_div,uint64_t b){
 uint64_t m=mask(w);b&=m;
 __uint128_t a=w==8?(s->r[0]&UINT64_C(65535)):((__uint128_t)(s->r[2]&m)<<w)|(s->r[0]&m);
 unsigned an=0,bn=0;uint64_t q=0,r=0;
 if(signed_div){
  an=(unsigned)((a>>(2*w-1))&1);bn=!!(b&signbit(w));
  if(an){a=(~a)+1;if(w<64)a&=(((__uint128_t)1<<(2*w))-1);}
  if(bn)b=(~b+1)&m;
 }
 if(!mx_udiv(w,a,b,&q,&r))return 0;
 if(signed_div){
  uint64_t lim=signbit(w)-(an==bn);
  if(q>lim)return 0;
  if(an!=bn)q=(~q+1)&m;
  if(an)r=(~r+1)&m;
 }
 if(w==8)regset(s,0,16,(r<<8)|q);else{regset(s,0,w,q);regset(s,2,w,r);}
 flagset(s,STATUS,0,0);return 1;
}
'''
def emit(row,pc):
    raw,op,arg=row;end=pc+len(raw)
    if op not in ('rol','ror','mul','div','idiv'):return None
    if not raw or raw[0] in (0x26,0x2e,0x36,0x3e,0x64,0x65,0x67,0xf0,0xf2,0xf3):raise ValueError("scalar_prefix")
    args=[a.strip() for a in arg.split(',')]
    if len(args)!=(2 if op in ('rol','ror') else 1):raise ValueError("scalar_operands")
    dst=args[0];reg=cfg.REGS.get(dst)
    if reg:i,w=reg;src=f's->r[{i}]';pre='';mem=None
    elif cfg.MEM.fullmatch(dst):
        mem,w=cfg.address(dst,end)
        if not w:raise ValueError("scalar_width")
        pre=f'uint64_t a;if(!s->read||!s->read(s->ctx,{mem},{w//8},&a))return -2;';src='a'
    else:raise ValueError("scalar_operand")
    if op in ('rol','ror'):
        c=args[1]
        if c=='cl':count='s->r[1]&255'
        else:
            try:n=int(c,0)
            except ValueError:raise ValueError("rotate_count") from None
            if not 0<=n<=255:raise ValueError("rotate_count")
            count=f'UINT64_C({n})'
        v=f'mx_rotate(s,{w},{int(op=="ror")},{src},{count})'
        if reg:body=f'uint64_t v={v};regset(s,{i},{w},v);'
        else:body=f'mxb_cfg tmp=*s;uint64_t v={v.replace("s,","&tmp,",1)};if(!s->write||!s->write(s->ctx,{mem},{w//8},v))return -2;s->flags=tmp.flags;s->known=tmp.known;'
    elif op=='mul':body=f'mx_mul(s,{w},{src});'
    else:body=f'if(!mx_div(s,{w},{int(op=="idiv")},{src}))return -7;'
    return pre+body+f's->rip=UINT64_C({end});break;',[end]
