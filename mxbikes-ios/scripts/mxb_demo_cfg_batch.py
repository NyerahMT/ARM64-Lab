"""Bounded standalone x64 CFG AOT pilot. Generated C/objects remain private.

Direct control flow only; no imports, indirect branches, SIMD or exception ABI.
Each accepted graph has a bounded instruction budget and explicit guest state.
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

SHA='b75ba091fea6425ea9e5e372d2c41bf19f7d3f20a1ff1890130389e9f51f8742'
GPRS=('rax','rcx','rdx','rbx','rsp','rbp','rsi','rdi','r8','r9','r10','r11','r12','r13','r14','r15')
REGS={r:(i,64) for i,r in enumerate(GPRS)}
for w,names in [(32,'eax ecx edx ebx esp ebp esi edi'),(16,'ax cx dx bx sp bp si di'),(8,'al cl dl bl spl bpl sil dil')]:
    REGS.update({r:(i,w) for i,r in enumerate(names.split())})
    REGS.update({f'r{i}'+{32:'d',16:'w',8:'b'}[w]:(i,w) for i in range(8,16)})
MEM=re.compile(r'(?:(byte|word|dword|qword) ptr )?\[(.+)\]$')
WIDTH={'byte':8,'word':16,'dword':32,'qword':64}
LINE=re.compile(r'^\s*([\da-fA-F]+):\s+((?:[\da-fA-F]{2}\s+)+)(\S+)(?:\s+(.*))?$')
PREAMBLE=r'''#include <stdint.h>
#include <stddef.h>
typedef struct { uint64_t r[16],rip,flags,known; void *ctx;
 int (*read)(void *,uint64_t,unsigned,uint64_t *);
 int (*write)(void *,uint64_t,unsigned,uint64_t); } mxb_cfg;
#define CF 1u
#define PF 4u
#define AF 16u
#define ZF 64u
#define SF 128u
#define OF 2048u
#define STATUS (CF|PF|AF|ZF|SF|OF)
static inline uint64_t mask(unsigned w){return UINT64_MAX>>(64-w);}
static inline uint64_t signbit(unsigned w){return UINT64_C(1)<<(w-1);}
static inline void regset(mxb_cfg*s,unsigned i,unsigned w,uint64_t v){
 s->r[i]=w>=32?v&mask(w):(s->r[i]&~mask(w))|(v&mask(w));
}
static inline uint64_t sx(uint64_t v,unsigned w){return ((v&mask(w))^signbit(w))-signbit(w);}
static inline void flagset(mxb_cfg*s,uint64_t affected,uint64_t known,uint64_t value){
 s->flags=(s->flags&~affected)|(value&known);s->known=(s->known&~affected)|known;
}
static inline uint64_t zsp(uint64_t v,unsigned w){
 uint64_t b=v&255; b^=b>>4;b^=b>>2;b^=b>>1;
 return (!v?ZF:0)|(v&signbit(w)?SF:0)|(!(b&1)?PF:0);
}
/* kind: 0 add,1 sub,2 and,3 or,4 xor,5 inc,6 dec,7 neg. */
static inline uint64_t alu(mxb_cfg*s,unsigned w,unsigned kind,uint64_t a,uint64_t b){
 uint64_t m=mask(w),h=signbit(w),v,carry=0,overflow=0,affected=STATUS,known=STATUS;
 a&=m;b&=m;
 if(kind==5||kind==6){b=1;affected&=~CF;known&=~CF;}
 if(kind==7){b=a;a=0;}
 if(kind==0||kind==5){v=(a+b)&m;carry=v<a;overflow=(~(a^b)&(a^v)&h)!=0;}
 else if(kind==1||kind==6||kind==7){v=(a-b)&m;carry=a<b;overflow=((a^b)&(a^v)&h)!=0;}
 else {v=kind==2?a&b:kind==3?a|b:a^b;known&=~AF;}
 flagset(s,affected,known,zsp(v,w)|(carry?CF:0)|(overflow?OF:0)|((a^b^v)&16?AF:0));return v;
}
/* condition number follows the low nibble of x86 Jcc. -1 unknown. */
static inline int cond(mxb_cfg*s,unsigned c){
 uint64_t needed=0,f=s->flags;int yes=0;
 switch(c>>1){case 0:needed=OF;yes=!!(f&OF);break;case 1:needed=CF;yes=!!(f&CF);break;
 case 2:needed=ZF;yes=!!(f&ZF);break;case 3:needed=CF|ZF;yes=!!(f&needed);break;
 case 4:needed=SF;yes=!!(f&SF);break;case 5:needed=PF;yes=!!(f&PF);break;
 case 6:needed=SF|OF;yes=!!(f&SF)!=!!(f&OF);break;
 case 7:needed=ZF|SF|OF;yes=!!(f&ZF)||(!!(f&SF)!=!!(f&OF));break;}
 return (s->known&needed)==needed?(yes^(c&1)):-1;
}
static inline int push(mxb_cfg*s,uint64_t v){uint64_t a=s->r[4]-8;
 if(!s->write||!s->write(s->ctx,a,8,v))return 0;s->r[4]=a;return 1;}
static inline int pop(mxb_cfg*s,uint64_t*v){if(!s->read||!s->read(s->ctx,s->r[4],8,v))return 0;s->r[4]+=8;return 1;}
'''

def decode(lines):
    out={}
    for line in lines:
        m=LINE.match(line)
        if m:
            a,b,op,args=m.groups();out[int(a,16)]=(bytes.fromhex(b),op,(args or '').split('#',1)[0].strip())
    return out

def target(raw,pc,op):
    end=pc+len(raw)
    if op=='call' and len(raw)==5 and raw[0]==0xe8:return end+struct.unpack_from('<i',raw,1)[0],None
    if op=='jmp' and len(raw)==5 and raw[0]==0xe9:return end+struct.unpack_from('<i',raw,1)[0],None
    if op=='jmp' and len(raw)==2 and raw[0]==0xeb:return end+struct.unpack_from('<b',raw,1)[0],None
    if op.startswith('j') and len(raw)==2 and 0x70<=raw[0]<=0x7f:return end+struct.unpack_from('<b',raw,1)[0],raw[0]&15
    if op.startswith('j') and len(raw)==6 and raw[0]==0x0f and 0x80<=raw[1]<=0x8f:return end+struct.unpack_from('<i',raw,2)[0],raw[1]&15
    raise ValueError('unsupported_control')

def address(token,end):
    m=MEM.fullmatch(token)
    if not m:raise ValueError('address')
    width,expr=m.groups();terms=expr.replace(' ','').replace('-','+-').split('+');acc=[]
    for term in terms:
        if term=='rip':acc.append(f'UINT64_C({end})');continue
        if term in GPRS:acc.append(f's->r[{GPRS.index(term)}]');continue
        factors=term.split('*')
        if len(factors)==2:
            r=next((x for x in factors if x in GPRS),None);k=next((x for x in factors if x in ('1','2','4','8')),None)
            if r and k:acc.append(f's->r[{GPRS.index(r)}]*UINT64_C({k})');continue
        try:acc.append(f'UINT64_C({int(term,0)&((1<<64)-1)})')
        except ValueError:raise ValueError('address') from None
    return '('+'+'.join(acc)+')',WIDTH.get(width)

def emit(row,pc):
    raw,op,arg=row;end=pc+len(raw);args=[a.strip() for a in arg.split(',')];code=[];edges=[end]
    # Reject segment and address-size overrides, LOCK and REP; these require different semantics.
    if raw[0] in (0x26,0x2e,0x36,0x3e,0x64,0x65,0x67,0xf0,0xf2,0xf3):raise ValueError('prefix')
    def width(t):return REGS[t][1] if t in REGS else address(t,end)[1] if MEM.fullmatch(t) else None
    def read(t,w,key):
        if t in REGS:
            i,b=REGS[t]
            if b!=w:raise ValueError('width')
            return f'(s->r[{i}]&mask({w}))'
        if MEM.fullmatch(t):
            a,b=address(t,end)
            if b!=w:raise ValueError('width')
            code.append(f'uint64_t {key}=0;if(!s->read||!s->read(s->ctx,{a},{w//8},&{key}))return -2;');return f'({key}&mask({w}))'
        try:return f'UINT64_C({int(t,0)&((1<<w)-1)})'
        except ValueError:raise ValueError('operand') from None
    def write(t,w,v):
        if t in REGS:
            i,b=REGS[t]
            if b!=w:raise ValueError('width')
            code.append(f'regset(s,{i},{w},{v});');return
        if MEM.fullmatch(t):
            a,b=address(t,end)
            if b!=w:raise ValueError('width')
            code.append(f'if(!s->write||!s->write(s->ctx,{a},{w//8},({v})&mask({w})))return -2;');return
        raise ValueError('destination')
    def advance(dest):code.append(f's->rip=UINT64_C({dest});break;')
    if op=='ret':
        if raw!=b'\xc3' or arg:raise ValueError('return')
        return 'uint64_t v;if(!pop(s,&v))return -2;s->rip=v;break;',[]
    if op=='call' or op.startswith('j'):
        dest,cc=target(raw,pc,op)
        if op=='call':code.append(f'if(!push(s,UINT64_C({end})))return -2;');edges=[dest,end]
        elif op=='jmp':edges=[dest]
        elif cc is not None:
            return f'int c=cond(s,{cc});if(c<0)return -3;s->rip=c?UINT64_C({dest}):UINT64_C({end});break;',[dest,end]
        else:raise ValueError('control')
        advance(dest);return ''.join(code),edges
    if op=='nop':pass
    elif op=='push' and len(args)==1 and args[0] in GPRS:code.append(f'if(!push(s,s->r[{GPRS.index(args[0])}]))return -2;')
    elif op=='pop' and len(args)==1 and args[0] in GPRS and args[0]!='rsp':code.append(f'uint64_t v;if(!pop(s,&v))return -2;s->r[{GPRS.index(args[0])}]=v;')
    elif op=='lea' and len(args)==2 and args[0] in REGS and width(args[0])>=32:
        a,_=address(args[1],end);write(args[0],width(args[0]),a)
    elif op in ('mov','movabs','movzx','movsx','movsxd') and len(args)==2:
        w=width(args[0]);src=width(args[1]) or w
        if not w or not src or (op in ('mov','movabs') and w!=src) or (op not in ('mov','movabs') and (src>=w or args[0] not in REGS or width(args[1]) is None)):raise ValueError('width')
        v=read(args[1],src,'a');write(args[0],w,f'sx({v},{src})' if op in ('movsx','movsxd') else v)
    elif op in ('add','sub','and','or','xor','cmp','test','inc','dec','neg','not') and len(args)==(1 if op in ('inc','dec','neg','not') else 2):
        w=width(args[0]);
        if not w:raise ValueError('width')
        a=read(args[0],w,'a');b=read(args[1],w,'b') if len(args)==2 else '0'
        if op=='not':v=f'~({a})'
        else:
            k={'add':0,'sub':1,'cmp':1,'and':2,'test':2,'or':3,'xor':4,'inc':5,'dec':6,'neg':7}[op]
            # For memory RMW, preflight isn't possible with the minimal callbacks;
            # reject rather than changing flags before a failed write.
            if MEM.fullmatch(args[0]) and op not in ('cmp','test'):raise ValueError('memory_rmw')
            v=f'alu(s,{w},{k},{a},{b})'
        if op in ('cmp','test'):code.append(f'(void){v};')
        else:write(args[0],w,v)
    else:raise ValueError('opcode:'+op)
    advance(end);return ''.join(code),edges

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

def inventory(data,ins):
    pe=struct.unpack_from('<I',data,0x3c)[0];opt=pe+24;base=struct.unpack_from('<Q',data,opt+24)[0]
    n=struct.unpack_from('<H',data,pe+6)[0];sz=struct.unpack_from('<H',data,pe+20)[0];sections=[]
    for i in range(n):
        at=opt+sz+40*i;_,rva,size,off=struct.unpack_from('<IIII',data,at+8);flags=struct.unpack_from('<I',data,at+36)[0]
        if size and off+size<=len(data):sections.append((base+rva,base+rva+size,off,flags))
    def raw_at(a,n,exec_only=False):
        for lo,hi,off,f in sections:
            if lo<=a and a+n<=hi and (not exec_only or f&0x20000000):return data[off+a-lo:off+a-lo+n]
    verified={a:r for a,r in ins.items() if r[0]==raw_at(a,len(r[0]),True)}
    targets=Counter()
    for a,(raw,op,_) in verified.items():
        if op=='call' and len(raw)==5 and raw[0]==0xe8:targets[target(raw,a,op)[0]]+=1
    pdata,size=struct.unpack_from('<II',data,opt+112+3*8);blob=raw_at(base+pdata,size)
    if not blob or size%12:raise ValueError('unwind')
    intervals={base+a:base+b for a,b,_ in struct.iter_unpack('<III',blob) if a<b and raw_at(base+a,b-a,True) is not None}
    return base,verified,targets,intervals

def graph_policy(ins,intervals):
    starts=sorted(intervals)
    def owner(pc):
        i=bisect_right(starts,pc)-1
        return starts[i] if i>=0 and pc<intervals[starts[i]] else None
    def allowed(pc):
        a=owner(pc)
        return a is not None and intervals[a]-a<=4096 and pc in ins and pc+len(ins[pc][0])<=intervals[a]
    def edge(pc,d):
        a,b=owner(pc),owner(d)
        if a is not None and a==b:return True
        # Cross-interval transfers must be actual CALL/JMP targets at exact
        # unwind starts. No cross-interval fallthrough or conditional jump.
        if b is None or d!=b or ins[pc][1] not in ('call','jmp'):return False
        raw,op,_=ins[pc]
        return target(raw,pc,op)[0]==d
    return owner,allowed,edge

def build(exe,dest):
    exe=Path(exe);dest=Path(dest);data=exe.read_bytes()
    if len(data)!=3878912 or hashlib.sha256(data).hexdigest()!=SHA:raise ValueError('demo_hash')
    dest.mkdir(mode=0o700,parents=True,exist_ok=False)
    lines=subprocess.check_output(['llvm-objdump','-d','--x86-asm-syntax=intel',str(exe)],text=True,timeout=120)
    base,ins,targets,intervals=inventory(data,decode(lines.splitlines()))
    rows=[];reject=Counter();sources=[PREAMBLE];all_nodes=set()
    owner,allowed,edge=graph_policy(ins,intervals)
    # Each cross-interval direct transfer must enter an exact unwind start.
    for a,b in sorted(intervals.items()):
        if b-a>4096:reject['interval_limit']+=1;continue
        try:src,seen=lift(ins,a,f'mxb_cfg_{a-base:x}',allowed,edge_allowed=edge)
        except ValueError as e:reject[str(e).split(':')[0]]+=1;continue
        rows.append({'rva':hex(a-base),'nodes':len(seen),'branches':sum(ins[p][1].startswith('j') for p in seen),'calls':sum(ins[p][1]=='call' for p in seen),'direct_references':targets[a],'linked_intervals':len({owner(p) for p in seen})});sources.append(src);all_nodes.update(seen)
    if not rows:raise ValueError('no_graphs')
    source=dest/'private-cfg.c';source.write_text(''.join(sources));obj=dest/'private-cfg.o'
    subprocess.run(['clang','--target=arm64-apple-ios15.0','-ffreestanding','-fno-builtin','-O2','-c',str(source),'-o',str(obj)],check=True,timeout=120)
    if obj.read_bytes()[:8]!=b'\xcf\xfa\xed\xfe\x0c\x00\x00\x01':raise ValueError('arm64_object')
    report={'sha256':SHA,'decoded_addresses':len(ins),'unwind_intervals':len(intervals),'compiled_cfgs':len(rows),'branch_cfgs':sum(bool(r['branches']) for r in rows),'call_cfgs':sum(bool(r['calls']) for r in rows),'linked_cfgs':sum(r['linked_intervals']>1 for r in rows),'decoded_nodes':sum(r['nodes'] for r in rows),'unique_decoded_nodes':len(all_nodes),'arm64_executed':False,'original_differential_verified':False,'rejections':dict(reject),'candidates':rows}
    (dest/'metadata.json').write_text(json.dumps(report,indent=2)+'\n');return report

if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('exe');p.add_argument('private_dir');a=p.parse_args();r=build(a.exe,a.private_dir);print(json.dumps({k:v for k,v in r.items() if k!='candidates'},indent=2))
