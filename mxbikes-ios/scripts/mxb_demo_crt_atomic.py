"""Single-thread guest CRT environment and locked memory operations.

These emit only exact supported forms. The exclusive_guest contract is
required because read/write callbacks are not a concurrent atomic primitive.
A multithreaded engine must supply a genuinely synchronized memory backend.
"""
import re
import mxb_demo_cfg_batch as cfg
PREAMBLE=r'''
static inline int mx_crt_cmpxchg64(mxb_cfg*s,uint64_t addr,uint64_t src){
 if(!s->exclusive_guest)return -8;
 uint64_t old=0,acc=s->r[0];
 if(!s->read||!s->write||!s->read(s->ctx,addr,8,&old))return -2;
 /* Locked CMPXCHG requires write permission even on comparison failure. */
 if(!s->write(s->ctx,addr,8,acc==old?src:old))return -2;
 (void)alu(s,64,1,acc,old);
 if(acc!=old)s->r[0]=old;
 return 1;
}
static inline int mx_crt_xchg64(mxb_cfg*s,uint64_t addr,unsigned reg){
 if(!s->exclusive_guest)return -8;
 uint64_t old=0;
 if(!s->read||!s->write||!s->read(s->ctx,addr,8,&old)||!s->write(s->ctx,addr,8,s->r[reg]))return -2;
 s->r[reg]=old;return 1;
}
static inline int mx_atomic_mem(mxb_cfg*s,uint64_t addr,unsigned w,unsigned reg,unsigned kind){
 if(!s->exclusive_guest)return -8;
 uint64_t old=0,m=mask(w),src=s->r[reg]&m,acc=s->r[0]&m;
 if(!s->read||!s->write||!s->read(s->ctx,addr,w/8,&old))return -2;old&=m;
 mxb_cfg tmp=*s;
 uint64_t result=kind==0?(acc==old?src:old):kind==1?src:alu(&tmp,w,3,old,src);
 if(!s->write(s->ctx,addr,w/8,result))return -2;
 if(kind==0){(void)alu(s,w,1,acc,old);if(acc!=old)regset(s,0,w,old);}
 else if(kind==1)regset(s,reg,w,old);
 else{s->flags=tmp.flags;s->known=tmp.known;}
 return 1;
}
'''
def emit(row,pc):
    raw,op,arg=row;end=pc+len(raw);args=[a.strip() for a in arg.split(',')]
    # Only the observed absolute GS disp32, 64-bit load. No host TLS access.
    if raw==b'\x65\x48\x8b\x04\x25\x30\x00\x00\x00' and op=='mov':
        if len(args)!=2 or args[0]!='rax' or not re.fullmatch(r'qword ptr gs:\[?(?:0x30|48)\]?',args[1]):raise ValueError("gs_operand")
        return f'uint64_t v;if(!s->gs_base||!s->read||!s->read(s->ctx,s->gs_base+48,8,&v))return -2;s->r[0]=v;s->rip=UINT64_C({end});break;',[end]
    # MSVC stack probing reads the current thread's guest stack limit.
    if raw==b'\x65\x4c\x8b\x1c\x25\x10\x00\x00\x00' and op=='mov':
        if len(args)!=2 or args[0]!='r11' or not re.fullmatch(r'qword ptr gs:\[?(?:0x10|16)\]?',args[1]):raise ValueError("gs_stack_limit_operand")
        return f'uint64_t v;if(!s->gs_base||!s->read||!s->read(s->ctx,s->gs_base+16,8,&v))return -2;s->r[11]=v;s->rip=UINT64_C({end});break;',[end]
    # General checked memory atomic operations. Single-thread guest only.
    if op not in ("lock cmpxchg","cmpxchg","xchg","lock or"):return None
    if len(args)!=2:return None
    if op=="xchg" and args[0] in cfg.REGS:args.reverse()
    mem,reg=args
    if not cfg.MEM.fullmatch(mem) or reg not in cfg.REGS:return None
    addr,w=cfg.address(mem,end);ri,rw=cfg.REGS[reg]
    if w!=rw or w not in (16,32,64):raise ValueError("atomic_width")
    pos=0;locked=False;word=False;rex=0
    if raw[pos]==0xf0:locked=True;pos+=1
    if pos<len(raw) and raw[pos]==0x66:word=True;pos+=1
    if pos<len(raw) and 0x40<=raw[pos]<=0x4f:rex=raw[pos];pos+=1
    if (64 if rex&8 else 16 if word else 32)!=w:raise ValueError("atomic_encoding_width")
    if op in ("lock cmpxchg","cmpxchg"):
        opcode=b'\x0f\xb1';kind=0
    elif op=="xchg":opcode=b'\x87';kind=1
    else:opcode=b'\x09';kind=2
    if kind==2 and not locked:return None
    if kind==0 and not locked:return None
    if raw[pos:pos+len(opcode)]!=opcode:raise ValueError("atomic_encoding")
    pos+=len(opcode)
    if pos>=len(raw) or raw[pos]>=0xc0 or (((raw[pos]>>3)&7)+(8 if rex&4 else 0))!=ri:raise ValueError("atomic_modrm")
    return f'int rc=mx_atomic_mem(s,{addr},{w},{ri},{kind});if(rc!=1)return rc;s->rip=UINT64_C({end});break;',[end]
