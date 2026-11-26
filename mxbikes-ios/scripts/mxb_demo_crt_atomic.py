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
    # RIP-relative qword CMPXCHG with LOCK, or implicit-LOCK XCHG.
    cmp=op in ('lock cmpxchg','cmpxchg') and len(raw)==9 and raw[:4]==b'\xf0\x48\x0f\xb1'
    xchg=op=='xchg' and len(raw)==7 and raw[:2]==b'\x48\x87'
    if not (cmp or xchg):return None
    if len(args)!=2:raise ValueError("atomic_operands")
    if xchg and args[0] in cfg.GPRS:args.reverse()
    mem,reg=args
    if reg not in cfg.GPRS or not re.fullmatch(r'qword ptr \[rip(?: [+-] 0x[0-9a-f]+)?\]',mem):raise ValueError("atomic_form")
    modrm=raw[4] if cmp else raw[2]
    if modrm&0xc7!=5 or ((modrm>>3)&7)!=cfg.GPRS.index(reg):raise ValueError("atomic_encoding")
    addr,w=cfg.address(mem,end)
    if w!=64:raise ValueError("atomic_width")
    i=cfg.GPRS.index(reg)
    call=f'mx_crt_cmpxchg64(s,{addr},s->r[{i}])' if cmp else f'mx_crt_xchg64(s,{addr},{i})'
    return f'int rc={call};if(rc!=1)return rc;s->rip=UINT64_C({end});break;',[end]
