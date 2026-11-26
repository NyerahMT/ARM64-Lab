"""Bounded legacy byte-string instructions for the original-PC dispatcher.

No host pointers or guest-derived unbounded native loops. REP progress is
committed per successful guest read; faults and work limits retain guest RIP.
"""
PREAMBLE=r'''
#define MXB_DF UINT64_C(1024)
#define MXB_SCAN_BUDGET 65536u
static inline int mxb_scan_byte(mxb_cfg*s,unsigned repeat_equal){
 for(unsigned n=0;n<MXB_SCAN_BUDGET&&s->r[1];++n){
  uint64_t v=0;
  if(!s->read||!s->read(s->ctx,s->r[7],1,&v))return -2;
  (void)alu(s,8,1,s->r[0],v);
  s->r[7]+=(s->flags&MXB_DF)?UINT64_MAX:UINT64_C(1);
  --s->r[1];
  if((unsigned)!!(s->flags&ZF)!=repeat_equal)return 1;
 }
 return s->r[1]?-6:1;
}
static inline int mxb_compare_byte(mxb_cfg*s,unsigned repeat_equal){
 for(unsigned n=0;n<MXB_SCAN_BUDGET&&s->r[1];++n){
  uint64_t a=0,b=0;
  if(!s->read||!s->read(s->ctx,s->r[6],1,&a)||!s->read(s->ctx,s->r[7],1,&b))return -2;
  (void)alu(s,8,1,a,b);
  uint64_t d=(s->flags&MXB_DF)?UINT64_MAX:UINT64_C(1);
  s->r[6]+=d;s->r[7]+=d;--s->r[1];
  if((unsigned)!!(s->flags&ZF)!=repeat_equal)return 1;
 }
 return s->r[1]?-6:1;
}
'''

def emit(row,pc):
    raw,op,args=row;end=pc+len(raw)
    # Accept exact legacy encodings only. ES is implicit and ignored in long mode.
    if raw in (b'\xf2\xae',b'\xf3\xae') and (op=='scasb' or op.endswith(' scasb') or op in ('repne','repnz','repe','repz','rep')):
        equal=int(raw[0]==0xf3)
        return f'int rc=mxb_scan_byte(s,{equal});if(rc!=1)return rc;s->rip=UINT64_C({end});break;',[end]
    if raw in (b'\xf2\xa6',b'\xf3\xa6') and (op=='cmpsb' or op.endswith(' cmpsb') or op in ('repne','repnz','repe','repz','rep')):
        equal=int(raw[0]==0xf3)
        return f'int rc=mxb_compare_byte(s,{equal});if(rc!=1)return rc;s->rip=UINT64_C({end});break;',[end]
    if raw==b'\xf3\xc3' and op in ('ret','rep ret','repz ret','repe ret','rep'):
        return 'uint64_t v;if(!pop(s,&v))return -2;s->rip=v;break;',[]
    return None
