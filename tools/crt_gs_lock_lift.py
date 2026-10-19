"""Bounded original x64 GS/TEB and single-threaded CMPXCHG CRT block lift.

Stops BEFORE the conditional jump after CMPXCHG. It does not implement Win64
thread scheduling, GS base management or concurrent LOCK atomic semantics.
"""
from capstone import Cs,CS_ARCH_X86,CS_MODE_64
from capstone.x86 import X86_OP_REG,X86_OP_MEM,X86_OP_IMM
from .crt_cfg_lift import UnsupportedCRT, _addr

def lift_crt_gs_lock_prefix(code:bytes,start:int,image_base:int=0x140000000):
    """Translate six supported original x64 instructions, reject unsupported forms."""
    if not isinstance(code,bytes) or len(code)<20 or len(code)>72:
        raise UnsupportedCRT("Guest GS/CMPXCHG block outside byte bound")
    md=Cs(CS_ARCH_X86,CS_MODE_64)
    md.detail=True
    ins=list(md.disasm(code,start))
    if len(ins)!=7 or sum(i.size for i in ins)!=len(code):
        raise UnsupportedCRT("Expected complete seven-instruction GS/LOCK boundary")
    if tuple(i.mnemonic for i in ins)!=("nop","mov","mov","xor","xor","lock cmpxchg","je"):
        raise UnsupportedCRT("Unrecognized GS/LOCK instruction signature")
    nop,gs,mov,esi,eax,cas,branch=ins
    def register(i,o,reg,size):
        return (o.type==X86_OP_REG and i.reg_name(o.reg)==reg and o.size==size)
    if nop.operands:
        raise UnsupportedCRT("NOP unexpectedly has operands")
    if (len(gs.operands)!=2 or not register(gs,gs.operands[0],"rax",8) or
        gs.operands[1].type!=X86_OP_MEM or gs.operands[1].size!=8 or
        gs.reg_name(gs.operands[1].mem.segment)!="gs" or
        gs.operands[1].mem.base or gs.operands[1].mem.index):
        raise UnsupportedCRT("Unrecognized GS-segment read")
    gs_offset=gs.operands[1].mem.disp
    if gs_offset<0 or gs_offset>128 or gs_offset%8:
        raise UnsupportedCRT("Unbounded GS segment displacement")
    if (len(mov.operands)!=2 or not register(mov,mov.operands[0],"rdi",8) or
        mov.operands[1].type!=X86_OP_MEM or mov.operands[1].size!=8 or
        mov.operands[1].mem.segment or mov.operands[1].mem.index or
        mov.reg_name(mov.operands[1].mem.base)!="rax"):
        raise UnsupportedCRT("Unrecognized TEB pointer dereference")
    teb_offset=mov.operands[1].mem.disp
    if teb_offset<0 or teb_offset>128 or teb_offset%8:
        raise UnsupportedCRT("Unbounded TEB field offset")
    for i,reg in ((esi,"esi"),(eax,"eax")):
        if (len(i.operands)!=2 or not all(register(i,o,reg,4) for o in i.operands)):
            raise UnsupportedCRT("Unsupported 32-bit zeroing XOR")
    if (len(cas.operands)!=2 or cas.operands[0].type!=X86_OP_MEM or
        cas.operands[0].size!=8 or not register(cas,cas.operands[1],"rdi",8) or
        not cas.prefix or 0xf0 not in cas.prefix):
        raise UnsupportedCRT("Expected LOCK CMPXCHG64 with guest global")
    global_va=_addr(cas,cas.operands[0],image_base)
    if (len(branch.operands)!=1 or branch.operands[0].type!=X86_OP_IMM):
        raise UnsupportedCRT("Unrecognized conditional branch")
    target=branch.operands[0].imm
    if target<=branch.address or target>start+1024:
        raise UnsupportedCRT("Unbounded branch destination")
    lines=[
        '#include <stdint.h>\n#include "mx_crt_primitives.h"\n',
        'int lifted_crt_gs_lock_prefix(mx_crt_state *s,mx_cfg_memory *m,uint64_t gsbase,int exclusive) {\n',
        f' if(!s||!m||s->fault||s->rip!=UINT64_C({image_base+start}))return MX_CRT_INVALID;\n',
        ' if(s->instructions)return MX_CRT_INVALID;\n',
        ' s->visited|=UINT64_C(1);s->instructions++; /* NOP */\n',
        ' s->visited|=UINT64_C(2);s->instructions++;\n',
        f' if(!mx_crt_gs_read64(s,m,gsbase,UINT64_C({gs_offset}),&s->rax))return MX_CRT_MEMORY_FAULT;\n',
        ' s->visited|=UINT64_C(4);s->instructions++;\n',
        f' s->rdi=mx_crt_read(s,m,s->rax+UINT64_C({teb_offset}),8);\n',
        ' if(s->fault)return MX_CRT_MEMORY_FAULT;\n',
        ' s->visited|=UINT64_C(8);s->instructions++;\n',
        ' s->rsi=0U;s->zf=1;\n',
        ' s->visited|=UINT64_C(16);s->instructions++;\n',
        ' s->rax=0U;s->zf=1;\n',
        ' s->visited|=UINT64_C(32);s->instructions++;\n',
        f' if(!mx_crt_cmpxchg64_single_thread(s,m,{global_va},s->rdi,exclusive))return MX_CRT_MEMORY_FAULT;\n',
        f' s->rip=UINT64_C({image_base+branch.address});\n',
        ' return MX_CRT_BRANCH_BOUNDARY;\n',
        '}\n'
    ]
    meta={"original_instructions_executed":6,
          "decoded_instructions_including_branch":7,
          "start_rva":hex(start),"stop_before_branch_rva":hex(branch.address),
          "jump_target_rva":hex(target),
          "uses_gs_teb":True,"uses_exclusive_compare_exchange":True,
          "fully_models_lock_atomicity":False,"executes_branch":False}
    return "".join(lines),meta
