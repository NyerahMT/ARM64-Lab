"""Strictly translate a small CRT prologue up to the first Win64 import boundary.

This deliberately STOPS before the imported CALL; GetStartupInfoA is not
implemented, simulated or counted as a successful guest import.
"""
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
from capstone.x86 import X86_OP_IMM, X86_OP_MEM, X86_OP_REG
from .crt_cfg_lift import _get, _put, _addr, UnsupportedCRT

EXPECTED=("mov","push","sub","and","lea","call")

def lift_crt_entry_prefix(code:bytes,start:int,iat:dict,image_base:int=0x140000000):
    """Return original-instruction-derived C and strictly scoped metadata.

    Supports one bounded five-instruction prologue ending before a validated
    RIP-relative GetStartupInfoA call. No Windows/API semantic execution.
    """
    if not isinstance(code,bytes) or len(code)>64 or len(code)<12:
        raise UnsupportedCRT("CRT prefix outside bounded byte range")
    md=Cs(CS_ARCH_X86,CS_MODE_64)
    md.detail=True
    ins=list(md.disasm(code,start))
    if len(ins)!=6 or tuple(x.mnemonic for x in ins)!=EXPECTED:
        raise UnsupportedCRT("Expected exact supported six-op CRT prefix")
    if sum(x.size for x in ins)!=len(code):
        raise UnsupportedCRT("Incomplete CRT prefix disassembly")
    a,b,c,d,e,call=ins
    def reg(ins,operand,name,size):
        return (operand.type==X86_OP_REG and ins.reg_name(operand.reg)==name
                and operand.size==size)
    def mem(ins,operand,base,disp,size):
        return (operand.type==X86_OP_MEM and operand.size==size and
                not operand.mem.segment and not operand.mem.index and
                ins.reg_name(operand.mem.base)==base and operand.mem.disp==disp)
    if not (len(a.operands)==2 and mem(a,a.operands[0],"rsp",a.operands[0].mem.disp,8)
            and reg(a,a.operands[1],"rsi",8) and
            0<a.operands[0].mem.disp<=64):
        raise UnsupportedCRT("Unsupported stack-save original MOV")
    if len(b.operands)!=1 or not reg(b,b.operands[0],"rdi",8):
        raise UnsupportedCRT("Unsupported original PUSH")
    if (len(c.operands)!=2 or not reg(c,c.operands[0],"rsp",8) or
        c.operands[1].type!=X86_OP_IMM or
        not (16<=c.operands[1].imm<=512) or c.operands[1].imm%16):
        raise UnsupportedCRT("Unsupported stack allocation")
    if (len(d.operands)!=2 or d.operands[1].type!=X86_OP_IMM or
        d.operands[1].imm!=0 or d.operands[0].type!=X86_OP_MEM or
        d.operands[0].size!=4):
        raise UnsupportedCRT("Unsupported original stack-zero AND")
    _addr(d,d.operands[0],image_base)
    if (len(e.operands)!=2 or not reg(e,e.operands[0],"rcx",8) or
        e.operands[1].type!=X86_OP_MEM):
        raise UnsupportedCRT("Unsupported original guest address LEA")
    _addr(e,e.operands[1],image_base)
    if (len(call.operands)!=1 or call.operands[0].type!=X86_OP_MEM or
        call.operands[0].mem.index or call.operands[0].mem.segment or
        call.reg_name(call.operands[0].mem.base)!="rip"):
        raise UnsupportedCRT("Expected validated RIP-relative IAT CALL")
    slot=call.address+call.size+call.operands[0].mem.disp
    if iat.get(slot)!=("kernel32.dll","GetStartupInfoA"):
        raise UnsupportedCRT("Unsupported imported call boundary")
    begin=image_base+start
    boundary=image_base+call.address
    lines=[
        '#include <stdint.h>\n#include "mx_crt_vm.h"\n',
        'int lifted_crt_entry_prefix(mx_crt_state *s,mx_cfg_memory *m) {\n',
        ' if(!s||!m||s->fault||s->rip!=UINT64_C('+str(begin)+'))return MX_CRT_INVALID;\n',
        ' if((s->rsp&15U)!=8U)return MX_CRT_INVALID;\n',
        ' if(s->instructions)return MX_CRT_INVALID;\n',
        ' s->visited|=UINT64_C(1);s->instructions++;\n',
        ' '+_put(a,a.operands[0],_get(a,a.operands[1],image_base),image_base)+'\n',
        ' if(s->fault)return MX_CRT_MEMORY_FAULT;\n',
        ' s->visited|=UINT64_C(2);s->instructions++;\n',
        ' s->rsp-=8U;\n',
        ' if(!mx_crt_write(s,m,s->rsp,8,s->rdi))return MX_CRT_MEMORY_FAULT;\n',
        ' s->visited|=UINT64_C(4);s->instructions++;\n',
        ' s->rsp-='+str(c.operands[1].imm)+'U;\n',
        ' s->visited|=UINT64_C(8);s->instructions++;\n',
        ' (void)mx_crt_read(s,m,'+_addr(d,d.operands[0],image_base)+',4);\n',
        ' if(s->fault)return MX_CRT_MEMORY_FAULT;\n',
        ' '+_put(d,d.operands[0],"0",image_base)+'\n',
        ' s->zf=1;\n',
        ' s->visited|=UINT64_C(16);s->instructions++;\n',
        ' '+_put(e,e.operands[0],_addr(e,e.operands[1],image_base),image_base)+'\n',
        ' if(s->fault)return MX_CRT_MEMORY_FAULT;\n',
        ' s->rip=UINT64_C('+str(boundary)+');\n',
        ' return MX_CRT_IMPORT_BOUNDARY;\n',
        '}\n'
    ]
    report={
        "original_prefix_instruction_count":5,
        "decoded_original_instructions_with_boundary":6,
        "entry_rva":hex(start),
        "stop_before_import_rva":hex(call.address),
        "verified_import_symbol":"kernel32.dll::GetStartupInfoA",
        "api_executed":False,
        "scope":"Five-instruction original CRT prologue before first imported CALL"
    }
    return "".join(lines),report
