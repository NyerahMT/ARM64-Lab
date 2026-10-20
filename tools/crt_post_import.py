"""Bounded CRT post-import continuation translators. No real MSVCR90 runtime."""
from capstone import Cs,CS_ARCH_X86,CS_MODE_64
from capstone.x86 import X86_OP_REG,X86_OP_IMM,X86_OP_MEM
from .crt_cfg_lift import UnsupportedCRT

def decode(code,start,kinds):
    if not isinstance(code,bytes) or not 7<=len(code)<=64:
        raise UnsupportedCRT("Bounded original CRT continuation only")
    d=Cs(CS_ARCH_X86,CS_MODE_64);d.detail=True
    a=list(d.disasm(code,start))
    if len(a)!=len(kinds) or sum(x.size for x in a)!=len(code) or tuple(x.mnemonic for x in a)!=kinds:
        raise UnsupportedCRT("Unsupported original CRT instruction sequence")
    return a

def reg(i,o,name,size):
    return o.type==X86_OP_REG and o.size==size and i.reg_name(o.reg)==name

def imm(o,value):
    return o.type==X86_OP_IMM and o.imm==value

def after_initterm_e(code,start,base=0x140000000):
    test,je,mov,jmp=decode(code,start,("test","je","mov","jmp"))
    if not(len(test.operands)==2 and all(reg(test,o,"eax",4) for o in test.operands)):
        raise UnsupportedCRT("Expected TEST EAX,EAX")
    if not(len(je.operands)==1 and je.operands[0].type==X86_OP_IMM):
        raise UnsupportedCRT("Expected JE success")
    if not(len(mov.operands)==2 and reg(mov,mov.operands[0],"eax",4) and imm(mov.operands[1],255)):
        raise UnsupportedCRT("Expected MOV EAX,255")
    if not(len(jmp.operands)==1 and jmp.operands[0].type==X86_OP_IMM):
        raise UnsupportedCRT("Expected JMP CRT failure")
    success,error=je.operands[0].imm,jmp.operands[0].imm
    if not start+len(code)<=success<=start+512 or not success<error<=start+4096:
        raise UnsupportedCRT("Unexpected continuation targets")
    c=("#include <stdint.h>\n#include \"mx_crt_vm.h\"\n"
       "int crt_after_initterm_e(mx_crt_state*s){\n"
       f"if(!s||s->fault||s->rip!=UINT64_C({base+start})||s->instructions)return MX_CRT_INVALID;\n"
       "s->visited=1;s->instructions=1;s->zf=((uint32_t)s->rax==0);\n"
       "s->visited|=2;s->instructions++;\n"
       f"if(s->zf){{s->rip=UINT64_C({base+success});return MX_CRT_BRANCH_BOUNDARY;}}\n"
       "s->visited|=4;s->instructions++;s->rax=255;\n"
       "s->visited|=8;s->instructions++;\n"
       f"s->rip=UINT64_C({base+error});return MX_CRT_BRANCH_BOUNDARY;\n"
       "}\n")
    return c,{"return_success_rva":hex(success),"return_error_rva":hex(error),
              "decoded_original_instructions":4,"import_is_synthetic":True}

def after_initterm(code,start,base=0x140000000):
    mov,test,jne,xor,xchg=decode(code,start,("mov","test","jne","xor","xchg"))
    def rip(i,o,size):
        return o.type==X86_OP_MEM and o.size==size and not o.mem.segment and not o.mem.index and i.reg_name(o.mem.base)=="rip"
    if not(len(mov.operands)==2 and rip(mov,mov.operands[0],4) and imm(mov.operands[1],2)):
        raise UnsupportedCRT("Expected state=2 write")
    if not(len(test.operands)==2 and all(reg(test,o,"esi",4) for o in test.operands)):
        raise UnsupportedCRT("Expected TEST ESI,ESI")
    if not(len(jne.operands)==1 and imm(jne.operands[0],start+len(code))):
        raise UnsupportedCRT("Unexpected release-skip edge")
    if not(len(xor.operands)==2 and all(reg(xor,o,"eax",4) for o in xor.operands)):
        raise UnsupportedCRT("Expected XOR EAX,EAX")
    if not(len(xchg.operands)==2 and rip(xchg,xchg.operands[0],8) and reg(xchg,xchg.operands[1],"rax",8)):
        raise UnsupportedCRT("Expected XCHG64 lock release")
    state=base+mov.address+mov.size+mov.operands[0].mem.disp
    lock=base+xchg.address+xchg.size+xchg.operands[0].mem.disp
    if not base<=state<base+0x10000000 or not base<=lock<base+0x10000000 or lock&7 or state==lock:
        raise UnsupportedCRT("Unsafe CRT lock/state address")
    end=base+start+len(code)
    c=("#include <stdint.h>\n#include \"mx_crt_primitives.h\"\n"
       "int crt_after_initterm(mx_crt_state*s,mx_cfg_memory*m,int exclusive){\n"
       f"if(!s||!m||s->fault||s->rip!=UINT64_C({base+start})||s->instructions)return MX_CRT_INVALID;\n"
       f"s->visited=1;s->instructions=1;if(!mx_crt_write(s,m,UINT64_C({state}),4,2))return MX_CRT_MEMORY_FAULT;\n"
       "s->visited|=2;s->instructions++;s->zf=((uint32_t)s->rsi==0);\n"
       "s->visited|=4;s->instructions++;\n"
       f"if(!s->zf){{s->rip=UINT64_C({end});return MX_CRT_BRANCH_BOUNDARY;}}\n"
       "s->visited|=8;s->instructions++;s->rax=0;s->zf=1;\n"
       "s->visited|=16;s->instructions++;\n"
       f"if(!mx_crt_xchg64_single_thread(s,m,UINT64_C({lock}),exclusive))return MX_CRT_MEMORY_FAULT;\n"
       f"s->rip=UINT64_C({end});return MX_CRT_BRANCH_BOUNDARY;\n"
       "}\n")
    return c,{"decoded_original_instructions":5,"state_global_va":hex(state),
              "lock_owner_va":hex(lock),"join_rva":hex(start+len(code)),
              "concurrent_lock_supported":False}
