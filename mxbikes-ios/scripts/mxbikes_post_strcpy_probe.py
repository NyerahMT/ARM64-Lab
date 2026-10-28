#!/usr/bin/env python3
"""Execute original MX Bikes x64 main through TWO modeled imported APIs,
then inspect the first post-strcpy helper control transfer at RVA 0x15b7aa.

Private, SHA-verified PE only. Both host services are deterministic fixtures,
not actual Windows DLLs. Bounded original instruction execution stops before
the next transfer; no new native code is claimed in this recon run.
"""
from pathlib import Path
import hashlib,json,struct,sys
from capstone import Cs,CS_ARCH_X86,CS_MODE_64,CS_GRP_CALL,CS_GRP_JUMP,CS_GRP_RET
from capstone.x86 import X86_OP_IMM,X86_OP_MEM
from unicorn import UC_HOOK_CODE
from unicorn.x86_const import (
    UC_X86_REG_RIP,UC_X86_REG_RSP,UC_X86_REG_RAX,
    UC_X86_REG_RBX,UC_X86_REG_RCX,UC_X86_REG_RDX,
    UC_X86_REG_R8,UC_X86_REG_R9,UC_X86_REG_RDI,
    UC_X86_REG_RSI,UC_X86_REG_R11,UC_X86_REG_R10,
    UC_X86_REG_EFLAGS
)
from mxbikes_joined_strcpy_native import (
  BASE,MAIN,AFTER_IMPORT,HOST_STUB,GUEST_CRT,PATH,PATH_LEN,WINDOW,
  verify_next_import,inspect_original,new_cpu,ENTRY_SP,TEST_INPUT,
  SEED_RBX,SEED_RDI,SEED_RSI,SEED_R11,EXE_SHA,MAX,
  RETURN,original_thunk,STACK_MAIN_RSP,HELPER_LOCAL_RSP
)
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/"arm64-lab"))
from tools.pe_probe import PE

START=RETURN
MAX_BYTE_SCAN=256
MAX_PREFIX_INS=38
MAX_WALK_INS=140

def discover(pe):
    decoder=Cs(CS_ARCH_X86,CS_MODE_64);decoder.detail=True
    seen=[]
    stop=None
    for instruction in decoder.disasm(pe.read_rva(START,MAX_BYTE_SCAN),START):
        if (instruction.group(CS_GRP_JUMP) or instruction.group(CS_GRP_RET) or
            instruction.group(CS_GRP_CALL)):
            stop=instruction;break
        seen.append(instruction)
        if len(seen)>=MAX_PREFIX_INS:
            raise RuntimeError("Post-strcpy original prefix exceeds bound")
    if not stop:
        raise RuntimeError("Post-strcpy original control not found within bound")
    details={
        "start_rva":hex(START),
        "first_control_rva":hex(stop.address),
        "first_control_mnemonic":stop.mnemonic,
        "first_control_operands":stop.op_str,
        "precontrol_instruction_count":len(seen),
        "precontrol_byte_count":stop.address-START,
        "precontrol_insns":[{"rva":hex(x.address),"mnemonic":x.mnemonic,"operands":x.op_str}
                           for x in seen]
    }
    if stop.group(CS_GRP_CALL) and stop.operands:
        op=stop.operands[0]
        if op.type==X86_OP_IMM:
            details["direct_callee_rva"]=hex(int(op.imm))
        if op.type==X86_OP_MEM and stop.reg_name(op.mem.base)=="rip" and not op.mem.index:
            details["indirect_iat_rva"]=hex(stop.address+stop.size+op.mem.disp)
    if stop.group(CS_GRP_JUMP) and stop.operands and stop.operands[0].type==X86_OP_IMM:
        details["branch_target_rva"]=hex(int(stop.operands[0].imm))
    return details,stop

def reference(pe,first_slot,strcpy_slot,original_dest,stop,k,execute_direct_jump=False):
    cpu=new_cpu(pe)
    cpu.mem_map(HOST_STUB,0x2000)
    cpu.mem_write(HOST_STUB,b"\xc3")
    cpu.mem_write(GUEST_CRT,b"\xc3")
    cpu.mem_write(BASE+first_slot,struct.pack("<Q",HOST_STUB))
    cpu.mem_write(BASE+strcpy_slot,struct.pack("<Q",GUEST_CRT))
    cpu.mem_write(TEST_INPUT,b"\x00")
    cpu.mem_write(ENTRY_SP,struct.pack("<Q",BASE+0x777777))
    seeds={
      UC_X86_REG_RIP:BASE+MAIN,UC_X86_REG_RSP:ENTRY_SP,
      UC_X86_REG_RAX:0x888876543210+k,
      UC_X86_REG_RBX:SEED_RBX,UC_X86_REG_RCX:BASE,
      UC_X86_REG_RDX:0,UC_X86_REG_R8:TEST_INPUT,UC_X86_REG_R9:10,
      UC_X86_REG_RDI:SEED_RDI,UC_X86_REG_RSI:SEED_RSI,
      UC_X86_REG_R11:SEED_R11,UC_X86_REG_R10:0x78123456789,
      UC_X86_REG_EFLAGS:0x202|[0,1,0x40,0x80,0xc1,0x41,0x200,0x81][k%8]
    }
    for reg,value in seeds.items():cpu.reg_write(reg,value)
    observed=[]
    trace=[]
    def hook(u,pc,size,unused):
        trace.append(pc)
        if pc==HOST_STUB:
            if(u.reg_read(UC_X86_REG_RCX)!=0 or
               u.reg_read(UC_X86_REG_RDX)!=STACK_MAIN_RSP+0x140 or
               u.reg_read(UC_X86_REG_R8)!=WINDOW):
                raise RuntimeError("Original GetModuleFileNameA argument mismatch")
            u.mem_write(STACK_MAIN_RSP+0x140,PATH+b"\x00")
            u.reg_write(UC_X86_REG_RAX,PATH_LEN)
            observed.append("GetModuleFileNameA")
        elif pc==GUEST_CRT:
            dst=u.reg_read(UC_X86_REG_RCX)
            src=u.reg_read(UC_X86_REG_RDX)
            if dst!=original_dest or src!=STACK_MAIN_RSP+0x140:
                raise RuntimeError("Original strcpy argument mismatch")
            data=bytearray()
            for i in range(MAX):
                b=bytes(u.mem_read(src+i,1))
                data+=b
                if b==b"\x00":break
            else:
                raise RuntimeError("Source string exceeds strcpy bound")
            u.mem_write(dst,bytes(data))
            u.reg_write(UC_X86_REG_RAX,dst)
            observed.append("strcpy")
        if len(trace)>=MAX_WALK_INS:
            raise RuntimeError("Original game startup step count overrun")
    cpu.hook_add(UC_HOOK_CODE,hook)
    cpu.emu_start(BASE+MAIN,BASE+stop.address,timeout=5500000,count=MAX_WALK_INS)
    pc=cpu.reg_read(UC_X86_REG_RIP)
    if (pc!=BASE+stop.address or observed!=["GetModuleFileNameA","strcpy"] or
        BASE+START not in trace):
        raise RuntimeError("Original x64 did not reach post-strcpy control from main")
    count=sum(BASE+START<=pc<BASE+stop.address for pc in trace)
    if execute_direct_jump:
        if (stop.mnemonic!="jmp" or stop.op_str!="0x15b7cf" or
            cpu.reg_read(UC_X86_REG_RIP)!=BASE+stop.address):
            raise RuntimeError("Original next jump identity changed")
        cpu.emu_start(BASE+stop.address,0,timeout=500000,count=1)
        if cpu.reg_read(UC_X86_REG_RIP)!=BASE+0x15b7cf:
            raise RuntimeError("Original x64 direct JMP did not land correctly")
    flags=cpu.reg_read(UC_X86_REG_EFLAGS)
    regmap={
      "rax":UC_X86_REG_RAX,"rbx":UC_X86_REG_RBX,
      "rcx":UC_X86_REG_RCX,"rdx":UC_X86_REG_RDX,
      "r8":UC_X86_REG_R8,"r9":UC_X86_REG_R9,
      "rdi":UC_X86_REG_RDI,"rsi":UC_X86_REG_RSI,
      "r10":UC_X86_REG_R10,"r11":UC_X86_REG_R11,
      "rsp":UC_X86_REG_RSP,"rip":UC_X86_REG_RIP
    }
    stack0=struct.unpack("<Q",bytes(cpu.mem_read(HELPER_LOCAL_RSP+0x20,8)))[0]
    stack1=struct.unpack("<Q",bytes(cpu.mem_read(HELPER_LOCAL_RSP+0x28,8)))[0]
    numeric={name:cpu.reg_read(reg) for name,reg in regmap.items()}
    return {
      "stack_qword_0":stack0,"stack_qword_1":stack1,
      "numeric_registers":numeric,
      "case":k,"x64_insns_executed":len(trace),
      "post_strcpy_insns_executed":count,
      "registers":{name:hex(cpu.reg_read(reg)) for name,reg in regmap.items()},
      "flags":{"cf":int(bool(flags&1)),"zf":int(bool(flags&0x40)),
               "sf":int(bool(flags&0x80)),"of":int(bool(flags&0x800))},
      "return_slot_va":hex(struct.unpack("<Q",bytes(
          cpu.mem_read(STACK_MAIN_RSP-8,8)))[0]),
      "buffer_written":bytes(cpu.mem_read(original_dest,PATH_LEN+1))==PATH+b"\x00",
      "strcpy_model_return_count":len(observed)
    }

def run(path,out):
    pe=PE(path)
    if hashlib.sha256(pe.b).hexdigest()!=EXE_SHA:
        raise RuntimeError("Original executable file digest mismatch")
    first_slot=verify_next_import(pe)
    strcpy_slot,dst=original_thunk(pe)
    data,stop=discover(pe)
    data["authentic_x64_samples"]=[reference(pe,first_slot,strcpy_slot,dst,stop,k)
                                   for k in (0,5,9)]
    if not all(x["post_strcpy_insns_executed"]==data["precontrol_instruction_count"] and
               x["buffer_written"] for x in data["authentic_x64_samples"]):
        raise RuntimeError("Original post-strcpy execution coverage mismatch")
    data["native_arm64_post_strcpy_executed"]=False
    data["game_engine_running"]=False
    data["import_fixtures"]=["KERNEL32.dll!GetModuleFileNameA",
                             "MSVCR90.dll!strcpy"]
    out.mkdir(parents=True,exist_ok=True)
    (out/"post-strcpy-frontier.json").write_text(json.dumps(data,indent=2)+"\n")
    lines=[
       "# MX Bikes next original game helper frontier after strcpy","",
       "- Original helper resume RVA: **"+data["start_rva"]+"**",
       "- Next x64 transfer: **"+data["first_control_rva"]+" "+
         data["first_control_mnemonic"]+" "+
         data["first_control_operands"]+"**",
       "- New x64 instructions before transfer: **"+
         str(data["precontrol_instruction_count"])+"**",
       "- Verified from original main using two bounded DLL models: **3/3**",
       "",
       "## Original instruction forms"
    ]
    lines.extend("- "+i["rva"]+": "+i["mnemonic"]+" "+i["operands"]
                 for i in data["precontrol_insns"])
    lines.extend(["","**Only original x64 recon here. No native successor claimed.**",""])
    md="\n".join(lines)
    (out/"post-strcpy-frontier.md").write_text(md)
    print(md)
    return data

if __name__=="__main__":
    if len(sys.argv)!=3:raise SystemExit("Usage: original-file report-dir")
    run(Path(sys.argv[1]),Path(sys.argv[2]))
