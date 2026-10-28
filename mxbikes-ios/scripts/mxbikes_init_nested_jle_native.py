#!/usr/bin/env python3
"""Join authentic first nested initializer CALL and eight-instruction JLE block.

Reference original x64 CALL 0x133EF6 -> 0x133640, then MOV R11, PUSH RBX,
SUB RSP, PE-cookie load/XOR/store, MOV EBX, and CMP/JLE. Differentially run
host C and executable AArch64 in the same cumulative guest-memory context.
Only the first branch is translated: both successors remain fail-closed.
"""
import json,sys
from pathlib import Path
from capstone import Cs,CS_ARCH_X86,CS_MODE_64
from capstone.x86 import X86_OP_IMM
from unicorn.x86_const import (
    UC_X86_REG_RIP,UC_X86_REG_RSP,UC_X86_REG_RAX,UC_X86_REG_RBX,
    UC_X86_REG_RSI,UC_X86_REG_R11,UC_X86_REG_RCX,UC_X86_REG_RDX,
    UC_X86_REG_EFLAGS,
)
import mxbikes_main_boot_init_callee_native as parent
import mxbikes_init_nested_wave as discovery
import mxbikes_main_boot_next_call_native as prior
import mxbikes_main_joined_callee_native as joined

BASE=joined.BASE
CALL=discovery.NESTED
CHILD=0x133640
BRANCH=0x133668
CMP_GLOBAL=0x565e54
COOKIE=parent.COOKIE_RVA
FIRST_INSTRUCTIONS=[
    ("mov","r11, rsp"),("push","rbx"),("sub","rsp, 0x160"),
    ("mov","rax, qword ptr [rip + 0x25f24e]"),
    ("xor","rax, rsp"),
    ("mov","qword ptr [rsp + 0x130], rax"),
    ("mov","ebx, 1"),
    ("cmp","dword ptr [rip + 0x4327ec], ebx")
]

def original_branch(pe):
    root=discovery.decode_call(pe,CALL,following=discovery.POST_NESTED)
    if root["callee_rva"]!=hex(CHILD):
        raise ValueError("Authentic original nested CALL target drifted")
    scanner=Cs(CS_ARCH_X86,CS_MODE_64)
    scanner.detail=True
    decoded=list(scanner.disasm(pe.read_rva(CHILD,BRANCH-CHILD+6),CHILD))
    if (len(decoded)!=9 or
        decoded[-1].address!=BRANCH or
        [(a.mnemonic,a.op_str) for a in decoded[:-1]]!=FIRST_INSTRUCTIONS or
        decoded[-1].mnemonic!="jle" or
        len(decoded[-1].operands)!=1 or
        decoded[-1].operands[0].type!=X86_OP_IMM):
        raise ValueError("Original guest nested initializer JLE shape changed")
    target=decoded[-1].operands[0].imm
    fall=decoded[-1].address+decoded[-1].size
    if not(0x1000<=target<0x800000 and target!=fall):
        raise ValueError("Original native conditional target malformed")
    if (CHILD+0x12+0x25f24e)!=COOKIE:
        raise ValueError("Original cookie qword reference changed")
    if (BRANCH+0x4327ec)!=CMP_GLOBAL:
        raise ValueError("Original comparison is not the initialized global")
    return target,fall

def original_x64_to_branch(pe,parser_dword,saved_rbx,saved_rsi,
                           target,fall):
    uc=joined.new_cpu(pe)
    orig_rsp=joined.ENTRY_SP-0x288
    uc.mem_write(BASE+prior.GLOBAL_RVA,int(parser_dword).to_bytes(4,"little"))
    for reg,value in (
       (UC_X86_REG_RIP,BASE+prior.CALLSITE),(UC_X86_REG_RSP,orig_rsp),
       (UC_X86_REG_RAX,1),(UC_X86_REG_RSI,saved_rsi),
       (UC_X86_REG_RBX,saved_rbx),(UC_X86_REG_RCX,parser_dword),
       (UC_X86_REG_RDX,BASE+prior.CONSTANT_RVA)):
        uc.reg_write(reg,value)
    uc.emu_start(BASE+prior.CALLSITE,BASE+CALL,
                 timeout=3000000,count=35)
    if uc.reg_read(UC_X86_REG_RIP)!=BASE+CALL:
        raise ValueError("Original outer native callee first CALL not reached")
    uc.emu_start(BASE+CALL,0,timeout=3000000,count=10)
    flags=uc.reg_read(UC_X86_REG_EFLAGS)
    rsp=uc.reg_read(UC_X86_REG_RSP)
    result={
      "rsp":rsp,"rip":uc.reg_read(UC_X86_REG_RIP),
      "rax":uc.reg_read(UC_X86_REG_RAX),
      "rbx":uc.reg_read(UC_X86_REG_RBX),
      "r11":uc.reg_read(UC_X86_REG_R11),
      "zf":int(bool(flags&0x40)),
      "sf":int(bool(flags&0x80)),
      "cf":int(bool(flags&1)),
      "call_slot":int.from_bytes(uc.mem_read(orig_rsp-0x2a0-8,8),"little"),
      "saved_rbx":int.from_bytes(uc.mem_read(orig_rsp-0x2a0-16,8),"little"),
      "cookie":int.from_bytes(uc.mem_read(rsp+0x130,8),"little"),
      "comparison":int.from_bytes(uc.mem_read(BASE+CMP_GLOBAL,4),"little")
    }
    if (result["rip"] not in (BASE+target,BASE+fall) or
        rsp!=orig_rsp-0x2a0-0x170 or
        result["call_slot"]!=BASE+discovery.POST_NESTED or
        result["saved_rbx"]!=saved_rbx or
        result["comparison"]!=parser_dword or
        result["rbx"]!=1):
        raise ValueError("Original x64 nested child state or guest memory drifted")
    return result

def extend(pe,source,cases):
    taken,fall=original_branch(pe)
    if len(cases)!=16:raise ValueError("Original 16 parser cases required")
    refs=[]
    for _,row,_,kind in cases:
        is_parent=kind=="returned" and row["rip"]==BASE+joined.AFTER_CALL
        refs.append(original_x64_to_branch(pe,row["callee_global1"],
                     row["rbx"],row["rsi"],taken,fall) if is_parent else None)
    if sum(x is not None for x in refs)!=prior.COUNT:
        raise ValueError("Original outer initializer returned-case coverage lost")
    def replace_once(old,new):
        nonlocal source
        if source.count(old)!=1:
            raise ValueError("Nested original guest link source identity changed: "+old[:65])
        source=source.replace(old,new)
    anchor="static int main_to_callee(mx_crt_cluster_state*s,mx_cfg_memory*m,"
    helper=f"""
static int native_original_nested_jle(mx_crt_cluster_state*s,mx_cfg_memory*m){{
 if(!s||!m||s->fault||s->rip!=UINT64_C({BASE+CALL})||
    (s->rsp&15U)!=0U||s->rsp<0x170U)
    return 240;
 const uint64_t caller_rsp=s->rsp;
 const uint64_t call_rsp=caller_rsp-8U;
 const uint64_t saved_rsp=caller_rsp-16U;
 const uint64_t frame_rsp=caller_rsp-0x170U;
 uint64_t old=0U,cookie=0U;
 uint32_t compared=0U;
 if(!mx_cfg_transfer(m,call_rsp,&old,8U,0)||
    !mx_cfg_transfer(m,saved_rsp,&old,8U,0)||
    !mx_cfg_transfer(m,frame_rsp+0x130U,&old,8U,0)||
    !mx_cfg_transfer(m,UINT64_C({BASE+COOKIE}),&cookie,8U,0)||
    !mx_cfg_transfer(m,UINT64_C({BASE+CMP_GLOBAL}),&compared,4U,0))
    return 241;
 uint64_t next=UINT64_C({BASE+discovery.POST_NESTED});
 uint64_t saved=s->rbx;
 uint64_t mixed=cookie^frame_rsp;
 if(!mx_cfg_transfer(m,call_rsp,&next,8U,1)||
    !mx_cfg_transfer(m,saved_rsp,&saved,8U,1)||
    !mx_cfg_transfer(m,frame_rsp+0x130U,&mixed,8U,1))
    return 242;
 s->r11=call_rsp;s->rsp=frame_rsp;s->rax=mixed;s->rbx=1U;
 const uint32_t difference=compared-1U;
 s->zf=(uint8_t)(difference==0U);
 s->sf=(uint8_t)(difference>>31U);
 s->cf=(uint8_t)(compared<1U);
 /* JLE is signed: ZF || (SF xor OF). 32-bit subtraction may overflow;
  * compare widened signed values rather than dropping guest OF. */
 const int jle=((int64_t)(int32_t)compared)<=1;
 s->rip=jle?UINT64_C({BASE+taken}):UINT64_C({BASE+fall});
 s->instructions+=10U; /* original CALL, eight instructions, JLE */
 return MX_NATIVE_LINK_FRONTIER_REACHED;
}}
"""
    replace_once(anchor,helper+anchor)
    keys=["rsp","rip","rax","rbx","r11","call_slot","saved_rbx",
          "cookie","comparison","zf","sf","cf"]
    rows=[]
    for ref in refs:
        if ref is None:rows.append(" {0}")
        else:rows.append(" {"+",".join("UINT64_C("+str(ref[k])+")" for k in keys)+"}")
    expected=("static const uint64_t original_nested_expected[CASES][12]={"+
             ",".join(rows)+"};\n")
    replace_once(anchor,expected+anchor)
    replace_once(" unsigned native_init_frontiers=0U;",
                 " unsigned native_init_frontiers=0U;\n unsigned native_nested_frontiers=0U;")
    point="      native_init_frontiers++;"
    snippet=f"""
      const unsigned before_nested=s.instructions;
      if(native_original_nested_jle(&s,&mem)!=MX_NATIVE_LINK_FRONTIER_REACHED)
         return 243;
      const uint64_t*ref=original_nested_expected[i];
      if(s.instructions!=before_nested+10U||s.rsp!=ref[0]||
         s.rip!=ref[1]||s.rax!=ref[2]||s.rbx!=ref[3]||
         s.r11!=ref[4]||s.zf!=ref[9]||s.sf!=ref[10]||
         s.cf!=ref[11])return 244;
      if(read_guest(&mem,original_init_expected[i][0]-8U,8U)!=ref[5]||
         read_guest(&mem,original_init_expected[i][0]-16U,8U)!=ref[6]||
         read_guest(&mem,s.rsp+0x130U,8U)!=ref[7]||
         read_guest(&mem,UINT64_C({BASE+CMP_GLOBAL}),4U)!=ref[8])
         return 245;
      native_nested_frontiers++;
"""
    replace_once(point,point+"\n"+snippet)
    replace_once(" if(native_init_frontiers!=12U)return 239;",
                 " if(native_init_frontiers!=12U)return 239;\n if(native_nested_frontiers!=12U)return 246;")
    return source

def run(executable,out,*,native_extension=None):
    from tools.pe_probe import PE
    pe=PE(executable)
    taken,fall=original_branch(pe)
    def combined_extension(pe,source,cases):
        source=extend(pe,source,cases)
        return native_extension(pe,source,cases) if native_extension is not None else source
    previous=parent.run(executable,out,native_extension=combined_extension)
    if previous["native_arm64_full_first_game_init_callee_cases"]!=12:
        raise ValueError("Original outer initialization was not executed")
    data={
       "original_sha256":previous["original_sha256"],
       "native_arm64_nested_first_branch_cases":12,
       "original_nested_call_rva":hex(CALL),
       "original_nested_callee_rva":hex(CHILD),
       "first_original_control_rva":hex(BRANCH),
       "first_control_taken_rva":hex(taken),
       "first_control_fallthrough_rva":hex(fall),
       "first_child_complete_original_function_verified":False,
       "engine_or_ios_boot":False}
    (out/"joined-native-boot-nested-jle.json").write_text(json.dumps(data,indent=2)+"\n")
    lines=["# MX Bikes: nested original Win64 CALL -> child CMP/JLE on ARM64","",
       "- Original x64/native host/executed AArch64 nested cases: **12/12**",
       "- Original nested CALL target: **"+hex(CHILD)+"**",
       "- Original child CMP/JLE through first conditional successor: **verified**",
       "- Both branch destinations: **"+hex(taken)+" / "+hex(fall)+"**",
       "","Other child blocks remain untranslated. No native engine/frame/menu/IPA.",""]
    (out/"joined-native-boot-nested-jle.md").write_text("\n".join(lines))
    print("\n".join(lines))
    return data

if __name__=="__main__":
    if len(sys.argv)!=3:raise SystemExit("usage: nested_jle.py owned.exe metadata-out")
    run(Path(sys.argv[1]),Path(sys.argv[2]))
