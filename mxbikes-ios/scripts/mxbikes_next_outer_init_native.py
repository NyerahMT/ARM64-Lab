#!/usr/bin/env python3
"""Advance the genuine game initializer into CALL 0x130580 on native AArch64.

Differential original x64 / host C / executed ARM64 of the actual parent
CALL and first seven original 0x130580 callee instructions, stopping
BEFORE its nested CALL 0x1305a9 -> 0x2aaebc. Validate stack return slot,
preserved R12, security-cookie stack store, RCX/RDX RIP-relative addresses,
and last XOR flags. This is a game-body startup frontier, not an engine boot.
"""
import json,sys
from pathlib import Path
from capstone import Cs,CS_ARCH_X86,CS_MODE_64,CS_GRP_CALL
from capstone.x86 import X86_OP_IMM
from unicorn.x86_const import (
 UC_X86_REG_RIP,UC_X86_REG_RSP,UC_X86_REG_RAX,UC_X86_REG_RBX,
 UC_X86_REG_RCX,UC_X86_REG_RDX,UC_X86_REG_RSI,UC_X86_REG_RDI,
 UC_X86_REG_R12,UC_X86_REG_EFLAGS
)
import mxbikes_init_child_return_native as previous
import mxbikes_next_outer_init_wave as mapped
import mxbikes_init_child_successors_native as successor
import mxbikes_main_joined_callee_native as joined
import mxbikes_main_boot_next_call_native as initial

BASE=joined.BASE
CALL=mapped.CALL
ENTRY=mapped.CHILD
BOUNDARY=0x1305a9
NESTED=0x2aaebc
AFTER_CALL=0x133f08
COOKIE=0x3928a0
FORMS=[
 ("push","r12"),("sub","rsp, 0x430"),
 ("mov","rax, qword ptr [rip + 0x262310]"),
 ("xor","rax, rsp"),("mov","qword ptr [rsp + 0x410], rax"),
 ("lea","rdx, [rip + 0x211d4e]"),
 ("lea","rcx, [rip + 0x212897]"),
]
REF_KEYS=("rip","rsp","rax","rbx","rcx","rdx","rsi","rdi",
          "saved_r12","return_slot","stack_cookie","zf","sf","cf")
SYNTHETIC=(0,1,2,0x80000000)

def verify_original(pe):
    previous.verify(pe)
    control=mapped.scan.decode_call(pe,CALL,following=AFTER_CALL)
    nested=mapped.scan.decode_call(pe,BOUNDARY)
    if control["callee_rva"]!=hex(ENTRY) or nested["callee_rva"]!=hex(NESTED):
        raise ValueError("Original parent initializer CALL or nested CALL changed")
    md=Cs(CS_ARCH_X86,CS_MODE_64);md.detail=True
    code=pe.read_rva(ENTRY,BOUNDARY+5-ENTRY)
    inst=list(md.disasm(code,ENTRY))
    if (len(inst)!=len(FORMS)+1 or
        [(i.mnemonic,i.op_str) for i in inst[:-1]]!=FORMS or
        inst[-1].address!=BOUNDARY or
        not inst[-1].group(CS_GRP_CALL) or
        sum(i.size for i in inst)!=len(code)):
        raise ValueError("Original seven-instruction next callee changed")
    if ENTRY+0x10+0x262310!=COOKIE:
        raise ValueError("Original RIP-relative cookie address moved")
    # LEA loads the address AFTER the original x64 instruction.
    rdx=0x1305a2+0x211d4e
    rcx=0x1305a9+0x212897
    if (rdx,rcx)!=(0x3422f0,0x342e40):
        raise ValueError("Guest original data address proof changed")
    return rdx,rcx

def original_reference(pe,dword,rbx,rsi,rdi):
    if 1<dword<0x80000000:return None
    uc=joined.new_cpu(pe)
    caller=joined.ENTRY_SP-0x288
    uc.mem_write(BASE+initial.GLOBAL_RVA,dword.to_bytes(4,"little"))
    for reg,val in (
       (UC_X86_REG_RIP,BASE+initial.CALLSITE),
       (UC_X86_REG_RSP,caller),(UC_X86_REG_RAX,1),
       (UC_X86_REG_RBX,rbx),(UC_X86_REG_RSI,rsi),
       (UC_X86_REG_RDI,rdi),(UC_X86_REG_RCX,dword),
       (UC_X86_REG_RDX,BASE+initial.CONSTANT_RVA)):
        uc.reg_write(reg,val)
    uc.emu_start(BASE+initial.CALLSITE,BASE+successor.parent.CALL,
                 timeout=3000000,count=35)
    if uc.reg_read(UC_X86_REG_RIP)!=BASE+successor.parent.CALL:
        raise ValueError("Original parent prefix failed")
    uc.emu_start(BASE+successor.parent.CALL,0,
                 timeout=3000000,count=10)
    if uc.reg_read(UC_X86_REG_RIP)!=BASE+successor.TAKEN:
        raise ValueError("Original early branch unexpectedly not taken")
    uc.emu_start(BASE+successor.TAKEN,0,
                 timeout=3000000,count=3)
    uc.emu_start(BASE+previous.x64.CHECK_CALL,0,
                 timeout=3000000,count=12)
    if uc.reg_read(UC_X86_REG_RIP)!=BASE+CALL:
        raise ValueError("Original checked child RET did not reach next CALL")
    before_rsp=uc.reg_read(UC_X86_REG_RSP)
    seed_r12=uc.reg_read(UC_X86_REG_R12)
    # Authentic Win64 CALL + exactly seven original body instructions.
    uc.emu_start(BASE+CALL,0,timeout=3000000,count=8)
    if uc.reg_read(UC_X86_REG_RIP)!=BASE+BOUNDARY:
        raise ValueError("Original first 0x130580 callee block did not reach boundary")
    flags=uc.reg_read(UC_X86_REG_EFLAGS)
    frame_rsp=uc.reg_read(UC_X86_REG_RSP)
    if frame_rsp!=before_rsp-0x440:
        raise ValueError("Original next CALL stack size changed")
    row={
        "rip":uc.reg_read(UC_X86_REG_RIP),
        "rsp":frame_rsp,
        "rax":uc.reg_read(UC_X86_REG_RAX),
        "rbx":uc.reg_read(UC_X86_REG_RBX),
        "rcx":uc.reg_read(UC_X86_REG_RCX),
        "rdx":uc.reg_read(UC_X86_REG_RDX),
        "rsi":uc.reg_read(UC_X86_REG_RSI),
        "rdi":uc.reg_read(UC_X86_REG_RDI),
        "saved_r12":int.from_bytes(uc.mem_read(before_rsp-16,8),"little"),
        "return_slot":int.from_bytes(uc.mem_read(before_rsp-8,8),"little"),
        "stack_cookie":int.from_bytes(uc.mem_read(frame_rsp+0x410,8),"little"),
        "zf":int(bool(flags&64)),"sf":int(bool(flags&128)),
        "cf":int(bool(flags&1)),
    }
    if (row["saved_r12"]!=seed_r12 or
        row["return_slot"]!=BASE+AFTER_CALL):
        raise ValueError("Original next native CALL return slot or preserved R12 changed")
    return row

def crow(row):
    return " {"+",".join("UINT64_C("+str(row[k])+")" for k in REF_KEYS)+"}"

def extend(pe,source,cases):
    rdx_rva,rcx_rva=verify_original(pe)
    if len(cases)!=16:raise ValueError("Cumulative original parser case count changed")
    refs=[]
    for _,row,_,kind in cases:
        if kind=="returned" and row["rip"]==BASE+joined.AFTER_CALL:
            refs.append(original_reference(pe,row["callee_global1"],
                        row["rbx"],row["rsi"],row["rdi"]))
        else:refs.append(None)
    if sum(x is not None for x in refs)<1:
        raise ValueError("No original startup cases can reach next inner function")
    variants=[original_reference(pe,v,successor.SAVED_RBX,
                   successor.SAVED_RSI,successor.SAVED_RDI)
              for v in SYNTHETIC]
    if sum(x is not None for x in variants)!=3:
        raise ValueError("Missing original x64 security-checked synthetic entry coverage")
    def rep(a,b):
        nonlocal source
        if source.count(a)!=1:
            raise ValueError("Native initializer source anchor moved: "+a[:80])
        source=source.replace(a,b)
    anchor="static int main_to_callee(mx_crt_cluster_state*s,mx_cfg_memory*m,"
    helper=f"""
/* Original CALL 0x133F03 into 0x130580, seven authenticated body
 * instructions. Stops BEFORE unknown nested CALL 0x1305A9. */
static int native_original_next_initializer(mx_crt_cluster_state*s,
      mx_cfg_memory*m,const mx_init_extra_regs*extra){{
 if(!s||!m||!extra||s->fault||s->rip!=UINT64_C({BASE+CALL})||
    (s->rsp&15U)!=0U||s->rsp<0x450U)return 160;
 const uint64_t caller_rsp=s->rsp;
 const uint64_t ret_rsp=caller_rsp-8U;
 const uint64_t push_rsp=caller_rsp-16U;
 const uint64_t frame=caller_rsp-0x440U;
 uint64_t old=0U,cookie=0U;
 if(!mx_cfg_transfer(m,ret_rsp,&old,8U,0)||
    !mx_cfg_transfer(m,push_rsp,&old,8U,0)||
    !mx_cfg_transfer(m,frame+0x410U,&old,8U,0)||
    !mx_cfg_transfer(m,UINT64_C({BASE+COOKIE}),&cookie,8U,0))
    return 161;
 uint64_t retval=UINT64_C({BASE+AFTER_CALL});
 uint64_t saved_r12=extra->r12;
 uint64_t local_cookie=cookie^frame;
 if(!mx_cfg_transfer(m,ret_rsp,&retval,8U,1)||
    !mx_cfg_transfer(m,push_rsp,&saved_r12,8U,1)||
    !mx_cfg_transfer(m,frame+0x410U,&local_cookie,8U,1))
    return 162;
 s->rsp=frame;s->rax=local_cookie;
 s->rdx=UINT64_C({BASE+rdx_rva});
 s->rcx=UINT64_C({BASE+rcx_rva});
 s->zf=(uint8_t)(local_cookie==0U);
 s->sf=(uint8_t)((local_cookie>>63U)&1U);
 s->cf=0U;
 s->rip=UINT64_C({BASE+BOUNDARY});
 s->instructions+=8U;
 return MX_NATIVE_LINK_FRONTIER_REACHED;
}}
static int verify_original_next_initializer(const mx_crt_cluster_state*s,
      mx_cfg_memory*m,const uint64_t*ref){{
 if(s->rip!=ref[0])return 1;
 if(s->rsp!=ref[1])return 2;
 if(s->rax!=ref[2])return 3;
 if(s->rbx!=ref[3])return 4;
 if(s->rcx!=ref[4])return 5;
 if(s->rdx!=ref[5])return 6;
 if(s->rsi!=ref[6])return 7;
 if(s->rdi!=ref[7])return 8;
 if(read_guest(m,s->rsp+0x430U,8U)!=ref[8])return 9;
 if(read_guest(m,s->rsp+0x438U,8U)!=ref[9])return 10;
 if(read_guest(m,s->rsp+0x410U,8U)!=ref[10])return 11;
 if(s->zf!=ref[11])return 12;
 if(s->sf!=ref[12])return 13;
 if(s->cf!=ref[13])return 14;
 return 0;
}}
"""
    rep(anchor,helper+anchor)
    rep(anchor,"static const uint64_t original_next_init_expected[CASES][14]={"+
          ",".join(crow(r) if r else " {0}" for r in refs)+"};\n"+
          "static const uint64_t original_next_init_synthetic[4][14]={"+
          ",".join(crow(r) if r else " {0}" for r in variants)+"};\n"+anchor)
    rep(" unsigned original_child_returns=0U;",
        " unsigned original_child_returns=0U;\n unsigned next_initializer_frontiers=0U;")
    mark="         original_child_returns++;"
    chunk=f"""
         const unsigned before_next=s.instructions;
         if(native_original_next_initializer(&s,&mem,&extra)!=
             MX_NATIVE_LINK_FRONTIER_REACHED)return 163;
         if(s.instructions!=before_next+8U)return 164;
         const int actual=verify_original_next_initializer(
             &s,&mem,original_next_init_expected[i]);
         if(actual)return 165+actual;
         next_initializer_frontiers++;
"""
    rep(mark,mark+"\n"+chunk)
    synthetic="       if(mismatch)return 205+mismatch;"
    syn_chunk=f"""
       if(original_next_init_synthetic[v][0]!=0U){{
          const unsigned before=trial.instructions;
          if(native_original_next_initializer(&trial,&mem,&trial_extra)!=
              MX_NATIVE_LINK_FRONTIER_REACHED)return 190;
          if(trial.instructions!=before+8U)return 191;
          const int actual=verify_original_next_initializer(
             &trial,&mem,original_next_init_synthetic[v]);
          if(actual)return 192+actual;
       }}
"""
    rep(synthetic,synthetic+"\n"+syn_chunk)
    gate=" if(original_child_returns!="+str(sum(r is not None for r in refs))+"U)return 211;"
    rep(gate,gate+"\n if(next_initializer_frontiers!="+
        str(sum(r is not None for r in refs))+"U)return 220;")
    return source

def run(executable,out,*,native_extension=None):
    from tools.pe_probe import PE
    pe=PE(executable)
    verify_original(pe)
    def combined_extension(pe,source,cases):
        source=extend(pe,source,cases)
        return native_extension(pe,source,cases) if native_extension is not None else source
    prior=previous.run(executable,out,native_extension=combined_extension)
    if prior["native_aarch64_cookie_return_oracle_variants"]!=3:
        raise ValueError("Original native cookie return regression")
    result={
       "original_sha256":prior["original_sha256"],
       "original_next_parent_call_rva":hex(CALL),
       "original_next_callee_rva":hex(ENTRY),
       "authentic_next_callee_precontrol_instructions":7,
       "next_original_untranslated_CALL_rva":hex(BOUNDARY),
       "next_original_untranslated_target_rva":hex(NESTED),
       "aarch64_next_callee_first_block_executed":True,
       "game_engine_loading_screen_running":False
    }
    (out/"joined-native-next-init-callee.json").write_text(json.dumps(result,indent=2)+"\n")
    lines=["# MX Bikes — original next initializer CALL and 7 instructions on ARM64","",
       "- Original Win64 CALL 0x133F03 -> 0x130580: **native executed**",
       "- Original callee push R12 and frame, security cookie, LEA arguments: **native executed**",
       "- Original x64/host C/AArch64 compared return slots, register state and stack cookie",
       "- Next untranslated nested CALL: **"+hex(BOUNDARY)+" -> "+hex(NESTED)+"**",
       "",
       "This does not launch original game engine, renderer, first frame or IPA.",""]
    (out/"joined-native-next-init-callee.md").write_text("\n".join(lines))
    print("\n".join(lines))
    return result

if __name__=="__main__":
    if len(sys.argv)!=3:
        raise SystemExit("usage: next_init_callee_native.py private.exe metadata-out")
    run(Path(sys.argv[1]),Path(sys.argv[2]))
