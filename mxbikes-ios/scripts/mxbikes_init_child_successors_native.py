#!/usr/bin/env python3
"""Extend executed AArch64 initializer through BOTH original JLE successors.

Original x64/host C/AArch64 differential covers the JLE-taken 3-op cookie
epilogue prefix and the JLE-fallthrough 13-op register-save/log setup prefix.
Every memory write is guest-preflighted; no CALL beyond either successor
control executes. Synthetic parser-global inputs are independently replayed
on original x64 for signed-branch coverage, in addition to 12 real
command-line parser cases on the cumulative native startup path.
"""
import json,sys
from pathlib import Path
from unicorn.x86_const import (
    UC_X86_REG_RIP,UC_X86_REG_RSP,UC_X86_REG_RAX,UC_X86_REG_RBX,
    UC_X86_REG_RCX,UC_X86_REG_RDX,UC_X86_REG_RSI,UC_X86_REG_RDI,
    UC_X86_REG_R11,UC_X86_REG_RBP,UC_X86_REG_R12,UC_X86_REG_R13,
    UC_X86_REG_R14,UC_X86_REG_R15,UC_X86_REG_EFLAGS,
)
import mxbikes_init_nested_jle_native as parent
import mxbikes_init_nested_wave as wave
import mxbikes_main_boot_next_call_native as prior
import mxbikes_main_joined_callee_native as joined

BASE=joined.BASE
TAKEN=0x133c9a
FALL=0x13366e
TAKEN_CONTROL=0x133ca7
FALL_CONTROL=0x1336b2
SAVE_OFFSETS=(8,16,24,-16,-24,-32,-40)
TAKEN_FORMS=[
 ("xor","eax, eax"),("mov","rcx, qword ptr [rsp + 0x130]"),
 ("xor","rcx, rsp")]
FALL_FORMS=[
 ("mov","qword ptr [r11 + 8], rbp"),
 ("mov","qword ptr [r11 + 0x10], rsi"),
 ("mov","qword ptr [r11 + 0x18], rdi"),
 ("mov","qword ptr [r11 - 0x10], r12"),
 ("mov","qword ptr [r11 - 0x18], r13"),
 ("mov","qword ptr [r11 - 0x20], r14"),
 ("mov","qword ptr [r11 - 0x28], r15"),
 ("lea","r14, [rip + 0x4330ef]"),
 ("lea","r12, [rip + 0xd17788]"),
 ("lea","r15, [rip + 0x432be1]"),
 ("lea","r13, [rip + 0x432cea]"),
 ("movabs","rdi, 0x7478742e676f6c"),
 ("test","ebx, ebx"),
]
EXTRA_REGS=("rbp","r12","r13","r14","r15")
REGS={
 "rbp":UC_X86_REG_RBP,"r12":UC_X86_REG_R12,"r13":UC_X86_REG_R13,
 "r14":UC_X86_REG_R14,"r15":UC_X86_REG_R15
}
SYNTHETIC_CASES=(0,1,2,0x80000000)
SAVED_RBX=0x123456789ABCD
SAVED_RSI=0x172839405060
SAVED_RDI=0x56781234

def validate_original(pe):
    t,f=parent.original_branch(pe)
    if (t,f)!=(TAKEN,FALL):
        raise ValueError("Original signed JLE branch destinations changed")
    for entry,expected_forms,expected_control,kind in (
       (TAKEN,TAKEN_FORMS,TAKEN_CONTROL,"call"),
       (FALL,FALL_FORMS,FALL_CONTROL,"js")):
        block=wave.scan_first_block(pe,entry)
        actual=[(r["mnemonic"],r["operands"])
                for r in block.get("precontrol_instruction_forms",[])]
        if (actual!=expected_forms or
            block.get("control_rva")!=hex(expected_control) or
            block.get("control_kind")!=kind):
            raise ValueError("Original x64 successor prefix changed: "+hex(entry))
    # Capture LEA targets from authenticated RIP-relative original operands.
    return (
       FALL+0x23+0x4330ef,   # r14, end of instruction 0x133691
       FALL+0x2a+0xd17788,   # r12, end of instruction 0x133698
       FALL+0x31+0x432be1,   # r15, end of instruction 0x13369f
       FALL+0x38+0x432cea,   # r13, end of instruction 0x1336a6
    )

def original_reference(pe,dword,saved_rbx,saved_rsi,saved_rdi):
    uc=joined.new_cpu(pe)
    caller_rsp=joined.ENTRY_SP-0x288
    uc.mem_write(BASE+prior.GLOBAL_RVA,dword.to_bytes(4,"little"))
    seed=(
      (UC_X86_REG_RIP,BASE+prior.CALLSITE),(UC_X86_REG_RSP,caller_rsp),
      (UC_X86_REG_RAX,1),(UC_X86_REG_RBX,saved_rbx),
      (UC_X86_REG_RSI,saved_rsi),(UC_X86_REG_RDI,saved_rdi),
      (UC_X86_REG_RCX,dword),(UC_X86_REG_RDX,BASE+prior.CONSTANT_RVA))
    for reg,value in seed:uc.reg_write(reg,value)
    uc.emu_start(BASE+prior.CALLSITE,BASE+parent.CALL,
                 timeout=3000000,count=35)
    if uc.reg_read(UC_X86_REG_RIP)!=BASE+parent.CALL:
        raise ValueError("Original caller failed to reach nested CALL")
    uc.emu_start(BASE+parent.CALL,0,timeout=3000000,count=10)
    pc=uc.reg_read(UC_X86_REG_RIP)-BASE
    if pc not in (TAKEN,FALL):
        raise ValueError("Original child JLE successor unexpected")
    count=3 if pc==TAKEN else 13
    end=TAKEN_CONTROL if pc==TAKEN else FALL_CONTROL
    uc.emu_start(BASE+pc,0,timeout=3000000,count=count)
    if uc.reg_read(UC_X86_REG_RIP)!=BASE+end:
        raise ValueError("Original child successor failed bounded instruction budget")
    r11=uc.reg_read(UC_X86_REG_R11)
    flags=uc.reg_read(UC_X86_REG_EFLAGS)
    return {
       "rip":BASE+end,"rsp":uc.reg_read(UC_X86_REG_RSP),
       "rax":uc.reg_read(UC_X86_REG_RAX),
       "rbx":uc.reg_read(UC_X86_REG_RBX),
       "rcx":uc.reg_read(UC_X86_REG_RCX),
       "rdi":uc.reg_read(UC_X86_REG_RDI),
       "rsi":uc.reg_read(UC_X86_REG_RSI),
       "r11":r11,
       **{name:uc.reg_read(reg) for name,reg in REGS.items()},
       "zf":int(bool(flags&64)),"sf":int(bool(flags&128)),
       "cf":int(bool(flags&1)),
       "saved_stores":[int.from_bytes(uc.mem_read(r11+off,8),"little")
                       for off in SAVE_OFFSETS],
       "instructions":count,
       "comparison_dword":dword,
       "branch_rva":pc
    }

KEYS=["rip","rsp","rax","rbx","rcx","rdi","rsi","r11",
      *EXTRA_REGS,"zf","sf","cf", "comparison_dword",*("stack_"+str(x) for x in SAVE_OFFSETS)]
def c_reference(row):
    values=[row[k] for k in KEYS if not k.startswith("stack_")]
    values+=row["saved_stores"]
    if len(values)!=len(KEYS):
        raise ValueError("Original successor reference changed shape")
    return " {"+",".join("UINT64_C("+str(v)+")" for v in values)+"}"

def extend(pe,source,cases):
    leavals=validate_original(pe)
    if len(cases)!=16:raise ValueError("Original startup parser fixture count drifted")
    refs=[]
    for _,row,_,kind in cases:
        if kind=="returned" and row["rip"]==BASE+joined.AFTER_CALL:
            refs.append(original_reference(pe,row["callee_global1"],
                  row["rbx"],row["rsi"],row["rdi"]))
        else:refs.append(None)
    if sum(r is not None for r in refs)!=12:
        raise ValueError("Twelve authentic original startup paths required")
    synthetic=[original_reference(pe,dword,SAVED_RBX,SAVED_RSI,SAVED_RDI)
               for dword in SYNTHETIC_CASES]
    if {r["branch_rva"] for r in synthetic}!={TAKEN,FALL}:
        raise ValueError("Independent original x64 signed-branch coverage missing")
    def rep(a,b):
        nonlocal source
        if source.count(a)!=1:raise ValueError("Native source integration anchor changed: "+a[:80])
        source=source.replace(a,b)
    anchor="static int main_to_callee(mx_crt_cluster_state*s,mx_cfg_memory*m,"
    records=("static const uint64_t original_successor_expected[CASES]["+
             str(len(KEYS))+"]={"+",".join(c_reference(r) if r else " {0}" for r in refs)+"};\n")
    synthetic_records=("static const uint64_t original_successor_synthetic["+
                       str(len(SYNTHETIC_CASES))+"]["+str(len(KEYS))+"]={"+
                       ",".join(c_reference(x) for x in synthetic)+"};\n")
    # Shadow extra Win64 nonvolatile registers which the shared narrow CRT
    # register struct does not represent. These are explicitly zero-seeded
    # in original x64 differential runs, then updated by true original LEAs.
    helper=f"""
typedef struct {{
 uint64_t rbp,r12,r13,r14,r15;
}} mx_init_extra_regs;
static int native_original_child_successor(mx_crt_cluster_state*s,
    mx_cfg_memory*m,mx_init_extra_regs*extra){{
 if(!s||!m||!extra||s->fault||
    (s->rip!=UINT64_C({BASE+TAKEN})&&s->rip!=UINT64_C({BASE+FALL})))
    return 247;
 if(s->rip==UINT64_C({BASE+TAKEN})){{
    uint64_t encoded=0U;
    if(!mx_cfg_transfer(m,s->rsp+0x130U,&encoded,8U,0))return 248;
    s->rax=0U;s->rcx=encoded^s->rsp;
    /* The final XOR RCX,RSP overwrites XOR EAX,EAX flags. */
    s->zf=(uint8_t)(s->rcx==0U);
    s->sf=(uint8_t)((s->rcx>>63U)&1U);
    s->cf=0U;
    s->rip=UINT64_C({BASE+TAKEN_CONTROL});
    s->instructions+=3U;
    return MX_NATIVE_LINK_FRONTIER_REACHED;
 }}
 /* Seven Win64 callee-saved register spills; preflight all before writing. */
 const uint64_t origin=s->r11;
 const uint64_t addrs[7U]={{
   origin+8U,origin+16U,origin+24U,
   origin-16U,origin-24U,origin-32U,origin-40U
 }};
 uint64_t old=0U;
 for(unsigned j=0U;j<7U;j++)
    if(!mx_cfg_transfer(m,addrs[j],&old,8U,0))return 249;
 const uint64_t values[7U]={{
    extra->rbp,s->rsi,s->rdi,extra->r12,extra->r13,extra->r14,extra->r15
 }};
 for(unsigned j=0U;j<7U;j++)
    if(!mx_cfg_transfer(m,addrs[j],(void*)&values[j],8U,1))return 250;
 extra->r14=UINT64_C({BASE+leavals[0]});
 extra->r12=UINT64_C({BASE+leavals[1]});
 extra->r15=UINT64_C({BASE+leavals[2]});
 extra->r13=UINT64_C({BASE+leavals[3]});
 s->rdi=UINT64_C(0x7478742e676f6c);
 /* Original EBX=1 from child precontrol; TEST EBX,EBX => ZF/SF/CF=0. */
 s->zf=(uint8_t)(s->rbx==0U);
 s->sf=(uint8_t)((s->rbx>>63U)&1U);
 s->cf=0U;
 s->rip=UINT64_C({BASE+FALL_CONTROL});
 s->instructions+=13U;
 return MX_NATIVE_LINK_FRONTIER_REACHED;
}}
static int verify_original_successor(const mx_crt_cluster_state*s,
     mx_cfg_memory*m,const mx_init_extra_regs*extra,const uint64_t*oracle){{
 if(s->rip!=oracle[0])return 1;
 if(s->rsp!=oracle[1])return 2;
 if(s->rax!=oracle[2])return 3;
 if(s->rbx!=oracle[3])return 4;
 if(s->rcx!=oracle[4])return 5;
 if(s->rdi!=oracle[5])return 6;
 if(s->rsi!=oracle[6])return 7;
 if(s->r11!=oracle[7])return 8;
 if(extra->rbp!=oracle[8])return 9;
 if(extra->r12!=oracle[9])return 10;
 if(extra->r13!=oracle[10])return 11;
 if(extra->r14!=oracle[11])return 12;
 if(extra->r15!=oracle[12])return 13;
 if(s->zf!=oracle[13])return 14;
 if(s->sf!=oracle[14])return 15;
 if(s->cf!=oracle[15])return 16;
 const int64_t off[7U]={{8,16,24,-16,-24,-32,-40}};
 for(unsigned j=0U;j<7U;j++){{
    const uint64_t address=j<3U?s->r11+(uint64_t)off[j]:
                                      s->r11-(uint64_t)(-off[j]);
    if(read_guest(m,address,8U)!=oracle[17U+j])return (int)(18U+j);
 }}
 if(read_guest(m,UINT64_C({BASE+parent.CMP_GLOBAL}),4U)!=oracle[16])return 17;
 return 0;
}}
"""
    rep(anchor,helper+records+synthetic_records+anchor)
    rep(" unsigned native_nested_frontiers=0U;",
        " unsigned native_nested_frontiers=0U;\n unsigned native_successor_frontiers=0U;")
    target="      native_nested_frontiers++;"
    step=f"""
      mx_init_extra_regs extra={{0}};
      const unsigned before_successor=s.instructions;
      if(native_original_child_successor(&s,&mem,&extra)!=
         MX_NATIVE_LINK_FRONTIER_REACHED)return 251;
      const uint64_t*successor_ref=original_successor_expected[i];
      if(s.instructions!=before_successor+
         (successor_ref[0]==UINT64_C({BASE+TAKEN_CONTROL})?3U:13U))
         return 252;
      const int mismatch=verify_original_successor(&s,&mem,&extra,successor_ref);
      if(mismatch)return 100+mismatch;
      native_successor_frontiers++;
"""
    rep(target,target+"\n"+step)
    gate=" if(native_nested_frontiers!=12U)return 246;"
    synthetic_c=f"""
 if(native_successor_frontiers!=12U)return 253;
 /* Independent original x64 guest path variants to force BOTH signed
  * JLE outcomes even when the real parser inputs cluster on one side.
  * These execute actual original init CALL/CMP and the true successor. */
 for(unsigned v=0U;v<{len(SYNTHETIC_CASES)}U;v++){{
    for(unsigned k=0U;k<131072U;k++)stack_bytes[k]=0U;
    uint64_t cookie=fixtures[0].pre[0];
    uint32_t global_value=(uint32_t)original_successor_synthetic[v][16U];
    if(!mx_cfg_transfer(&mem,COOKIE,&cookie,8U,1)||
       !mx_cfg_transfer(&mem,UINT64_C({BASE+prior.GLOBAL_RVA}),
                        &global_value,4U,1))return 254;
    mx_crt_cluster_state trial={{0}};
    trial.rip=UINT64_C({BASE+prior.CALLSITE});
    trial.rsp=UINT64_C({joined.ENTRY_SP-0x288});
    trial.rax=1U;
    trial.rbx=UINT64_C({SAVED_RBX});
    trial.rsi=UINT64_C({SAVED_RSI});
    trial.rdi=UINT64_C({SAVED_RDI});
    trial.rcx=(uint64_t)global_value;
    trial.rdx=UINT64_C({BASE+prior.CONSTANT_RVA});
    if(native_original_init_callee(&trial,&mem)!=
       MX_NATIVE_LINK_FRONTIER_REACHED)return 255;
    if(native_original_nested_jle(&trial,&mem)!=
       MX_NATIVE_LINK_FRONTIER_REACHED)return 256;
    mx_init_extra_regs trial_extra={{0}};
    if(native_original_child_successor(&trial,&mem,&trial_extra)!=
       MX_NATIVE_LINK_FRONTIER_REACHED)return 257;
    const int synthetic_mismatch=verify_original_successor(
        &trial,&mem,&trial_extra,original_successor_synthetic[v]);
    if(synthetic_mismatch)return 140+synthetic_mismatch;
 }}
"""
    rep(gate,gate+"\n"+synthetic_c)
    return source

def run(executable,out,*,native_extension=None):
    from tools.pe_probe import PE
    pe=PE(executable)
    validate_original(pe)
    def combined_extension(pe,source,cases):
        source=extend(pe,source,cases)
        return native_extension(pe,source,cases) if native_extension is not None else source
    previous=parent.run(executable,out,native_extension=combined_extension)
    if previous["native_arm64_nested_first_branch_cases"]!=12:
        raise ValueError("Earlier native original nested branch did not execute")
    report={
      "original_sha256":previous["original_sha256"],
      "native_arm64_cumulative_genuine_parser_cases":12,
      "original_x64_host_and_arm64_child_successor_cases":16,
      "original_child_taken_control_rva":hex(TAKEN_CONTROL),
      "original_child_fallthrough_control_rva":hex(FALL_CONTROL),
      "original_nested_original_function_fully_returned":False,
      "engine_render_or_menu_running":False}
    (out/"joined-native-child-successors.json").write_text(json.dumps(report,indent=2)+"\n")
    lines=["# MX Bikes — two original initializer successors execute on AArch64","",
      "- Cumulative real original game parser/initializer cases: **12/12**",
      "- Additional original x64 signed-branch variant cases: **4/4**",
      "- Total original x64/native host/executed AArch64 successor cases: **16/16**",
      "- Original taken cookie-check CALL boundary: **"+hex(TAKEN_CONTROL)+"**",
      "- Original non-taken JS boundary: **"+hex(FALL_CONTROL)+"**",
      "","No original downstream checker, full engine, frame, or iOS IPA executed.",""]
    (out/"joined-native-child-successors.md").write_text("\n".join(lines))
    print("\n".join(lines))
    return report

if __name__=="__main__":
    if len(sys.argv)!=3:
        raise SystemExit("usage: child_successors_native.py owned-original.exe metadata-dir")
    run(Path(sys.argv[1]),Path(sys.argv[2]))
