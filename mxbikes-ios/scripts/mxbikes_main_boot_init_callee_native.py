#!/usr/bin/env python3
"""Batch native execution of the first genuine game-main initialization callee.

Execute the original direct CALL at 0x13677f and 20 original instructions of
callee 0x133e80 through its first nested CALL boundary at 0x133ef6.
Every original source instruction is checked from the pinned private PE.
Original x64, native C host and executed AArch64 compare register, guest stack,
and the twelve image-global side effects. No unresolved inner CALL executes.
"""
from pathlib import Path
import json,sys
from capstone import Cs,CS_ARCH_X86,CS_MODE_64,CS_GRP_CALL
from unicorn.x86_const import (
    UC_X86_REG_RIP, UC_X86_REG_RSP, UC_X86_REG_RAX, UC_X86_REG_RSI,
    UC_X86_REG_RCX, UC_X86_REG_RDX, UC_X86_REG_EFLAGS,
)
import mxbikes_main_boot_next_call_native as prior
import mxbikes_main_joined_callee_native as joined

BASE=joined.BASE
ENTRY=0x133e80
FIRST_NESTED=0x133ef6
SOURCE_DWORD=prior.GLOBAL_RVA
COOKIE_RVA=0x3928a0
CONSTANT_RVA=0xe4ae20
# Original static RVA destinations, widths, and semantic source register.
STORES=[
    (0x565e54,4,"global"),
    (0x565e64,4,"zero"),
    (0x566280,1,"zero"),
    (0x565cd4,4,"zero"),
    (0x565ce8,4,"zero"),
    (0x566278,8,"pointer"),
    (0x566780,1,"zero"),
    (0x565ed8,8,"zero"),
    (0xe4addc,4,"zero"),
    (0xe4adf4,4,"zero"),
    (0x56638c,4,"zero"),
    (0x565ed4,4,"zero"),
]
ORIGINAL=[
    ("push","rsi"),
    ("sub","rsp, 0x290"),
    ("mov","rax, qword ptr [rip + 0x25ea10]"),
    ("xor","rax, rsp"),
    ("mov","qword ptr [rsp + 0x280], rax"),
    ("mov","eax, dword ptr [rip + 0xd16f4f]"),
    ("xor","esi, esi"),
    ("mov","dword ptr [rip + 0x431fab], eax"),
    ("lea","rax, [rip + 0xd16f70]"),
    ("mov","dword ptr [rip + 0x431fae], esi"),
    ("mov","byte ptr [rip + 0x4323c3], sil"),
    ("mov","dword ptr [rip + 0x431e11], esi"),
    ("mov","dword ptr [rip + 0x431e1f], esi"),
    ("mov","qword ptr [rip + 0x4323a8], rax"),
    ("mov","byte ptr [rip + 0x4328a9], sil"),
    ("mov","qword ptr [rip + 0x431ffa], rsi"),
    ("mov","dword ptr [rip + 0xd16ef8], esi"),
    ("mov","dword ptr [rip + 0xd16f0a], esi"),
    ("mov","dword ptr [rip + 0x43249c], esi"),
    ("mov","dword ptr [rip + 0x431fde], esi"),
]

def verify_original(pe):
    decoder=Cs(CS_ARCH_X86,CS_MODE_64)
    decoder.detail=True
    raw=pe.read_rva(ENTRY,FIRST_NESTED+5-ENTRY)
    inst=list(decoder.disasm(raw,ENTRY))
    if (len(inst)!=len(ORIGINAL)+1 or
        sum(op.size for op in inst)!=len(raw) or
        [(op.mnemonic,op.op_str) for op in inst[:-1]]!=ORIGINAL or
        inst[-1].address!=FIRST_NESTED or
        not inst[-1].group(CS_GRP_CALL)):
        raise ValueError("Original 20-instruction initial game callee changed")
    if SOURCE_DWORD!=0xe4adf0 or COOKIE_RVA!=0x3928a0:
        raise ValueError("Original guest layout drifted")
    return inst[-1].op_str

def original_callee_reference(pe, parser_dword, saved_rsi):
    uc=joined.new_cpu(pe)
    original_rsp=joined.ENTRY_SP-0x288
    uc.mem_write(BASE+SOURCE_DWORD,parser_dword.to_bytes(4,"little"))
    uc.reg_write(UC_X86_REG_RIP,BASE+prior.CALLSITE)
    uc.reg_write(UC_X86_REG_RSP,original_rsp)
    uc.reg_write(UC_X86_REG_RAX,1)
    uc.reg_write(UC_X86_REG_RSI,saved_rsi)
    uc.reg_write(UC_X86_REG_RCX,parser_dword)
    uc.reg_write(UC_X86_REG_RDX,BASE+prior.CONSTANT_RVA)
    uc.emu_start(BASE+prior.CALLSITE,BASE+FIRST_NESTED,
                 timeout=3000000,count=35)
    if uc.reg_read(UC_X86_REG_RIP)!=BASE+FIRST_NESTED:
        raise ValueError("Original Win64 CALL/callee failed to reach nested boundary")
    flags=uc.reg_read(UC_X86_REG_EFLAGS)
    stack_rsp=uc.reg_read(UC_X86_REG_RSP)
    expected_rsp=original_rsp-8-8-0x290
    output={
      "rsp":stack_rsp,"rax":uc.reg_read(UC_X86_REG_RAX),
      "rsi":uc.reg_read(UC_X86_REG_RSI),
      "rcx":uc.reg_read(UC_X86_REG_RCX),
      "rdx":uc.reg_read(UC_X86_REG_RDX),
      "cf":int(bool(flags&1)),"zf":int(bool(flags&64)),
      "sf":int(bool(flags&128)),
      "call_slot":int.from_bytes(uc.mem_read(original_rsp-8,8),"little"),
      "saved_rsi":int.from_bytes(uc.mem_read(original_rsp-16,8),"little"),
      "stack_cookie":int.from_bytes(uc.mem_read(stack_rsp+0x280,8),"little"),
      "stores":[int.from_bytes(uc.mem_read(BASE+rva,width),"little")
                for rva,width,_ in STORES],
    }
    if (stack_rsp!=expected_rsp or output["rax"]!=BASE+CONSTANT_RVA or
        output["rsi"]!=0 or output["saved_rsi"]!=saved_rsi or
        output["call_slot"]!=BASE+0x136784 or
        output["cf"]!=0 or output["zf"]!=1 or output["sf"]!=0):
        raise ValueError("Original x64 stack/register fixture for first callee drifted")
    return output

def extend(pe,source,cases):
    verify_original(pe)
    if len(cases)!=16:
        raise ValueError("Original parser differential requires 16 cases")
    reference=[]
    for _,row,_,kind in cases:
        if kind=="returned" and row["rip"]==BASE+joined.AFTER_CALL:
            reference.append(original_callee_reference(
                 pe,row["callee_global1"],row["rsi"]))
        else:reference.append(None)
    if sum(x is not None for x in reference)!=prior.COUNT:
        raise ValueError("Not all twelve original guest returns reached next callee")
    new_pages=(BASE+0x565000,BASE+0x566000)
    layout,_,_=joined.inspect_original(pe)
    earlier={layout[k]&~4095 for k in (
       "cookie_va","arg0_va","arg1_va","show_va","callee_global0",
       "callee_global1")}
    earlier.add((BASE+0x3968a0)&~4095)
    if any(p in earlier for p in new_pages):
        raise ValueError("Original guest image regions unexpectedly overlap")
    def replace_once(old,new):
        nonlocal source
        if source.count(old)!=1:
            raise ValueError("Authenticated prior native source anchor moved: "+old[:80])
        source=source.replace(old,new)
    replace_once("mx_cfg_region regions[PAGE_COUNT+3U];",
                 "mx_cfg_region regions[PAGE_COUNT+5U];")
    replace_once(" mx_cfg_memory mem={regions,PAGE_COUNT+3U};",
      f""" regions[PAGE_COUNT+3U].base=UINT64_C({new_pages[0]});
 regions[PAGE_COUNT+3U].data=game_init_globals_a;
 regions[PAGE_COUNT+3U].length=4096U;
 regions[PAGE_COUNT+4U].base=UINT64_C({new_pages[1]});
 regions[PAGE_COUNT+4U].data=game_init_globals_b;
 regions[PAGE_COUNT+4U].length=4096U;
 mx_cfg_memory mem={{regions,PAGE_COUNT+5U}};""")
    source_header="static int main_to_callee(mx_crt_cluster_state*s,mx_cfg_memory*m,"
    addrs=",".join("UINT64_C("+str(BASE+r)+")" for r,_,_ in STORES)
    widths=",".join(str(w)+"U" for _,w,_ in STORES)
    # Whole original CALL+callee first region in one batch, all guest access
    # preflighted before changing any memory, with a strict first nested-call
    # frontier (no fabricated return from 0x133ef6).
    helper=f"""
static uint8_t game_init_globals_a[4096U],game_init_globals_b[4096U];
static const uint64_t original_init_addrs[12U]={{{addrs}}};
static const uint32_t original_init_widths[12U]={{{widths}}};
static int native_original_init_callee(mx_crt_cluster_state*s,mx_cfg_memory*m){{
 if(!s||!m||s->fault||s->rip!=UINT64_C({BASE+prior.CALLSITE})||
    (s->rsp&15U)!=0U||s->rsp<0x2a0U)
    return 230;
 const uint64_t original_rsp=s->rsp,ret_rsp=s->rsp-8U;
 const uint64_t saved_rsp=s->rsp-16U,frame_rsp=s->rsp-0x2a0U;
 uint64_t cookie=0U,preflight=0U;
 uint32_t source_dword=0U;
 if(!mx_cfg_transfer(m,UINT64_C({BASE+COOKIE_RVA}),&cookie,8U,0)||
    !mx_cfg_transfer(m,UINT64_C({BASE+SOURCE_DWORD}),&source_dword,4U,0)||
    !mx_cfg_transfer(m,ret_rsp,&preflight,8U,0)||
    !mx_cfg_transfer(m,saved_rsp,&preflight,8U,0)||
    !mx_cfg_transfer(m,frame_rsp+0x280U,&preflight,8U,0))
    return 231;
 for(unsigned j=0;j<12U;j++){{
    if(!mx_cfg_transfer(m,original_init_addrs[j],&preflight,
                        original_init_widths[j],0))return 232;
 }}
 uint64_t next=UINT64_C({BASE+0x136784}),saved_rsi=s->rsi;
 uint64_t stack_cookie=cookie^frame_rsp;
 if(!mx_cfg_transfer(m,ret_rsp,&next,8U,1)||
    !mx_cfg_transfer(m,saved_rsp,&saved_rsi,8U,1)||
    !mx_cfg_transfer(m,frame_rsp+0x280U,&stack_cookie,8U,1))
    return 233;
 for(unsigned j=0;j<12U;j++){{
    uint64_t val=j==0U?(uint64_t)source_dword:
                   j==5U?UINT64_C({BASE+CONSTANT_RVA}):0U;
    if(!mx_cfg_transfer(m,original_init_addrs[j],&val,
                        original_init_widths[j],1))return 234;
 }}
 s->rsp=frame_rsp;s->rip=UINT64_C({BASE+FIRST_NESTED});
 s->rax=UINT64_C({BASE+CONSTANT_RVA});s->rsi=0U;
 s->zf=1U;s->sf=0U;s->cf=0U;
 s->instructions+=21U; /* authentic CALL + twenty original callee ops */
 (void)original_rsp;
 return MX_NATIVE_LINK_FRONTIER_REACHED;
}}
"""
    replace_once(source_header,helper+source_header)
    rows=[]
    for x in reference:
        if x is None:rows.append(" {0}")
        else:
            seq=[x["rsp"],x["rax"],x["rcx"],x["rdx"],x["call_slot"],
                 x["saved_rsi"],x["stack_cookie"]]+x["stores"]
            rows.append(" {"+",".join("UINT64_C("+str(v)+")" for v in seq)+"}")
    expected=("static const uint64_t original_init_expected[CASES][19]={"+
              ",".join(rows)+"};\n")
    replace_once(source_header,expected+source_header)
    marker="      next_call_frontiers++;"
    extra=f"""
      const unsigned before_init=s.instructions;
      if(native_original_init_callee(&s,&mem)!=MX_NATIVE_LINK_FRONTIER_REACHED)
         return 235;
      if(s.rip!=UINT64_C({BASE+FIRST_NESTED})||
         s.instructions!=before_init+21U||s.rsi!=0U||
         s.zf!=1U||s.sf!=0U||s.cf!=0U)return 236;
      const uint64_t*oracle=original_init_expected[i];
      if(s.rsp!=oracle[0]||s.rax!=oracle[1]||
         s.rcx!=oracle[2]||s.rdx!=oracle[3]||
         read_guest(&mem,original_caller_rsp-8U,8U)!=oracle[4]||
         read_guest(&mem,original_caller_rsp-16U,8U)!=oracle[5]||
         read_guest(&mem,s.rsp+0x280U,8U)!=oracle[6])return 237;
      for(unsigned j=0;j<12U;j++)
         if(read_guest(&mem,original_init_addrs[j],
                       original_init_widths[j])!=oracle[7U+j])return 238;
      native_init_frontiers++;
"""
    # Counter is checked outside the per-input loop, not at each case.
    replace_once(" unsigned next_call_frontiers=0U;",
                 " unsigned next_call_frontiers=0U;\n unsigned native_init_frontiers=0U;")
    replace_once(marker,marker+"\n"+extra)
    replace_once(" if(next_call_frontiers!=12U)return 224;",
                 " if(next_call_frontiers!=12U)return 224;\n if(native_init_frontiers!=12U)return 239;")
    return source

def run(executable,out,*,native_extension=None):
    from tools.pe_probe import PE
    pe=PE(executable)
    first_nested=verify_original(pe)
    def combined_extension(pe,source,cases):
        source=extend(pe,source,cases)
        return native_extension(pe,source,cases) if native_extension is not None else source
    previous=prior.run(executable,out,native_extension=combined_extension)
    if previous["native_arm64_full_helper_cwd_main_args_cases"]!=prior.COUNT:
        raise ValueError("Previous real native startup regressed")
    report={
       "original_sha256":previous["original_sha256"],
       "original_parser_arm64_cases":16,
       "native_arm64_full_first_game_init_callee_cases":12,
       "first_callee_original_instruction_count":20,
       "original_nested_call_rva":hex(FIRST_NESTED),
       "original_nested_call_operand":first_nested,
       "next_nested_call_not_executed":True,
       "game_engine_or_ios_started":False}
    (out/"joined-native-boot-init-callee.json").write_text(
         json.dumps(report,indent=2)+"\n")
    lines=["# MX Bikes: native first game-initializer CALL and twenty instructions","",
      "- Original x64/native host/executed AArch64 initializer fixtures: **12/12**",
      "- Original command-line parser scenarios: **16/16**",
      "- Original initializer global stores checked per case: **12**",
      "- Next authentic untranslated nested CALL: **"+hex(FIRST_NESTED)+"**",
      "","No nested call is fabricated; engine, renderer, menu and iOS are not running.",""]
    (out/"joined-native-boot-init-callee.md").write_text("\n".join(lines))
    print("\n".join(lines))
    return report
if __name__=="__main__":
    if len(sys.argv)!=3:raise SystemExit("usage: next-callee.py original.exe metadata-dir")
    run(Path(sys.argv[1]),Path(sys.argv[2]))
