#!/usr/bin/env python3
"""Joined original MX Bikes game main -> CALL -> first callee Jcc, x64 vs ARM64.

The native main prefix executes eight original-equivalent instructions then
dispatches an authentic Win64 CALL by guest virtual address through the
verified linker. The native callee executes its six original-equivalent
straight-line instructions and first JE. Stops at BOTH branch frontiers;
neither successor nor the whole game main/callee is implemented.
"""
import hashlib,json,struct,subprocess,sys,tempfile
from pathlib import Path
from capstone import Cs,CS_ARCH_X86,CS_MODE_64,CS_GRP_CALL
from capstone.x86 import X86_OP_MEM,X86_OP_IMM
from unicorn import Uc,UC_ARCH_X86,UC_MODE_64,UC_HOOK_CODE
from unicorn.x86_const import (
 UC_X86_REG_RIP,UC_X86_REG_RSP,UC_X86_REG_RAX,UC_X86_REG_RBX,
 UC_X86_REG_RCX,UC_X86_REG_RDX,UC_X86_REG_R8,UC_X86_REG_R9,
 UC_X86_REG_RDI,UC_X86_REG_RSI,UC_X86_REG_R11,UC_X86_REG_R10,
 UC_X86_REG_EFLAGS
)
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/"arm64-lab"))
from tools.pe_probe import PE
from tools.import_aot_smoke import execute_arm64_elf
from mxbikes_main_first_block import probe as verify_main,align4k,EXE_SHA
from mxbikes_main_callee_native_branch import original_instructions as verify_callee,INPUT as BYTE_CASES

BASE=0x140000000
MAIN=0x136710
CALLEE=0x136120
CALL_SITE=0x136741
AFTER_CALL=0x136746
CODE_DATA=0x600010000
STACK=0x710000000
STACK_BYTES=0x20000
ENTRY_SP=STACK+0x10000-0x108
TEST_INPUT=CODE_DATA+0x100
NUM_CASES=16
REGISTER_IDS=[
 ("rax",UC_X86_REG_RAX),("rbx",UC_X86_REG_RBX),
 ("rcx",UC_X86_REG_RCX),("rdx",UC_X86_REG_RDX),
 ("r8",UC_X86_REG_R8),("r9",UC_X86_REG_R9),
 ("rdi",UC_X86_REG_RDI),("rsi",UC_X86_REG_RSI),
 ("r11",UC_X86_REG_R11)
]
SEED_RBX=0x123456789abcd
SEED_RDI=0x5778899aabbcc
SEED_RSI=0x1123456789abc
SEED_R11=0x54111122223333

def rip_addr(instruction,operand_index):
    operand=instruction.operands[operand_index]
    if operand.type!=X86_OP_MEM or instruction.reg_name(operand.mem.base)!="rip":
        raise RuntimeError("Original x64 main RIP addressing pattern changed")
    if operand.mem.index or operand.mem.segment:
        raise RuntimeError("Unsupported original RIP-relative address expression")
    return BASE+instruction.address+instruction.size+operand.mem.disp

def inspect_original(pe):
    decoder=Cs(CS_ARCH_X86,CS_MODE_64);decoder.detail=True
    raw=pe.read_rva(MAIN,CALL_SITE+5-MAIN)
    inst=list(decoder.disasm(raw,MAIN))
    if(len(inst)!=9 or sum(i.size for i in inst)!=len(raw) or
       inst[0].mnemonic!="sub" or inst[0].op_str!="rsp, 0x288" or
       inst[1].mnemonic!="mov" or inst[2].mnemonic!="xor" or
       inst[2].op_str!="rax, rsp" or inst[3].mnemonic!="mov" or
       inst[3].op_str!="qword ptr [rsp + 0x250], rax" or
       inst[4].mnemonic!="mov" or inst[5].mnemonic!="mov" or
       inst[5].op_str!="rcx, r8" or
       inst[6].mnemonic!="mov" or inst[7].mnemonic!="mov" or
       inst[8].address!=CALL_SITE or not inst[8].group(CS_GRP_CALL) or
       inst[8].operands[0].type!=X86_OP_IMM or
       inst[8].operands[0].imm!=CALLEE):
        raise RuntimeError("Original main first block or CALL changed")
    callee,callee_code=verify_callee(pe)
    empty=list(decoder.disasm(pe.read_rva(0x136207,3),0x136207))
    if (len(empty)!=2 or empty[0].mnemonic!="xor" or
        empty[0].op_str!="eax, eax" or empty[1].mnemonic!="ret" or
        sum(ins.size for ins in empty)!=3):
        raise RuntimeError("Original JE-taken XOR EAX,EAX; RET identity changed")
    layout={
       "main_va":BASE+MAIN,
       "callee_va":BASE+CALLEE,
       "callsite_va":BASE+CALL_SITE,
       "return_va":BASE+AFTER_CALL,
       "cookie_va":rip_addr(inst[1],1),
       "arg0_va":rip_addr(inst[4],0),
       "arg1_va":rip_addr(inst[6],0),
       "show_va":rip_addr(inst[7],0),
       "callee_constant":callee["constant"],
       "callee_global0":callee["address_global"],
       "callee_global1":callee["flag_global"],
       "taken_va":callee["taken"],
       "fallthrough_va":callee["fallthrough"]
    }
    if not all(x>BASE for k,x in layout.items() if k.endswith("_va") and k not in ("callsite_va","return_va")):
        raise RuntimeError("Original PE-global layout changed")
    return layout,inst,callee_code

def new_cpu(pe):
    image_end=max(int(rva)+max(int(vsz),int(raw)) for _,vsz,rva,raw,_,_ in pe.sections)
    if image_end>128*1024*1024:raise RuntimeError("Original executable image oversized")
    uc=Uc(UC_ARCH_X86,UC_MODE_64)
    uc.mem_map(BASE,align4k(image_end))
    uc.mem_write(BASE,pe.b[:min(pe.size_of_headers if hasattr(pe,"size_of_headers") else 4096,len(pe.b))])
    for _,_,rva,raw,ptr,_ in pe.sections:
        if raw:uc.mem_write(BASE+rva,pe.b[ptr:ptr+raw])
    uc.mem_map(STACK,STACK_BYTES)
    uc.mem_map(CODE_DATA,4096)
    return uc

def original_run(pe,layout,index):
    uc=new_cpu(pe)
    input_byte=BYTE_CASES[index]
    uc.mem_write(TEST_INPUT,bytes([input_byte]))
    uc.mem_write(ENTRY_SP,struct.pack("<Q",BASE+0x777777))
    seed={
       UC_X86_REG_RIP:BASE+MAIN,
       UC_X86_REG_RSP:ENTRY_SP,
       UC_X86_REG_RAX:0x888876543210+index,
       UC_X86_REG_RBX:SEED_RBX,
       UC_X86_REG_RCX:BASE,
       UC_X86_REG_RDX:0,
       UC_X86_REG_R8:TEST_INPUT,
       UC_X86_REG_R9:10,
       UC_X86_REG_RDI:SEED_RDI,
       UC_X86_REG_RSI:SEED_RSI,
       UC_X86_REG_R11:SEED_R11,
       UC_X86_REG_R10:0x78123456789,
       UC_X86_REG_EFLAGS:0x202|[0,1,0x40,0x80,0xc1,0x41,0x200,0x81][index%8]
    }
    for reg,val in seed.items():uc.reg_write(reg,val)
    pre={
       "cookie":struct.unpack("<Q",bytes(uc.mem_read(layout["cookie_va"],8)))[0],
       "arg0":struct.unpack("<Q",bytes(uc.mem_read(layout["arg0_va"],8)))[0],
       "arg1":struct.unpack("<Q",bytes(uc.mem_read(layout["arg1_va"],8)))[0],
       "show":struct.unpack("<I",bytes(uc.mem_read(layout["show_va"],4)))[0],
       "callee0":struct.unpack("<Q",bytes(uc.mem_read(layout["callee_global0"],8)))[0],
       "callee1":struct.unpack("<I",bytes(uc.mem_read(layout["callee_global1"],4)))[0]
    }
    count=18 if input_byte==0 else 16
    sequence=[]
    def on_code(u,address,size,ctx):
        sequence.append(address)
        if len(sequence)>count:
            u.emu_stop()
    uc.hook_add(UC_HOOK_CODE,on_code)
    uc.emu_start(BASE+MAIN,0,timeout=3000000,count=count)
    pc=uc.reg_read(UC_X86_REG_RIP)
    if(len(sequence)!=count or sequence[0]!=BASE+MAIN or
       sequence[8]!=BASE+CALL_SITE or
       sequence[9]!=BASE+CALLEE or
       pc!=(layout["return_va"] if input_byte==0 else layout["fallthrough_va"]) or
       (input_byte==0 and sequence[-2:]!=[BASE+0x136207,BASE+0x136209])):
        raise RuntimeError("Original joined main/CALL/callee JE execution escaped: "+
                           json.dumps({"case":index,"pc":hex(pc),"len":len(sequence),
                                       "trace":[hex(v-BASE) for v in sequence]}))
    flags=uc.reg_read(UC_X86_REG_EFLAGS)
    expected={
      **{name:uc.reg_read(reg) for name,reg in REGISTER_IDS},
      "r10":uc.reg_read(UC_X86_REG_R10),
      "rsp":uc.reg_read(UC_X86_REG_RSP),"rip":pc,
      "cf":int(bool(flags&1)),"zf":int(bool(flags&64)),
      "sf":int(bool(flags&128)),
      "ret_at_guest_rsp":struct.unpack("<Q",bytes(
          uc.mem_read(ENTRY_SP-0x288-8,8)))[0],
      "saved_cookie":struct.unpack("<Q",bytes(
          uc.mem_read(ENTRY_SP-0x288+0x250,8)))[0],
      "arg0_global":struct.unpack("<Q",bytes(uc.mem_read(layout["arg0_va"],8)))[0],
      "arg1_global":struct.unpack("<Q",bytes(uc.mem_read(layout["arg1_va"],8)))[0],
      "show_global":struct.unpack("<I",bytes(uc.mem_read(layout["show_va"],4)))[0],
      "callee_global0":struct.unpack("<Q",bytes(uc.mem_read(layout["callee_global0"],8)))[0],
      "callee_global1":struct.unpack("<I",bytes(uc.mem_read(layout["callee_global1"],4)))[0],
      "input_byte":input_byte
    }
    if(expected["ret_at_guest_rsp"]!=layout["return_va"] or
       expected["r10"]!=1 or
       expected["rsp"]!=(ENTRY_SP-0x288 if input_byte==0
                         else ENTRY_SP-0x288-8)):
        raise RuntimeError("Original joined x64 Win64 call state mismatch")
    return pre,expected

SOURCE=r'''#include <stdint.h>
#include "mx_main_entry_prefix.h"
#include "mx_native_guest_linker.h"
#include "mx_game_main_callee_prefix.h"
#define BASE UINT64_C(0x140000000)
#define MAIN UINT64_C(__MAIN__)
#define CALLEE UINT64_C(__CALLEE__)
#define CALLSITE UINT64_C(__CALLSITE__)
#define AFTER_CALL UINT64_C(__AFTER_CALL__)
#define COOKIE UINT64_C(__COOKIE__)
#define ARG0 UINT64_C(__ARG0__)
#define ARG1 UINT64_C(__ARG1__)
#define SHOW UINT64_C(__SHOW__)
#define CALLEE_CONST UINT64_C(__CALLEE_CONST__)
#define CALLEE_G0 UINT64_C(__CALLEE_G0__)
#define CALLEE_G1 UINT64_C(__CALLEE_G1__)
#define TAKEN UINT64_C(__TAKEN__)
#define FALLTHROUGH UINT64_C(__FALLTHROUGH__)
#define DATA UINT64_C(0x600010000)
#define STACK UINT64_C(0x710000000)
#define ENTRY_SP (STACK+0x10000U-0x108U)
#define TEST_INPUT (DATA+0x100U)
#define CASES 16U
#define PAGE_COUNT __PAGE_COUNT__
typedef struct {
 uint8_t in_byte;
 uint64_t pre[6];
 uint64_t expected[9];
 uint64_t r10,rsp,rip,ret_at_guest_rsp,saved_cookie;
 uint64_t arg0,arg1,show,g0,g1;
 uint8_t cf,zf,sf;
} fixture;
static const fixture fixtures[CASES]={__FIXTURES__};
static uint8_t stack_bytes[131072U],input_data[4096U];
static uint8_t original_image_pages[PAGE_COUNT][4096U];
static const uint64_t mapped_original_pages[PAGE_COUNT]={__PAGES__};
static mx_game_main_callee_layout callee_layout={
  CALLEE,CALLEE_CONST,CALLEE_G0,CALLEE_G1,TAKEN,FALLTHROUGH
};
static mx_game_main_callee_out current_branch={0};
static int native_callee_prefix(mx_crt_cluster_state*s,mx_cfg_memory*m,void*ctx){
 (void)ctx;
 int rc=mx_game_main_callee_branch(s,m,&callee_layout,&current_branch);
 if(rc!=MX_GAME_PREFIX_BRANCH_REACHED)return rc;
 if(current_branch.branch_taken)
    return mx_game_main_callee_finish_empty(s,m,&callee_layout);
 return MX_NATIVE_LINK_FRONTIER_REACHED;
}
static const mx_native_link_entry callable[]={
  {CALLEE,native_callee_prefix,0}
};
static uint64_t read_guest(mx_cfg_memory*m,uint64_t addr,unsigned size){
 uint64_t out=0U;
 if(!mx_cfg_transfer(m,addr,&out,size,0))return UINT64_MAX;
 return out;
}
static int main_to_callee(mx_crt_cluster_state*s,mx_cfg_memory*m,
                          mx_native_link_registry*r){
 mx_main_prefix_state p={0};
 p.rip=s->rip;p.rsp=s->rsp;
 p.rax=s->rax;p.rcx=s->rcx;p.rdx=s->rdx;p.r8=s->r8;p.r9=s->r9;
 p.cf=s->cf;p.sf=s->sf;p.zf=s->zf;
 mx_main_prefix_layout layout={
   MAIN,CALLSITE,COOKIE,ARG0,ARG1,SHOW,0x288U,0x250U
 };
 if(mx_main_execute_prefix(&p,m,&layout)!=MX_MAIN_PREFIX_CALL_BOUNDARY)
    return MX_NATIVE_LINK_INVALID;
 s->rip=p.rip;s->rsp=p.rsp;s->rax=p.rax;s->rcx=p.rcx;s->rdx=p.rdx;
 s->r8=p.r8;s->r9=p.r9;
 s->cf=(uint8_t)p.cf;s->sf=(uint8_t)p.sf;s->zf=(uint8_t)p.zf;
 s->instructions=p.instructions+1U; /* original direct CALL */
 return mx_native_link_call_until_return_or_frontier(
     r,s,m,CALLEE,AFTER_CALL,TAKEN,FALLTHROUGH);
}
int smoke(void){
 mx_cfg_region regions[PAGE_COUNT+2U];
 regions[0].base=STACK;regions[0].data=stack_bytes;regions[0].length=131072U;
 regions[1].base=DATA;regions[1].data=input_data;regions[1].length=4096U;
 for(unsigned j=0;j<PAGE_COUNT;j++){
   regions[2U+j].base=mapped_original_pages[j];
   regions[2U+j].data=original_image_pages[j];
   regions[2U+j].length=4096U;
 }
 mx_cfg_memory mem={regions,PAGE_COUNT+2U};
 mx_native_link_registry r={0};
 r.entries=callable;r.count=1U;r.max_depth=4U;
 if(mx_native_link_seal(&r)!=MX_NATIVE_LINK_OK)return 1;
 unsigned taken=0,fallthrough=0;
 for(unsigned i=0;i<CASES;i++){
   const fixture*f=&fixtures[i];
   for(unsigned j=0;j<131072U;j++)stack_bytes[j]=0U;
   for(unsigned j=0;j<PAGE_COUNT;j++)
      for(unsigned k=0;k<4096U;k++)original_image_pages[j][k]=0U;
   input_data[0x100U]=f->in_byte;
   uint64_t init0=f->pre[0];
   uint64_t init1=f->pre[1];
   uint64_t init2=f->pre[2];
   uint32_t init3=(uint32_t)f->pre[3];
   uint64_t init4=f->pre[4];
   uint32_t init5=(uint32_t)f->pre[5];
   if(!mx_cfg_transfer(&mem,COOKIE,&init0,8U,1) ||
      !mx_cfg_transfer(&mem,ARG0,&init1,8U,1) ||
      !mx_cfg_transfer(&mem,ARG1,&init2,8U,1) ||
      !mx_cfg_transfer(&mem,SHOW,&init3,4U,1) ||
      !mx_cfg_transfer(&mem,CALLEE_G0,&init4,8U,1) ||
      !mx_cfg_transfer(&mem,CALLEE_G1,&init5,4U,1))return 2;
   mx_crt_cluster_state s={0};
   s.rip=MAIN;s.rsp=ENTRY_SP;
   s.rax=UINT64_C(0x888876543210)+i;
   s.rbx=UINT64_C(0x123456789abcd);
   s.rcx=BASE;s.rdx=0U;s.r8=TEST_INPUT;s.r9=10U;
   s.rdi=UINT64_C(0x5778899aabbcc);
   s.rsi=UINT64_C(0x1123456789abc);
   s.r11=UINT64_C(0x54111122223333);
   s.cf=(uint8_t)((i%8U==1U)||(i%8U==4U)||(i%8U==5U)||(i%8U==7U));
   s.sf=(uint8_t)((i%8U==3U)||(i%8U==4U)||(i%8U==7U));
   s.zf=(uint8_t)((i%8U==2U)||(i%8U==4U)||(i%8U==5U));
   int result=main_to_callee(&s,&mem,&r);
   if(result!=(f->in_byte==0U?MX_NATIVE_LINK_OK:
                 MX_NATIVE_LINK_FRONTIER_REACHED))return 3;
   const uint64_t actual[9]={
      s.rax,s.rbx,s.rcx,s.rdx,s.r8,s.r9,s.rdi,s.rsi,s.r11
   };
   for(unsigned j=0;j<9U;j++)
      if(actual[j]!=f->expected[j])return 4;
   if(current_branch.r10!=f->r10 || s.rsp!=f->rsp ||
      s.rip!=f->rip || s.cf!=f->cf||s.zf!=f->zf||s.sf!=f->sf ||
      read_guest(&mem,ENTRY_SP-0x288U-8U,8U)!=f->ret_at_guest_rsp ||
      read_guest(&mem,ENTRY_SP-0x288U+0x250U,8U)!=f->saved_cookie)
       return 5;
   if(read_guest(&mem,ARG0,8U)!=f->arg0 ||
      read_guest(&mem,ARG1,8U)!=f->arg1 ||
      read_guest(&mem,SHOW,4U)!=f->show ||
      read_guest(&mem,CALLEE_G0,8U)!=f->g0 ||
      read_guest(&mem,CALLEE_G1,4U)!=f->g1 ||
      s.instructions!=(f->in_byte==0U?18U:16U) ||
      current_branch.input_first_byte!=f->in_byte)
       return 6;
   if(current_branch.branch_taken)taken++;else fallthrough++;
 }
 if(taken==0U||fallthrough==0U||r.calls_attempted!=CASES||
    r.unresolved_calls||r.active_depth ||r.calls_completed!=taken)
    return 7;
 /* Unknown functions cannot fabricate a successful frontier. */
 mx_crt_cluster_state absent={0};
 absent.rip=CALLSITE;absent.rsp=ENTRY_SP-0x288U;
 if(mx_native_link_call_frontier(&r,&absent,&mem,
      BASE+0x999999U,AFTER_CALL,TAKEN,FALLTHROUGH)!=MX_NATIVE_LINK_UNRESOLVED ||
    absent.rsp!=ENTRY_SP-0x288U||absent.rip!=CALLSITE)return 8;
 return 0;
}
#ifdef HOST
int main(void){return smoke();}
#endif
'''

def generate(layout,references):
    rows=[]
    keys=["rax","rbx","rcx","rdx","r8","r9","rdi","rsi","r11"]
    for pre,x in references:
        before=[pre[k] for k in ("cookie","arg0","arg1","show","callee0","callee1")]
        values=[x[k] for k in keys]
        suffix=[
           x["r10"],x["rsp"],x["rip"],
           x["ret_at_guest_rsp"],x["saved_cookie"],
           x["arg0_global"],x["arg1_global"],x["show_global"],
           x["callee_global0"],x["callee_global1"]
        ]
        rows.append(" {"+str(x["input_byte"])+
          ",{"+",".join(f"UINT64_C({z})" for z in before)+"},"+
          "{"+",".join(f"UINT64_C({z})" for z in values)+"},"+
          ",".join(f"UINT64_C({z})" for z in suffix)+","+
          str(x["cf"])+","+str(x["zf"])+","+str(x["sf"])+"}")
    relevant=[
        "cookie_va","arg0_va","arg1_va","show_va",
        "callee_global0","callee_global1"
    ]
    pages=sorted({layout[k]&~4095 for k in relevant})
    table={
      "__MAIN__":layout["main_va"],"__CALLEE__":layout["callee_va"],
      "__CALLSITE__":layout["callsite_va"],
      "__AFTER_CALL__":layout["return_va"],
      "__COOKIE__":layout["cookie_va"],"__ARG0__":layout["arg0_va"],
      "__ARG1__":layout["arg1_va"],"__SHOW__":layout["show_va"],
      "__CALLEE_CONST__":layout["callee_constant"],
      "__CALLEE_G0__":layout["callee_global0"],
      "__CALLEE_G1__":layout["callee_global1"],
      "__TAKEN__":layout["taken_va"],
      "__FALLTHROUGH__":layout["fallthrough_va"],
      "__PAGE_COUNT__":len(pages),
      "__PAGES__":",".join(f"UINT64_C({p})" for p in pages),
      "__FIXTURES__":",\n".join(rows)
    }
    src=SOURCE
    for key,v in table.items():src=src.replace(key,str(v))
    if "__" in src[src.index("#define MAIN"):src.index("static uint8_t stack_bytes")]:
        raise RuntimeError("Unresolved generated guest-layout placeholder")
    return src,pages

def run(executable,destination):
    pe=PE(executable)
    if hashlib.sha256(pe.b).hexdigest()!=EXE_SHA:
        raise RuntimeError("Original executable SHA no longer matches")
    verify_main(executable)
    layout,inst,callee_code=inspect_original(pe)
    refs=[original_run(pe,layout,k) for k in range(NUM_CASES)]
    src,pages=generate(layout,refs)
    with tempfile.TemporaryDirectory(prefix="mxb-joined-original-main-") as td:
        p=Path(td);c=p/"private-joined-original-x64-guest.c"
        c.write_text(src)
        opts=["-O2","-std=c11","-Wall","-Wextra","-Werror",
              "-I",str(ROOT/"arm64-lab"/"runtime")]
        host=p/"host"
        result=subprocess.run(["cc",*opts,"-DHOST",str(c),"-o",str(host)],
                              capture_output=True,text=True)
        if result.returncode:
            raise RuntimeError("Joined native host compile failed: "+result.stderr[-4000:])
        result=subprocess.run([str(host)],capture_output=True,text=True)
        if result.returncode:
            raise RuntimeError("Joined original x64 vs native host mismatch exit "+
                               str(result.returncode))
        arm=p/"joined-original-main-arm64.elf"
        result=subprocess.run(["clang","--target=aarch64-unknown-linux-gnu",
             "-fuse-ld=lld","-nostdlib","-static","-ffreestanding",
             "-fno-builtin","-fno-stack-protector",*opts,
             "-Wl,-e,smoke","-Wl,-z,max-page-size=4096",
             "-Wl,--build-id=none",str(c),"-o",str(arm)],
             capture_output=True,text=True)
        if result.returncode:
            raise RuntimeError("Joined native ARM64 compile failed: "+result.stderr[-4000:])
        result=execute_arm64_elf(arm,instruction_budget=1950000,timeout_us=15000000)
        if result["arm64_smoke_exit"]!=0:
            raise RuntimeError("Joined real-game main/CALL/Jcc ARM64 execution failed")
    destination.mkdir(parents=True,exist_ok=True)
    taken=sum(x["input_byte"]==0 for _,x in refs)
    report={
       "original_sha_verified":True,
       "main_entry_rva":hex(MAIN),"first_callee_rva":hex(CALLEE),
       "joined_original_machine_instructions_through_first_jcc":16,
       "joined_original_instructions_empty_branch_return":18,
       "original_game_main_instructions":8,
       "original_game_direct_call_instructions":1,
       "original_callee_instructions_through_first_jcc":7,
       "joined_native_arm64_cases":NUM_CASES,
       "matching_original_x64_cases":NUM_CASES,
       "je_taken_cases":taken,
       "je_fallthrough_cases":NUM_CASES-taken,
       "original_guest_image_pages_mapped":len(pages),
       "original_globals_verified_per_case":5,
       "guest_call_return_slot_preserved":True,
       "original_empty_branch_xor_ret_native_executed":True,
       "empty_branch_returned_to_game_main":True,
       "nonempty_successor_executed":False,
       "full_callee_all_paths_implemented":False,
       "engine_initialized":False,
       "actual_ios_build":False,
       "scope":"Original main CALL and native callee return to game main on empty command; nonempty case stops at JE fallthrough. No downstream main body or engine boot."
    }
    (destination/"joined-main-callee-frontier.json").write_text(json.dumps(report,indent=2)+"\n")
    summary="\n".join([
        "# MX Bikes — joined real game-main CALL into first native callee JE",
        "",
        "- Original game main/CALL/callee instructions before first JE: **16**",
        "- Original empty branch XOR EAX,EAX; RET joined: **2 additional instructions**",
        "- Matched original x64 vs executed native ARM64 scenarios: **16/16**",
        "- JE taken cases: **"+str(taken)+"**",
        "- JE fallthrough cases: **"+str(NUM_CASES-taken)+"**",
        "- Original Win64 CALL stack and return-address slot: **Verified**",
        "- Empty-command callee returned to original main continuation: **YES**",
        "- Original image global values compared after joined execution: **5**",
        "- Native guest-function dispatcher invoked: **YES**",
        "- Nonempty-command callee returned: **NO — unresolved path**",
        "",
        "**Empty command returns through the real guest CALL; nonempty command "
        "halts at the untranslated fallthrough. Full game main, engine and "
        "rendering have not run.**",""
    ])
    (destination/"joined-main-callee-frontier.md").write_text(summary)
    print(summary)
    return report

if __name__=="__main__":
    if len(sys.argv)!=3:
        raise SystemExit("usage: joined_main.py original-mxbikes.exe report-dir")
    run(Path(sys.argv[1]),Path(sys.argv[2]))
