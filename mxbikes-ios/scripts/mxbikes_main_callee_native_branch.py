#!/usr/bin/env python3
"""Compare original x64 first game-main callee Jcc against executable AArch64.

Only first seven source instructions of original function at RVA 0x136120:
six pre-branch instructions and the branch itself. Real x64 state and both
guest globals are compared to compiled AArch64 behavior over 16 byte cases.
No full original function, DirectX/OpenGL or engine boot is inferred.
"""
import hashlib,json,struct,subprocess,sys,tempfile
from pathlib import Path
from capstone import Cs,CS_ARCH_X86,CS_MODE_64,CS_GRP_JUMP
from capstone.x86 import X86_OP_MEM,X86_OP_IMM
from unicorn import Uc,UC_ARCH_X86,UC_MODE_64
from unicorn.x86_const import (
 UC_X86_REG_RIP,UC_X86_REG_RSP,UC_X86_REG_RAX,UC_X86_REG_R10,
 UC_X86_REG_RCX,UC_X86_REG_RDX,UC_X86_REG_R8,UC_X86_REG_R9,
 UC_X86_REG_EFLAGS
)
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/"arm64-lab"))
from tools.pe_probe import PE
from tools.import_aot_smoke import execute_arm64_elf

BASE=0x140000000
START=0x136120
DATA=0x600010000
STACK=0x710000000
SP=STACK+0x8000-8
SHA="4ae7de3854b4d0a18271679fb57a1f2fdf0b21804417b85dd82055078ea123b6"
INPUT=[0,1,0x7f,0x80,0xff,0,0x40,0x81,0,3,0xfe,0,0x01,0x55,0,0x88]

def original_instructions(pe):
    md=Cs(CS_ARCH_X86,CS_MODE_64);md.detail=True
    code=pe.read_rva(START,96)
    seq=[]
    for inst in md.disasm(code,START):
        seq.append(inst)
        if inst.group(CS_GRP_JUMP):
            break
    expected=[
        ("lea","rax, [rip + 0x20d1a5]"),
        ("mov","r10d, 1"),
        ("mov","qword ptr [rip + 0xd14cec], rax"),
        ("movzx","eax, byte ptr [rcx]"),
        ("mov","dword ptr [rip + 0xd14cb2], r10d"),
        ("test","al, al")
    ]
    if (len(seq)!=7 or [(i.mnemonic,i.op_str) for i in seq[:-1]]!=expected or
        seq[-1].mnemonic!="je" or len(seq[-1].operands)!=1 or
        seq[-1].operands[0].type!=X86_OP_IMM or
        seq[-1].operands[0].imm!=0x136207):
        raise RuntimeError("Original 0x136120 first branch x64 identity changed")
    def rip_address(instruction,number):
        operand=instruction.operands[number]
        if (operand.type!=X86_OP_MEM or instruction.reg_name(operand.mem.base)!="rip" or
            operand.mem.index or operand.mem.segment):
            raise RuntimeError("Original game RIP-relative memory mapping changed")
        return BASE+instruction.address+instruction.size+operand.mem.disp
    addresses={
        "entry":BASE+START,
        "constant":rip_address(seq[0],1),
        "address_global":rip_address(seq[2],0),
        "flag_global":rip_address(seq[4],0),
        "taken":BASE+int(seq[-1].operands[0].imm),
        "fallthrough":BASE+seq[-1].address+seq[-1].size,
        "byte_count":seq[-1].address+seq[-1].size-START,
    }
    if addresses["byte_count"]>64:
        raise RuntimeError("Original main callee branch length exceeds bound")
    return addresses,pe.read_rva(START,addresses["byte_count"])

def x64_case(addrs,bytes_source,case):
    val=INPUT[case]
    cpu=Uc(UC_ARCH_X86,UC_MODE_64)
    mapped=set()
    def ensure_page(addr):
        pg=addr&~4095
        if pg not in mapped:
            mapped.add(pg)
            cpu.mem_map(pg,4096)
    for addr in (addrs["entry"],addrs["entry"]+len(bytes_source)-1,
                 addrs["address_global"],addrs["flag_global"],DATA):
        ensure_page(addr)
    cpu.mem_map(STACK,0x10000)
    cpu.mem_write(addrs["entry"],bytes_source)
    cpu.mem_write(DATA+0x100,bytes([val]))
    cpu.mem_write(addrs["address_global"],struct.pack("<Q",0x1111222233334444))
    cpu.mem_write(addrs["flag_global"],struct.pack("<I",0x89abcdef))
    cpu.mem_write(SP,struct.pack("<Q",BASE+0x136747))
    initflags=0x202|([0,1,0x40,0x80,0xc1,0x41,0x200,0x81][case%8])
    regs={
        UC_X86_REG_RIP:addrs["entry"],UC_X86_REG_RSP:SP,
        UC_X86_REG_RAX:0x111222333444,
        UC_X86_REG_R10:0x1234567887654321,
        UC_X86_REG_RCX:DATA+0x100,
        UC_X86_REG_RDX:0x900000000000+case,
        UC_X86_REG_R8:DATA+0x100,
        UC_X86_REG_R9:10,
        UC_X86_REG_EFLAGS:initflags
    }
    for reg,seed in regs.items():cpu.reg_write(reg,seed)
    cpu.emu_start(addrs["entry"],0,timeout=1500000,count=7)
    flags=cpu.reg_read(UC_X86_REG_EFLAGS)
    observed={
        "input":val,"initial_flags":initflags,
        "rax":cpu.reg_read(UC_X86_REG_RAX),
        "r10":cpu.reg_read(UC_X86_REG_R10),
        "rcx":cpu.reg_read(UC_X86_REG_RCX),
        "rdx":cpu.reg_read(UC_X86_REG_RDX),
        "rsp":cpu.reg_read(UC_X86_REG_RSP),
        "rip":cpu.reg_read(UC_X86_REG_RIP),
        "cf":int(bool(flags&1)),"zf":int(bool(flags&64)),
        "sf":int(bool(flags&128)),
        "global0":struct.unpack("<Q",bytes(cpu.mem_read(addrs["address_global"],8)))[0],
        "global1":struct.unpack("<I",bytes(cpu.mem_read(addrs["flag_global"],4)))[0]
    }
    if observed["rip"]!=(addrs["taken"] if val==0 else addrs["fallthrough"]):
        raise RuntimeError("Original Jcc branch result moved")
    return observed

C=r'''#include <stdint.h>
#include "mx_game_main_callee_prefix.h"
#define BASE UINT64_C(0x140000000)
#define DATA UINT64_C(0x600010000)
#define STACK UINT64_C(0x710000000)
#define SP (STACK+0x8000U-8U)
#define CASES 16U
typedef struct {
 uint8_t first;uint32_t flags;
 uint64_t rax,r10,rcx,rdx,rsp,rip;
 uint8_t cf,zf,sf;
 uint64_t global0;uint32_t global1;
} original_case;
static const original_case cases[CASES]={__CASES__};
static uint8_t input_data[512],global0[8],global1[4];
int smoke(void){
 mx_cfg_region regions[3]={
   {DATA,input_data,512U},
   {UINT64_C(__GLOBAL0__),global0,8U},
   {UINT64_C(__GLOBAL1__),global1,4U},
 };
 mx_cfg_memory mem={regions,3U};
 mx_game_main_callee_layout layout={
   UINT64_C(__ENTRY__),
   UINT64_C(__CONSTANT__),
   UINT64_C(__GLOBAL0__),UINT64_C(__GLOBAL1__),
   UINT64_C(__TAKEN__),UINT64_C(__FALLTHROUGH__)
 };
 unsigned observed_taken=0,observed_fallthrough=0;
 for(unsigned k=0;k<CASES;k++){
   const original_case *t=&cases[k];
   input_data[0x100U]=t->first;
   uint64_t old_global=UINT64_C(0x1111222233334444);
   uint32_t old_flag=UINT32_C(0x89abcdef);
   if(!mx_cfg_transfer(&mem,UINT64_C(__GLOBAL0__),&old_global,8U,1) ||
      !mx_cfg_transfer(&mem,UINT64_C(__GLOBAL1__),&old_flag,4U,1))return 1;
   mx_crt_cluster_state s={0};
   s.rip=UINT64_C(__ENTRY__);s.rsp=SP;
   s.rcx=DATA+0x100U;s.rax=UINT64_C(0x111222333444);
   s.rdx=UINT64_C(0x900000000000)+k;
   s.r8=DATA+0x100U;s.r9=10U;
   s.cf=(t->flags&1U)!=0U;s.zf=(t->flags&64U)!=0U;
   s.sf=(t->flags&128U)!=0U;
   mx_game_main_callee_out result={0};
   int status=mx_game_main_callee_branch(&s,&mem,&layout,&result);
   if(status!=MX_GAME_PREFIX_BRANCH_REACHED)return 2;
   if(s.rax!=t->rax||result.r10!=t->r10||
      s.rcx!=t->rcx||s.rdx!=t->rdx||
      s.rsp!=t->rsp||s.rip!=t->rip||
      s.cf!=t->cf||s.zf!=t->zf||s.sf!=t->sf||
      result.branch_taken!=(t->first==0U)||
      result.input_first_byte!=t->first||
      result.executed_original_instructions!=7U||
      s.instructions!=7U)return 3;
   uint64_t g0=0;uint32_t g1=0;
   if(!mx_cfg_transfer(&mem,UINT64_C(__GLOBAL0__),&g0,8U,0)||
      !mx_cfg_transfer(&mem,UINT64_C(__GLOBAL1__),&g1,4U,0))
      return 4;
   if(g0!=t->global0||g1!=t->global1)return 5;
   if(result.branch_taken)observed_taken++;else observed_fallthrough++;
 }
 if(!observed_taken||!observed_fallthrough)return 6;
 return 0;
}
#ifdef HOST
int main(void){return smoke();}
#endif
'''

def emit(addrs,samples):
    rows=[]
    for t in samples:
        values=[
            t["input"],t["initial_flags"],t["rax"],t["r10"],
            t["rcx"],t["rdx"],t["rsp"],t["rip"],
            t["cf"],t["zf"],t["sf"],t["global0"],t["global1"]
        ]
        rows.append("{"+",".join(
            str(v) if i in (0,1,8,9,10,12) else "UINT64_C("+str(v)+")"
            for i,v in enumerate(values))+ "}")
    result=C.replace("__CASES__",",\n".join(rows))
    placeholders={
        "ENTRY":addrs["entry"],"CONSTANT":addrs["constant"],
        "GLOBAL0":addrs["address_global"],"GLOBAL1":addrs["flag_global"],
        "TAKEN":addrs["taken"],"FALLTHROUGH":addrs["fallthrough"]
    }
    for key,value in placeholders.items():
        result=result.replace("__"+key+"__",str(value))
    if "__GLOBAL" in result or "__ENTRY__" in result or "__CONSTANT__" in result:
        raise RuntimeError("Unresolved original game branch fixture placeholder")
    return result

def run(executable,directory):
    pe=PE(executable)
    if hashlib.sha256(pe.b).hexdigest()!=SHA:
        raise RuntimeError("Original executable revision changed")
    addrs,code=original_instructions(pe)
    samples=[x64_case(addrs,code,k) for k in range(len(INPUT))]
    generated=emit(addrs,samples)
    with tempfile.TemporaryDirectory(prefix="mxb-callee-first-branch-") as tmp:
        work=Path(tmp);source=work/"private-original-game-callee-branch.c"
        source.write_text(generated)
        opts=["-O2","-std=c11","-Wall","-Wextra","-Werror",
              "-I",str(ROOT/"arm64-lab"/"runtime")]
        host=work/"host"
        t=subprocess.run(["cc",*opts,"-DHOST",str(source),"-o",str(host)],
                         capture_output=True,text=True)
        if t.returncode:raise RuntimeError("Host compiler: "+t.stderr[-2400:])
        t=subprocess.run([str(host)],capture_output=True,text=True)
        if t.returncode:raise RuntimeError("Original/native host branch mismatch exit "+str(t.returncode))
        arm=work/"original-game-branch-arm64.elf"
        t=subprocess.run(["clang","--target=aarch64-unknown-linux-gnu",
             "-fuse-ld=lld","-nostdlib","-static","-ffreestanding",
             "-fno-builtin","-fno-stack-protector",*opts,
             "-Wl,-e,smoke","-Wl,-z,max-page-size=4096",
             "-Wl,--build-id=none",str(source),"-o",str(arm)],
             capture_output=True,text=True)
        if t.returncode:raise RuntimeError("ARM64 compiler: "+t.stderr[-2400:])
        result=execute_arm64_elf(arm,instruction_budget=1000000,timeout_us=6000000)
        if result["arm64_smoke_exit"]!=0:
            raise RuntimeError("Original/native ARM64 branch mismatch: "+str(result["arm64_smoke_exit"]))
    directory.mkdir(parents=True,exist_ok=True)
    pass_taken=sum(s["input"]==0 for s in samples)
    metadata={
      "original_game_sha_verified":True,
      "original_game_callee_rva":"0x136120",
      "original_first_conditional_rva":"0x136140",
      "taken_rva":"0x136207",
      "fallthrough_rva":"0x136146",
      "original_x64_cases":len(samples),
      "native_host_cases":len(samples),
      "native_arm64_cases":len(samples),
      "taken_cases":pass_taken,
      "fallthrough_cases":len(samples)-pass_taken,
      "original_global_writes_per_case":2,
      "original_instructions_per_case":7,
      "full_original_callee_executed":False,
      "original_callee_jcc_successors_executed":False,
      "engine_initialized":False
    }
    (directory/"game-callee-native-jcc.json").write_text(json.dumps(metadata,indent=2)+"\n")
    summary="\n".join([
        "# MX Bikes real game-callee Jcc differential on ARM64","",
        "- Original callee initial block: **0x136120 → 0x136140 (JE)**",
        "- Original x64 vs native ARM64 matching cases: **"+str(len(samples))+"/"+str(len(samples))+"**",
        "- Taken JE test cases: **"+str(pass_taken)+"**",
        "- Fallthrough test cases: **"+str(len(samples)-pass_taken)+"**",
        "- Original instructions translated and executed per case: **7**",
        "- Original global memory writes compared per case: **2**",
        "- Win64 guest registers, SF/ZF/CF and branch destinations compared: **YES**",
        "",
        "**Stops at the two branch destinations without executing either successor. "
        "The full callee and engine are not running.**",""
    ])
    (directory/"game-callee-native-jcc.md").write_text(summary)
    print(summary)
    return metadata

if __name__=="__main__":
    if len(sys.argv)!=3:raise SystemExit("usage: branch_diff.py original.exe out-dir")
    run(Path(sys.argv[1]),Path(sys.argv[2]))
