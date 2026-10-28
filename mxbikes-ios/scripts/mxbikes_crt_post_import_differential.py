#!/usr/bin/env python3
"""Private original CALL -> import JMP -> synthetic RET -> CRT continuation.

Verifies two original MX Bikes MSVCR90 CRT calls with their actual following
machine instructions on x64 against compiled C and AArch64. Callbacks return
synthetic data; no actual CRT callback arrays are executed.
"""
from pathlib import Path
import hashlib,json,struct,subprocess,sys,tempfile

from capstone import Cs,CS_ARCH_X86,CS_MODE_64
from unicorn import Uc,UC_ARCH_X86,UC_MODE_64,UC_HOOK_CODE
from unicorn.x86_const import (UC_X86_REG_RIP,UC_X86_REG_RSP,
    UC_X86_REG_RAX,UC_X86_REG_RBX,UC_X86_REG_RCX,UC_X86_REG_RDX,
    UC_X86_REG_RDI,UC_X86_REG_RSI,UC_X86_REG_EFLAGS)

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/"arm64-lab"))
from tools.pe_probe import PE
from tools.crt_post_import import after_initterm_e,after_initterm
from tools.import_aot_smoke import execute_arm64_elf
from mxbikes_crt_import_thunk_differential import decode_calls,BASE,SHA

CALL_E=0x2ab0b6
AFTER_E=0x2ab0bb
ERROR_E=0x2ab221
JOIN_E=0x2ab0d3
END_E=0x2ab0c9
CALL_VOID=0x2ab0ec
AFTER_VOID=0x2ab0f1
END_VOID=0x2ab108
STATE=BASE+0xe4ada0
OWNER=BASE+0xe4ada8
STACK=0x700000000
SP=STACK+0xff00
WIN=SP-128
STUB=0x600000000
REGS=(("rax",UC_X86_REG_RAX),("rbx",UC_X86_REG_RBX),
      ("rcx",UC_X86_REG_RCX),("rdx",UC_X86_REG_RDX),
      ("rdi",UC_X86_REG_RDI),("rsi",UC_X86_REG_RSI),
      ("rsp",UC_X86_REG_RSP),("rip",UC_X86_REG_RIP))
OUT=("rax","rbx","rcx","rdx","rdi","rsi","rsp","rip","zf",
     "crt_state","lock_owner","visited","steps")

def fixtures():
    statuses=(0,1,2,255,0x7fffffff,0x80000000,0xffffffff,42)
    for kind in (1,2):
        for k in range(16):
            yield {
                "kind":kind,
                "status":statuses[k%len(statuses)],
                "rax":0x334400001000+k*913,
                "rbx":0x113355000000+k*139,
                "rcx":0x14031b000+k*24,
                "rdx":0x14031c000+k*40,
                "rdi":0x667788112200+k*51,
                "rsi":(0 if k%2==0 else 1) if kind==2 else 0x554400+k,
                "zf":k%2,
                "initial_state":1 if kind==2 else 0,
                "initial_owner":0x778899110000+k*0x141,
            }

def x64_original(pe,spec,case,after,stop):
    site=spec["call_rva"]
    kind=case["kind"]
    expected_stop=(JOIN_E if case["status"]==0 else ERROR_E) if kind==1 else END_VOID
    cpu=Uc(UC_ARCH_X86,UC_MODE_64)
    for page in {(BASE+site)&~4095,(BASE+spec["thunk_rva"])&~4095,
                 (BASE+spec["iat_rva"])&~4095,STATE&~4095}:
        cpu.mem_map(page,4096)
    cpu.mem_map(STACK,0x20000)
    cpu.mem_map(STUB,4096)
    cpu.mem_write(BASE+site,pe.read_rva(site,stop-site))
    cpu.mem_write(BASE+spec["thunk_rva"],spec["original_thunk"])
    cpu.mem_write(BASE+spec["iat_rva"],struct.pack("<Q",STUB))
    cpu.mem_write(STUB,b"\xc3")
    cpu.mem_write(STATE,struct.pack("<I",case["initial_state"]))
    cpu.mem_write(OWNER,struct.pack("<Q",case["initial_owner"]))
    for name,reg in REGS:
        cpu.reg_write(reg,BASE+site if name=="rip" else SP if name=="rsp" else case[name])
    cpu.reg_write(UC_X86_REG_EFLAGS,0x202|(case["zf"]<<6))
    md=Cs(CS_ARCH_X86,CS_MODE_64)
    ins=list(md.disasm(pe.read_rva(after,stop-after),after))
    reference_map={BASE+i.address:j for j,i in enumerate(ins)}
    approved={BASE+site,BASE+spec["thunk_rva"],STUB,*reference_map}
    seen={"call":0,"visited":0,"steps":0}
    def hook(emu,pc,length,_):
        if pc not in approved:
            raise RuntimeError("Original post-CRT import escaped bounded code")
        if pc==STUB:
            seen["call"]+=1
            if (seen["call"]!=1 or emu.reg_read(UC_X86_REG_RSP)!=SP-8 or
                emu.reg_read(UC_X86_REG_RSP)%16!=8):
                raise RuntimeError("Original imported CRT call ABI violation")
            if (emu.reg_read(UC_X86_REG_RCX)!=case["rcx"] or
                emu.reg_read(UC_X86_REG_RDX)!=case["rdx"]):
                raise RuntimeError("Original imported CRT call argument mismatch")
            if kind==1:
                emu.reg_write(UC_X86_REG_RAX,case["status"])
        if pc in reference_map:
            seen["visited"]|=1<<reference_map[pc]
            seen["steps"]+=1
    cpu.hook_add(UC_HOOK_CODE,hook)
    cpu.emu_start(BASE+site,BASE+expected_stop,timeout=2_000_000,count=32)
    if seen["call"]!=1:
        raise RuntimeError("Original direct CRT thunk callback did not run exactly once")
    result={name:cpu.reg_read(reg) for name,reg in REGS}
    result["zf"]=int(bool(cpu.reg_read(UC_X86_REG_EFLAGS)&64))
    result["crt_state"]=struct.unpack("<I",cpu.mem_read(STATE,4))[0]
    result["lock_owner"]=struct.unpack("<Q",cpu.mem_read(OWNER,8))[0]
    result["visited"]=seen["visited"]
    result["steps"]=seen["steps"]
    result["stack"]=bytes(cpu.mem_read(WIN,256))
    if result["rsp"]!=SP or result["rip"]!=BASE+expected_stop:
        raise RuntimeError("Original postcall did not hit approved continuation boundary")
    if kind==2 and (result["crt_state"]!=2 or
        result["lock_owner"]!=(case["initial_owner"] if case["rsi"] else 0)):
        raise RuntimeError("Original void CRT postcall changed state incorrectly")
    return result

HARNESS=r"""
#include <stdint.h>
#include "mx_crt_init_imports.h"
#include "mx_crt_primitives.h"
#define WINDOW UINT64_C(WIN_ADDR)
#define SP UINT64_C(SP_ADDR)
#define STATE UINT64_C(STATE_ADDR)
#define OWNER UINT64_C(OWNER_ADDR)
typedef struct {
 uint64_t kind,site,status,rax,rbx,rcx,rdx,rdi,rsi,zf,initial_state,initial_owner;
 uint64_t e_rax,e_rbx,e_rcx,e_rdx,e_rdi,e_rsi,e_rsp,e_rip,e_zf;
 uint64_t e_state,e_owner,e_visited,e_steps;
 uint8_t e_stack[256];
} fixture;
static const fixture data[]={
__CASES__
};
static uint8_t stack_window[256],state_bytes[4],owner_bytes[8];
typedef struct {uint32_t seen,kind,status;uint64_t rcx,rdx;} cb_state;
static int synthetic(void *p,uint32_t kind,uint64_t a,uint64_t b,uint32_t *out){
 cb_state *v=(cb_state*)p;
 v->seen++;v->rcx=a;v->rdx=b;
 if(kind!=v->kind)return 0;
 *out=v->status;return 1;
}
int crt_after_initterm_e(mx_crt_state*);
int crt_after_initterm(mx_crt_state*,mx_cfg_memory*,int);
int smoke(void) {
 mx_cfg_region ranges[3]={{WINDOW,stack_window,256},
                          {STATE,state_bytes,4},{OWNER,owner_bytes,8}};
 mx_cfg_memory memory={ranges,3};
 for(unsigned k=0;k<sizeof(data)/sizeof(data[0]);k++){
  const fixture *f=&data[k];
  volatile uint8_t *p=stack_window,*a=state_bytes,*b=owner_bytes;
  for(unsigned j=0;j<256;j++)p[j]=0;
  for(unsigned j=0;j<4;j++)a[j]=0;
  for(unsigned j=0;j<8;j++)b[j]=0;
  uint32_t state=(uint32_t)f->initial_state;
  uint64_t owner=f->initial_owner;
  if(!mx_cfg_transfer(&memory,STATE,&state,4,1)||
     !mx_cfg_transfer(&memory,OWNER,&owner,8,1))return 10+k;
  mx_crt_state s={0};
  s.rip=f->site;s.rsp=SP;s.rax=f->rax;s.rbx=f->rbx;
  s.rcx=f->rcx;s.rdi=f->rdi;s.rsi=f->rsi;s.zf=(uint8_t)f->zf;
  uint64_t rdx=f->rdx;
  cb_state callback={0,(uint32_t)f->kind,(uint32_t)f->status,0,0};
  int status=mx_crt_invoke_init_thunk(&s,&memory,(uint32_t)f->kind,
       f->site,f->site+5U,rdx,synthetic,&callback);
  if(status!=MX_CRT_BRANCH_BOUNDARY||s.fault||
     s.imports!=1||callback.seen!=1||
     callback.rcx!=f->rcx||callback.rdx!=f->rdx)return 40+k;
  s.instructions=0;s.visited=0;
  status=f->kind==1U?crt_after_initterm_e(&s):
       crt_after_initterm(&s,&memory,1);
  if(status!=MX_CRT_BRANCH_BOUNDARY||s.fault)return 70+k;
  if(s.rax!=f->e_rax||s.rbx!=f->e_rbx||
     s.rcx!=f->e_rcx||rdx!=f->e_rdx||s.rdi!=f->e_rdi||
     s.rsi!=f->e_rsi)return 100+k;
  if(s.rsp!=f->e_rsp||s.rip!=f->e_rip||s.zf!=f->e_zf)return 140+k;
  if(s.visited!=f->e_visited||s.instructions!=f->e_steps)return 180+k;
  uint32_t state_out=0;uint64_t owner_out=0;
  if(!mx_cfg_transfer(&memory,STATE,&state_out,4,0)||
     !mx_cfg_transfer(&memory,OWNER,&owner_out,8,0))return 220+k;
  if(state_out!=f->e_state||owner_out!=f->e_owner)return 240+k;
  for(unsigned j=0;j<256;j++)
   if(stack_window[j]!=f->e_stack[j])return 260+k;
 }
 return 0;
}
#ifdef HOST
int main(void){return smoke();}
#endif
"""

def encode(rows):
    lines=[]
    for f,result,spec in rows:
        src=[f["kind"],BASE+spec["call_rva"],f["status"]]
        src += [f[k] for k in ("rax","rbx","rcx","rdx","rdi","rsi","zf",
                               "initial_state","initial_owner")]
        expected=[result[k] for k in OUT]
        stack="{"+",".join(str(x) for x in result["stack"])+"}"
        lines.append(" {"+",".join("UINT64_C("+str(v)+")" for v in src+expected)+","+stack+"},")
    return "\n".join(lines)

def checked(argv):
    p=subprocess.run(argv,capture_output=True,text=True)
    if p.returncode:
        raise RuntimeError("Original CRT import+continuation failed exit="+
                           str(p.returncode)+": "+(p.stderr or p.stdout)[-4000:])

def run(executable,output):
    pe=PE(executable)
    if hashlib.sha256(pe.b).hexdigest()!=SHA:
        raise RuntimeError("Original game executable revision changed")
    specs=decode_calls(pe)
    native_e,meta_e=after_initterm_e(pe.read_rva(AFTER_E,END_E-AFTER_E),AFTER_E)
    native_v,meta_v=after_initterm(pe.read_rva(AFTER_VOID,END_VOID-AFTER_VOID),AFTER_VOID)
    if (meta_e["decoded_original_instructions"]!=4 or
        meta_e["return_success_rva"]!=hex(JOIN_E) or
        meta_e["return_error_rva"]!=hex(ERROR_E) or
        meta_v["decoded_original_instructions"]!=5 or
        meta_v["join_rva"]!=hex(END_VOID) or
        meta_v["state_global_va"]!=hex(STATE) or
        meta_v["lock_owner_va"]!=hex(OWNER)):
        raise RuntimeError("Unexpected original post-CRT import continuation CFG")
    rows=[]
    for f in fixtures():
        spec=specs[f["kind"]-1]
        stop=END_E if f["kind"]==1 else END_VOID
        start=AFTER_E if f["kind"]==1 else AFTER_VOID
        rows.append((f,x64_original(pe,spec,f,start,stop),spec))
    if len(rows)!=32:
        raise RuntimeError("Missing complete MSVCR90 post-import branch matrix")
    with tempfile.TemporaryDirectory(prefix="private-original-msvcr90-post-call-") as td:
        root=Path(td)
        c1=root/"original-status.c";c2=root/"original-initialized.c"
        smoke=root/"guest-smoke.c"
        c1.write_text(native_e);c2.write_text(native_v)
        smoke.write_text(HARNESS.replace("WIN_ADDR",str(WIN))
                         .replace("SP_ADDR",str(SP))
                         .replace("STATE_ADDR",str(STATE))
                         .replace("OWNER_ADDR",str(OWNER))
                         .replace("__CASES__",encode(rows)))
        runtime=ROOT/"arm64-lab"/"runtime"
        host=root/"host"
        checked(["cc","-std=c11","-O2","-Wall","-Wextra","-Werror",
                 "-DHOST","-I"+str(runtime),str(c1),str(c2),
                 str(smoke),"-o",str(host)])
        checked([str(host)])
        arm=root/"native-post-crt-arm64.elf"
        checked(["clang","--target=aarch64-unknown-linux-gnu","-fuse-ld=lld",
                 "-nostdlib","-static","-ffreestanding","-fno-builtin",
                 "-fno-stack-protector","-O2","-std=c11",
                 "-I"+str(runtime),"-Wl,-e,smoke",
                 "-Wl,-z,max-page-size=4096","-Wl,--build-id=none",
                 str(c1),str(c2),str(smoke),"-o",str(arm)])
        result=execute_arm64_elf(arm,instruction_budget=650000,timeout_us=9000000)
    output.mkdir(parents=True,exist_ok=True)
    report={
      "original_game_SHA_verified":True,
      "original_import_thunk_and_post_return_combined":True,
      "x64_host_arm64_matched_fixtures":len(rows),
      "initterm_e_success_cases":2,
      "initterm_e_error_cases":14,
      "initterm_lock_retain_cases":8,
      "initterm_lock_release_cases":8,
      "synthetic_callback_only":True,
      "joined_with_preceding_49_instruction_CRT_region":False,
      "native_ARM64_exit":result["arm64_smoke_exit"],
      "full_game_boot":False
    }
    (output/"crt-post-msvcr90-arm64.json").write_text(json.dumps(report,indent=2)+"\n")
    summary="\n".join([
       "# Original MX Bikes CRT imports and post-return continuation","",
       "- Original CALL, import JMP thunk, synthetic RET, and following CRT x64 instructions: **32/32 native host / ARM64 matches**",
       "- _initterm_e: 16 status cases, success vs error EAX=255; stops before CRT continuation or exit",
       "- _initterm: 16 cases with CRT state=2, 8 recursive retains and 8 exclusive XCHG releases",
       "- Checked guest stack bytes, register state, EFLAGS ZF, global ownership and original postcall branch path",
       "- ARM64 ELF return: **"+str(result["arm64_smoke_exit"])+"**","",
       "**Synthetic callbacks, no genuine CRT initializer arrays. Independently joined import+postcall region, not yet attached to the 49-instruction earlier startup prefix.**",""])
    (output/"crt-post-msvcr90-arm64.md").write_text(summary)
    print(summary)

if __name__=="__main__":
    if len(sys.argv)!=3:
        raise SystemExit("usage: script.py /private/original.exe report-dir")
    run(Path(sys.argv[1]),Path(sys.argv[2]))
