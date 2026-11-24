#!/usr/bin/env python3
"""Bounded direct-call/straight-line x64 -> portable C differential lifter.

Only audited instruction forms are accepted. No external imports, arbitrary
indirect control flow, authentication, or executable writes. Private original
code is decoded in a temporary directory; only aggregate metadata is printed.
"""
from __future__ import annotations
import argparse, hashlib, json, random, struct, subprocess, sys, tempfile
from pathlib import Path
from capstone import Cs, CS_ARCH_X86, CS_MODE_64, CS_OP_REG, CS_OP_IMM, CS_OP_MEM
from unicorn import Uc, UC_ARCH_X86, UC_MODE_64
from unicorn import x86_const as x
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT.parent))
from tools.import_aot_smoke import execute_arm64_elf

MASK=(1<<64)-1
PAGE=4096
STACK=0x720000000
RSP=STACK+0xc00
SHA="4ae7de3854b4d0a18271679fb57a1f2fdf0b21804417b85dd82055078ea123b6"
REGS=("rax","rcx","rdx","rbx","rsp","rbp","rsi","rdi",
      "r8","r9","r10","r11","r12","r13","r14","r15")
LOW=("eax","ecx","edx","ebx","esp","ebp","esi","edi",
     "r8d","r9d","r10d","r11d","r12d","r13d","r14d","r15d")
REG_INDEX={n:(i,64) for i,n in enumerate(REGS)}
REG_INDEX.update({n:(i,32) for i,n in enumerate(LOW)})
UC_REG=[getattr(x,"UC_X86_REG_"+n.upper()) for n in REGS]
FLAG_MASK=0x8d5 # CF PF AF ZF SF OF
CMP_FLAGS=MASK^0x10 # AF undefined by XOR

def u(n):return "UINT64_C(0x%x)"%(n&MASK)

def translate(windows,entry,stop):
    """Decode only reached instructions in caller-approved byte windows."""
    decoder=Cs(CS_ARCH_X86,CS_MODE_64);decoder.detail=True
    pc=entry; seen=set(); statements=[]; static_pages=set()
    def register(ins,op):
        name=ins.reg_name(op.reg)
        if name not in REG_INDEX:raise ValueError("Unsupported register "+name)
        idx,width=REG_INDEX[name]
        if op.size*8!=width:raise ValueError("Register width mismatch")
        return idx,width
    def address(ins,op):
        mem=op.mem
        if mem.segment or mem.index or not mem.base:raise ValueError("Complex memory operand")
        base=ins.reg_name(mem.base)
        if base=="rip":
            addr=(ins.address+ins.size+mem.disp)&MASK
            if ins.mnemonic!="lea":
                if addr%PAGE+op.size>PAGE:raise ValueError("Cross-page static operand")
                static_pages.add(addr&~(PAGE-1))
            return u(addr)
        if base not in REGS:raise ValueError("Unsupported memory base")
        return "(s.r[%d]+%s)"%(REGS.index(base),u(mem.disp))
    def read(ins,op):
        if op.type==CS_OP_REG:
            idx,width=register(ins,op)
            return "(s.r[%d]&%s)"%(idx,u((1<<width)-1))
        if op.type==CS_OP_IMM:return u(op.imm)
        if op.type==CS_OP_MEM and op.size in (4,8):
            return "load(&s,%s,%du)"%(address(ins,op),op.size)
        raise ValueError("Unsupported source operand")
    def write(ins,op,value):
        if op.type==CS_OP_REG:
            idx,width=register(ins,op)
            return "s.r[%d]=(%s)&%s;"%(idx,value,u((1<<width)-1))
        if op.type==CS_OP_MEM and op.size in (4,8):
            return "store(&s,%s,%s,%du);"%(address(ins,op),value,op.size)
        raise ValueError("Unsupported destination operand")
    while pc!=stop:
        if pc in seen or len(seen)>=256:raise ValueError("Repeated or excessive instructions")
        seen.add(pc)
        found=[(base,buf) for base,buf in windows if base<=pc<base+len(buf)]
        if len(found)!=1:raise ValueError("PC outside approved code windows")
        base,buf=found[0]
        ins=next(decoder.disasm(buf[pc-base:],pc,count=1),None)
        if ins is None:raise ValueError("Unable to decode")
        op=ins.operands; mn=ins.mnemonic; nxt=pc+ins.size
        if mn=="mov" and len(op)==2:
            statement=write(ins,op[0],read(ins,op[1]))
        elif mn=="lea" and len(op)==2 and op[0].type==CS_OP_REG and op[1].type==CS_OP_MEM:
            statement=write(ins,op[0],address(ins,op[1]))
        elif mn in ("xor","sub") and len(op)==2 and op[0].type==CS_OP_REG:
            _,width=register(ins,op[0]); lhs=read(ins,op[0]);rhs=read(ins,op[1])
            statement=write(ins,op[0],"%s_flags(&s,%s,%s,%du)"%(mn,lhs,rhs,width))
        elif mn=="push" and len(op)==1 and op[0].type==CS_OP_REG and op[0].size==8:
            statement="{uint64_t value=%s;s.r[4]-=8u;store(&s,s.r[4],value,8u);}"%read(ins,op[0])
        elif mn=="call" and len(op)==1 and op[0].type==CS_OP_IMM:
            statement="s.r[4]-=8u;store(&s,s.r[4],%s,8u);"%u(nxt)
            nxt=op[0].imm
        else:raise ValueError("Unsupported instruction form: "+mn)
        statements.append(statement+" if(s.fault)return 90;")
        pc=nxt
    return statements,sorted(static_pages),len(seen)

RUNTIME=r"""
#include <stdint.h>
#define PAGE 4096u
typedef struct {uint64_t r[16],flags;uint8_t mem[NP][PAGE];int fault;} State;
static const uint64_t bases[NP]=BASES;
static uint8_t *locate(State*s,uint64_t addr,unsigned size){
 for(unsigned p=0;p<NP;p++)
  if(addr>=bases[p]&&addr-bases[p]<=PAGE-size)return &s->mem[p][addr-bases[p]];
 s->fault=1;return 0;
}
static uint64_t load(State*s,uint64_t addr,unsigned size){
 uint8_t*p=locate(s,addr,size);uint64_t v=0;
 if(p)for(unsigned i=0;i<size;i++)v|=(uint64_t)p[i]<<(8u*i);
 return v;
}
static void store(State*s,uint64_t addr,uint64_t v,unsigned size){
 uint8_t*p=locate(s,addr,size);
 if(p)for(unsigned i=0;i<size;i++)p[i]=(uint8_t)(v>>(8u*i));
}
static uint64_t common_flags(uint64_t v,unsigned width){
 unsigned parity=0;for(unsigned i=0;i<8;i++)parity^=(v>>i)&1u;
 return (parity?0u:4u)|(v?0u:0x40u)|(((v>>(width-1u))&1u)?0x80u:0u);
}
static uint64_t xor_flags(State*s,uint64_t a,uint64_t b,unsigned width){
 uint64_t mask=width==32u?UINT64_C(0xffffffff):UINT64_MAX;
 uint64_t v=(a^b)&mask;
 s->flags=(s->flags&~UINT64_C(0x8c5))|common_flags(v,width);
 return v;
}
static uint64_t sub_flags(State*s,uint64_t a,uint64_t b,unsigned width){
 uint64_t mask=width==32u?UINT64_C(0xffffffff):UINT64_MAX;
 a&=mask;b&=mask;uint64_t v=(a-b)&mask;
 s->flags=(s->flags&~UINT64_C(0x8d5))|common_flags(v,width)|
   (a<b?1u:0u)|((a^b^v)&0x10u)|((((a^b)&(a^v))>>(width-1u))&1u?0x800u:0u);
 return v;
}
#ifdef MXB_FREESTANDING_TEST
void *memset(void *dst,int byte,unsigned long n){
 volatile unsigned char*p=dst;
 for(unsigned long i=0;i<n;i++)p[i]=(unsigned char)byte;
 return dst;
}
#endif
static uint64_t hash_page(const uint8_t*p){
 uint64_t h=UINT64_C(0xcbf29ce484222325);
 for(unsigned i=0;i<PAGE;i++)h=(h^p[i])*UINT64_C(0x100000001b3);
 return h;
}
"""
def hash_page(data):
    h=0xcbf29ce484222325
    for b in data:h=((h^b)*0x100000001b3)&MASK
    return h

def initial(seed,pages):
    rng=random.Random(seed)
    regs=[rng.getrandbits(64) for _ in REGS];regs[4]=RSP
    data={p:bytes((i*17+seed*31+(p>>12))&255 for i in range(PAGE)) for p in pages}
    return regs,0x202|(0x44 if seed%2 else 0),data

def original_reference(windows,entry,stop,pages,count,seed):
    regs,flags,data=initial(seed,pages)
    cpu=Uc(UC_ARCH_X86,UC_MODE_64)
    code_pages=set()
    for addr,blob in windows:
        for page in range(addr&~(PAGE-1),(addr+len(blob)+PAGE-1)&~(PAGE-1),PAGE):
            if page not in code_pages:cpu.mem_map(page,PAGE);code_pages.add(page)
        cpu.mem_write(addr,blob)
    if code_pages.intersection(pages):raise ValueError("Code/data pages overlap")
    for p in pages:cpu.mem_map(p,PAGE);cpu.mem_write(p,data[p])
    for r,v in zip(UC_REG,regs):cpu.reg_write(r,v)
    cpu.reg_write(x.UC_X86_REG_EFLAGS,flags)
    cpu.emu_start(entry,stop,count=count,timeout=2_000_000)
    if cpu.reg_read(x.UC_X86_REG_RIP)!=stop:raise ValueError("Original slice failed to reach stop")
    return ([cpu.reg_read(r) for r in UC_REG],cpu.reg_read(x.UC_X86_REG_EFLAGS),
            [hash_page(cpu.mem_read(p,PAGE)) for p in pages])

def fixture(windows,entry,stop,pages,statements,count):
    parts=[("#define NP %du\n#define BASES {%s}\n"%(len(pages),",".join(map(u,pages)))),RUNTIME,
           "int smoke(void){"]
    for seed in range(1,9):
        regs,flags,data=initial(seed,pages)
        out,of,hashes=original_reference(windows,entry,stop,pages,count,seed)
        parts.append("{State s={0};")
        for i,v in enumerate(regs):parts.append("s.r[%d]=%s;"%(i,u(v)))
        parts.append("s.flags=%s;"%u(flags))
        for i,p in enumerate(pages):
            parts.append("for(unsigned j=0;j<PAGE;j++)s.mem[%d][j]=(uint8_t)(j*17u+%du+%s);"%(i,seed*31,u(p>>12)))
        parts.extend(statements)
        for i,v in enumerate(out):parts.append("if(s.r[%d]!=%s)return %d;"%(i,u(v),10+i))
        parts.append("if((s.flags&%s)!=%s)return 40;"%(u(CMP_FLAGS),u(of&CMP_FLAGS)))
        for i,h in enumerate(hashes):parts.append("if(hash_page(s.mem[%d])!=%s)return %d;"%(i,u(h),50+i))
        parts.append("}")
    parts.append("return 0;}\n#ifdef HOST\nint main(void){return smoke();}\n#endif")
    return "\n".join(parts)

def compile_native(src, runtime_sources=()):
    with tempfile.TemporaryDirectory(prefix="mxb-slice-lift-") as td:
        p=Path(td); c=p/"slice.c";c.write_text(src)
        flags=["-O2","-std=c11","-Wall","-Wextra","-Werror","-Wno-unused-function","-I"+str(ROOT/"runtime")]
        sources=[str(ROOT/"runtime"/name) for name in runtime_sources]
        host=p/"host";arm=p/"arm.elf";ios=p/"ios.o"
        subprocess.run(["cc",*flags,"-DHOST",str(c),*sources,"-o",str(host)],check=True)
        subprocess.run([str(host)],check=True)
        subprocess.run(["clang","--target=aarch64-unknown-linux-gnu","-fuse-ld=lld",
            "-nostdlib","-static","-ffreestanding","-fno-builtin","-fno-stack-protector","-DMXB_FREESTANDING_TEST",
            *flags,"-Wl,-e,smoke","-Wl,-z,max-page-size=4096","-Wl,--build-id=none",
            str(c),*sources,"-o",str(arm)],check=True)
        execute_arm64_elf(arm,instruction_budget=6000000,timeout_us=15000000)
        subprocess.run(["clang","--target=arm64-apple-ios17.0","-ffreestanding",
                        *flags,"-c",str(c),"-o",str(ios)],check=True)
        if ios.read_bytes()[:4]!=b"\xcf\xfa\xed\xfe":raise ValueError("Not a Mach-O object")
        for i,source in enumerate(sources):
            obj=p/("runtime-%d.o"%i)
            subprocess.run(["clang","--target=arm64-apple-ios17.0","-ffreestanding",*flags,"-c",source,"-o",str(obj)],check=True)
            if obj.read_bytes()[:4]!=b"\xcf\xfa\xed\xfe":raise ValueError("Runtime is not Mach-O")

def source_input():
    # Purpose-built synthetic caller + helper; not original game bytes.
    base=0x10000000
    # mov edx,7; call +0xf6 (target base+0x100); helper: push rbx;
    # sub rsp,0x20; mov rax,rdx; xor rax,rsp; mov [rsp+8],rax; lea rcx,[rsp+8].
    a=bytes.fromhex("ba07000000 e8f6000000")
    b=bytes.fromhex("53 4883ec20 4889d0 4831e0 4889442408 488d4c2408")
    return [(base,a),(base+0x100,b)],base,base+0x100+len(b)

def owned_input(path):
    from tools.pe_probe import PE
    if hashlib.sha256(path.read_bytes()).hexdigest()!=SHA:raise ValueError("Wrong owned executable")
    pe=PE(path);base=pe.u64(pe.opt+24)
    if base!=0x140000000:raise ValueError("Unexpected image base")
    spans=((0x133f66,0x133f7b),(0x2a9ae0,0x2a9b0d),(0x2838f0,0x283945))
    return [(base+a,pe.read_rva(a,b-a)) for a,b in spans],base+spans[0][0],base+spans[-1][1]

def run(path=None):
    windows,entry,stop=owned_input(path) if path else source_input()
    statements,static_pages,count=translate(windows,entry,stop)
    pages=sorted(set(static_pages+[STACK]))
    if len(pages)>16:raise ValueError("Too many data pages")
    if path and count!=30:raise ValueError("Original instruction coverage changed: "+str(count))
    if not path and count!=8:raise ValueError("Synthetic instruction coverage changed")
    compile_native(fixture(windows,entry,stop,pages,statements,count))
    print(json.dumps({"mode":"private_owned_original" if path else "public_synthetic",
        "instructions_executed_and_lifted":count,"cases":8,"all_16_gpr_compared":True,
        "defined_flags_compared":True,"data_pages_compared":len(pages),
        "bytes_compared_per_case":len(pages)*PAGE,"host_native":"pass",
        "aarch64_execution":"pass","ios_arm64_macho_compile":"pass",
        "entry":hex(entry),"stop_before_call":hex(stop),
        "original_game_booted":False,"original_game_frame":False},indent=2))

if __name__=="__main__":
    p=argparse.ArgumentParser()
    g=p.add_mutually_exclusive_group(required=True)
    g.add_argument("--source-only",action="store_true")
    g.add_argument("--owned-exe",type=Path)
    run(p.parse_args().owned_exe)
