#!/usr/bin/env python3
"""Private, independently callable config helper differential, never a game boot.

No Steam state, original game startup state, entitlement result or main
entrypoint is accessed. Original bytes remain in private temporary storage.
"""
import argparse, ctypes as C, hashlib, struct, subprocess, tempfile
from pathlib import Path
from unicorn import Uc, UC_ARCH_X86, UC_MODE_64, UC_HOOK_CODE
from unicorn import x86_const as x
from capstone import Cs,CS_ARCH_X86,CS_MODE_64,CS_OP_MEM
from mxbikes_native_cfg_lift import MEMORY_RUNTIME,EXTRA,decode_cfg,u,UC_REG,SHA
from mxbikes_native_slice_lift import ROOT,initial,CMP_FLAGS
from mxbikes_first_callee_emu import import_slots
from mxbikes_post_steam_static_successors import containing_unwind
from tools.pe_probe import PE

BASE=0x140000000
START=BASE+0x157890
END=BASE+0x15791c
RETURN=0x7500ff000
STACK=0x720000000
SP=STACK+0x808
DATA=0x730000000
OUT=DATA+0x100
SITE_NAMES={0x1578c2:"CreateFileA",0x1578dd:"GetFileTime",0x1578e6:"CloseHandle"}
HANDLE=0x730070000
STUB=0x7500fe000

def generate(pe):
    if containing_unwind(pe,0x1578c2)!=(START-BASE,END-BASE):
        raise ValueError("Original config helper boundary drift")
    decoder=Cs(CS_ARCH_X86,CS_MODE_64);decoder.detail=True
    slots={a:(dll.lower(),n) for a,dll,n in import_slots(pe)}
    code=pe.read_rva(START-BASE,END-START)
    calls=[]
    for i,(site,name) in enumerate(SITE_NAMES.items()):
        op=next(decoder.disasm(pe.read_rva(site,6),BASE+site))
        if (op.mnemonic!="call" or op.size!=6 or op.operands[0].type!=CS_OP_MEM
            or op.reg_name(op.operands[0].mem.base)!="rip" or op.operands[0].mem.index):
            raise ValueError("Config helper import instruction drift")
        slot=op.address+op.size+op.operands[0].mem.disp
        if slots.get(slot-BASE)!=("kernel32.dll",name):raise ValueError("Config import identity drift")
        calls.append((op.address,op.address+6,slot,name,STUB+i*16))
    body,_,nodes=decode_cfg([(START,code)],START,RETURN,
                    alternate_stops=tuple(a for a,_,_,_,_ in calls),
                    additional_entries=tuple(b for _,b,_,_,_ in calls))
    dispatch=[]
    for pc,ret,slot,name,_ in calls:
        original=int.from_bytes(pe.read_rva(slot-BASE,8),"little")
        dispatch.append(f'case {u(pc)}: if(load(s,{u(slot)},8)!={u(original)}||s->fault)return 0; next={u(ret)};name="{name}";break;')
    src=MEMORY_RUNTIME+EXTRA+body+r"""
#include "mxb_config_file.h"
#include <string.h>
int config_replay(uint64_t*regs,uint8_t*stack,uint8_t*data,uint64_t stamp){
 State state={0};State*s=&state;
 MXBConfigFile f={.last_write=stamp};
 if(!mxb_config_file_smoke()||
    !mxb_guest_map(&s->memory,STACK_VA,stack,4096,3)||
    !mxb_guest_map(&s->memory,DATA_VA,data,4096,3))return 0;
 for(unsigned i=0;i<16;i++)s->r[i]=regs[i];
 s->flags=regs[16];
 SLOT_MAPS
 Cursor c=lifted_begin();unsigned count=0;
 for(unsigned i=0;i<4;i++){
    if(lifted_resume(s,&c,128)||s->fault)return 0;
    if(c.pc==RETURN_VA){
        if(f.open||f.opens!=1||f.queries!=1||f.closes!=1)return 0;
        for(unsigned j=0;j<16;j++)regs[j]=s->r[j];
        regs[16]=s->flags;regs[17]=c.pc;regs[18]=c.steps+count;regs[19]=count;
        return 1;
    }
    uint64_t next=0;const char*name=0;
    switch(c.pc){DISPATCH default:return 0;}
    uint64_t sp=s->r[MXB_RSP];
    if((sp&15)||sp<8||!mxb_guest_check(&s->memory,sp-8,40,MXB_MEM_WRITE))return 0;
    store(s,sp-8,next,8);s->r[MXB_RSP]=sp-8;
    if(s->fault||!mxb_config_file_call(s,&f,name,next))return 0;
    c.pc=next;count++;
 }
 return 0;
}
"""
    maps=[]
    for i,(_,_,slot,_,_) in enumerate(calls):
        val=int.from_bytes(pe.read_rva(slot-BASE,8),"little")
        maps.append(f"uint64_t slot{i}={u(val)};if(!mxb_guest_map(&s->memory,{u(slot)},(uint8_t*)&slot{i},8,1))return 0;")
    for k,v in {"STACK_VA":u(STACK),"DATA_VA":u(DATA),"RETURN_VA":u(RETURN),
                "SLOT_MAPS":"\n".join(maps),"DISPATCH":"\n".join(dispatch)}.items():
        src=src.replace(k,v)
    return src,code,calls,len(nodes)

def oracle(code,calls,regs,stack,data,stamp):
    cpu=Uc(UC_ARCH_X86,UC_MODE_64)
    cpu.mem_map(START&~4095,4096);cpu.mem_write(START,code)
    cpu.mem_map(STACK,4096);cpu.mem_write(STACK,stack)
    cpu.mem_map(DATA,4096);cpu.mem_write(DATA,data)
    cpu.mem_map(STUB,4096)
    mapped=set()
    lookup={}
    for pc,ret,slot,name,stub in calls:
        page=slot&~4095
        if page not in mapped:cpu.mem_map(page,4096);mapped.add(page)
        cpu.mem_write(slot,struct.pack("<Q",stub))
        cpu.mem_write(stub,b"\xc3")
        lookup[stub]=(ret,name)
    for reg,val in zip(UC_REG,regs):cpu.reg_write(reg,val)
    cpu.reg_write(x.UC_X86_REG_EFLAGS,regs[16])
    called=[];count=0
    def hook(uc,pc,size,ctx):
        nonlocal count
        if pc not in lookup:count+=1;return
        ret,name=lookup[pc];sp=uc.reg_read(x.UC_X86_REG_RSP)
        a,b,c,d=(uc.reg_read(r) for r in (x.UC_X86_REG_RCX,x.UC_X86_REG_RDX,x.UC_X86_REG_R8,x.UC_X86_REG_R9))
        if sp%16!=8 or struct.unpack("<Q",uc.mem_read(sp,8))[0]!=ret:raise ValueError("Invalid original service stack")
        if name=="CreateFileA":
            creation,flags,template=struct.unpack("<III",b"\0"*12) # overwritten by exact original stack values
            creation=struct.unpack("<I",uc.mem_read(sp+40,4))[0]
            flags=struct.unpack("<I",uc.mem_read(sp+48,4))[0]
            template=struct.unpack("<Q",uc.mem_read(sp+56,8))[0]
            if bytes(uc.mem_read(a,9))!=b"core.ini\0" or (b,c,d,creation,flags,template)!=(0x80000000,1,0,3,0,0):raise ValueError("Original CreateFileA ABI changed")
            value=HANDLE
        elif name=="GetFileTime":
            if called!=["CreateFileA"] or (a,b,c)!=(HANDLE,0,0):raise ValueError("Original GetFileTime ABI changed")
            uc.mem_write(d,struct.pack("<Q",stamp));value=1
        elif name=="CloseHandle":
            if called!=["CreateFileA","GetFileTime"] or a!=HANDLE:raise ValueError("Original CloseHandle ABI changed")
            value=1
        else:raise ValueError("Unexpected import")
        called.append(name);uc.reg_write(x.UC_X86_REG_RAX,value)
    cpu.hook_add(UC_HOOK_CODE,hook)
    cpu.emu_start(START,RETURN,count=128)
    if cpu.reg_read(x.UC_X86_REG_RIP)!=RETURN or called!=list(SITE_NAMES.values()):
        raise ValueError("Original helper did not return")
    return ([cpu.reg_read(r) for r in UC_REG]+[cpu.reg_read(x.UC_X86_REG_EFLAGS),RETURN,count,len(called)],
            bytes(cpu.mem_read(STACK,4096)),bytes(cpu.mem_read(DATA,4096)))

def run(path,stamp):
    pe=PE(path)
    if hashlib.sha256(pe.b).hexdigest()!=SHA:raise ValueError("Owned original changed")
    if not 0<stamp<2**64:raise ValueError("Invalid private timestamp")
    src,code,calls,static=generate(pe)
    with tempfile.TemporaryDirectory(prefix="mxb-config-") as directory:
        d=Path(directory);(d/"config.c").write_text(src)
        sources=[ROOT/"runtime"/n for n in ("mxb_guest_memory.c","mxb_config_file.c")]
        lib=d/"config.so"
        subprocess.run(["cc","-shared","-fPIC","-O2","-I"+str(ROOT/"runtime"),str(d/"config.c"),*map(str,sources),"-o",str(lib)],check=True)
        replay=C.CDLL(str(lib)).config_replay
        replay.argtypes=[C.POINTER(C.c_uint64),C.c_void_p,C.c_void_p,C.c_uint64]
        for seed,t in enumerate((stamp,1,0xffffffff,0x100000000,0x123456789abcdef,0x7fffffffffffffff,0x8000000000000000,0xffffffffffffffff),1):
            regs,flags,_=initial(seed,[])
            regs[1]=OUT;regs[2]=DATA;regs[4]=SP
            before=regs+[flags,0,0,0]
            stack=bytearray([seed]*4096);struct.pack_into("<Q",stack,SP-STACK,RETURN)
            data=bytearray([0xa5]*4096);data[:9]=b"core.ini\0"
            expected,es,ed=oracle(code,calls,before,bytes(stack),bytes(data),t)
            rr=(C.c_uint64*20)(*before);ss=(C.c_uint8*4096).from_buffer_copy(stack);dd=(C.c_uint8*4096).from_buffer_copy(data)
            if not replay(rr,ss,dd,t):raise ValueError("Native config helper rejected case "+str(seed))
            actual=list(rr)
            if (actual[16]^expected[16])&CMP_FLAGS:raise ValueError("Config helper flags mismatch")
            actual[16]=expected[16]
            if actual!=expected or bytes(ss)!=es or bytes(dd)!=ed:
                raise ValueError("Config helper register, stack or data mismatch: "+str(seed))
            if int.from_bytes(ed[OUT-DATA:OUT-DATA+8],"little")!=t or expected[0]!=0:
                raise ValueError("Original file timestamp not returned")
        print(f"PASS: isolated original configuration metadata helper; 8 cases; {static} static nodes; {expected[18]} original dynamic steps; 3 modeled Win32 services; full GPR, flags, stack and data matched")
if __name__=="__main__":
    p=argparse.ArgumentParser();p.add_argument("--owned-exe",type=Path,required=True)
    p.add_argument("--filetime",type=Path,required=True);a=p.parse_args()
    run(a.owned_exe,int(a.filetime.read_text()))
