#!/usr/bin/env python3
"""Independent original file-loader test, not game startup or authorization.

Fresh cache fixture: complete unencrypted configuration file loader and
cache insertion. Encrypted/package modes, existing caches and security
failure branches stop explicitly and are not treated as successful returns.
Private file bytes are not printed or committed.
"""
import argparse, ctypes as C, hashlib, struct, subprocess, tempfile
from pathlib import Path
import pefile
from unicorn import Uc,UC_ARCH_X86,UC_MODE_64,UC_HOOK_CODE
from unicorn import x86_const as x
from mxbikes_native_cfg_lift import MEMORY_RUNTIME,EXTRA,decode_cfg,u,UC_REG,SHA,owned_import_site
from mxbikes_native_slice_lift import ROOT,initial,CMP_FLAGS
from mxbikes_first_callee_emu import import_slots
from mxbikes_isolated_config_native import generate as metadata, BASE,STACK,DATA,OUT,HANDLE
from mxbikes_owned_file_crt import OwnedReadOnlyFile,ReadOnlyCRT,FILE_HANDLE
from tools.pe_probe import PE

START=BASE+0x157920
STOP=0x7500fc000
CACHE=BASE+0x396758
SP=STACK+0x1808
STACK_SIZE=0x4000
HEAP=0x740000000
HEAP_SIZE=0x1000
SPAN=((0x157920,0x1579ca),(0x157a8c,0x157a98),(0x157ae5,0x157b05),
      (0x157c50,0x157ce9),(0x157a66,0x157a70),(0x1584b6,0x158529),(0x158566,0x1585f3),
      (0x15c040,0x15c0a6),(0x15c10d,0x15c22c),(0x1598e0,0x159920),(0x159990,0x1599f9),(0x2aae60,0x2aae76),(0x157690,0x1576e1),(0x159720,0x159765),
      (0x15b4f0,0x15b507),(0x157890,0x15791c))
FILE_CALLS=((0x157af4,"fopen"),(0x157c59,"fseek"),(0x157c61,"ftell"),
            (0x15b4fd,"malloc"),(0x157c7d,"fseek"),(0x157c92,"fread"),
            (0x157c9a,"fclose"),(0x15c1aa,"memmove"),(0x15c1f2,"memset"),
            (0x1599c2,"memcpy"),(0x1599df,"memcpy"))
MASK=(1<<64)-1

def generate(pe):
    _,_,win32,_=metadata(pe)
    slots={BASE+r:(dll.lower(),name) for r,dll,name in import_slots(pe)}
    windows=[(BASE+a,pe.read_rva(a,b-a)) for a,b in SPAN]
    imports={};iat={};disk={};targets={};seen=set()
    for site,name in FILE_CALLS:
        target=targets.setdefault(name,0x7500fd000+16*len(targets))
        parts,slot,ret=owned_import_site(pe,BASE,slots,site,name,target)
        imports[target]=name
        for addr,raw in parts:
            if addr not in seen:windows.append((addr,raw));seen.add(addr)
        if slot not in iat:
            iat[slot]=(target,[])
            disk[slot]=int.from_bytes(pe.read_rva(slot-BASE,8),"little")
        if iat[slot][0]!=target:raise ValueError("Original IAT collision")
        iat[slot][1].append(ret)
    stops=(BASE+0x1579ca,BASE+0x157a98,BASE+0x157b05,BASE+0x157ce9,BASE+0x158529,BASE+0x15c0a6,BASE+0x2aae76,BASE+0x2aae7a,*[a for a,_,_,_,_ in win32])
    code,_,nodes=decode_cfg(windows,START,STOP,imports,iat,alternate_stops=stops,
                            disk_imports=disk,additional_entries=tuple(b for _,b,_,_,_ in win32))
    dispatch=[]
    for pc,ret,slot,name,_ in win32:
        original=int.from_bytes(pe.read_rva(slot-BASE,8),"little")
        dispatch.append(f'case {u(pc)}: if(load(s,{u(slot)},8)!={u(original)}||s->fault)goto done; next={u(ret)};name="{name}";break;')
    source=MEMORY_RUNTIME+EXTRA+code+r"""
#include "mxb_config_file.h"
#include <stdlib.h>
#include <string.h>
int replay(const uint8_t*exe,size_t exe_n,const uint8_t*file,size_t file_n,
           uint64_t stamp,uint64_t*regs,uint8_t*stack,uint8_t*data,uint8_t*heap){
 State state={0};State*s=&state;MXBPEImage image;
 MXBConfigFile f={.last_write=stamp};
 if(!mxb_pe_plan(exe,exe_n,&image))return 0;
 uint8_t*backing=malloc(image.image_size);if(!backing)return 0;
 int ok=0;
 if(!mxb_pe_map(&s->memory,exe,exe_n,backing,image.image_size,&image)||
    !mxb_guest_map(&s->memory,STACK_VA,stack,STACK_BYTES,3)||
    !mxb_guest_map(&s->memory,DATA_VA,data,4096,3)||
    !mxb_guest_heap_init(s,HEAP_VA,heap,4096)||
    !mxb_guest_file_bind(s,"core.ini",file,file_n))goto done;
 for(unsigned i=0;i<16;i++)s->r[i]=regs[i];
 s->flags=regs[16];
 Cursor c=lifted_begin();unsigned calls=0;
 for(unsigned i=0;i<4;i++){
    int rc=lifted_resume(s,&c,4096);
    regs[17]=c.pc;regs[18]=c.steps;regs[19]=rc;
    if(rc||s->fault)goto done;
    if(c.pc==STOP_VA){
        if(f.open||f.opens!=1||f.queries!=1||f.closes!=1||
           s->file.open||s->file.total_read!=file_n||
           s->file.opens!=1||s->file.seeks!=2||s->file.tells!=1||
           s->file.reads!=1||s->file.closes!=1||s->heap.count!=3||
           s->completed_crt_calls!=14||s->r[MXB_RAX]!=0||
           load(s,CACHE_VA,8)!=HEAP_VA+192u||s->fault)goto done;
        for(unsigned j=0;j<16;j++)regs[j]=s->r[j];
        regs[16]=s->flags;regs[17]=c.pc;
        regs[18]=c.steps-s->completed_crt_calls+calls;
        regs[19]=s->completed_crt_calls+calls;
        ok=1;goto done;
    }
    uint64_t next=0;const char*name=0;
    switch(c.pc){DISPATCH default:goto done;}
    uint64_t sp=s->r[MXB_RSP];
    if((sp&15)||sp<8||!mxb_guest_check(&s->memory,sp-8,40,MXB_MEM_WRITE))goto done;
    store(s,sp-8,next,8);s->r[MXB_RSP]=sp-8;
    if(s->fault||!mxb_config_file_call(s,&f,name,next))goto done;
    c.pc=next;calls++;
 }
 done:free(backing);return ok;
}
"""
    for k,v in {"STACK_VA":u(STACK),"STACK_BYTES":str(STACK_SIZE),"DATA_VA":u(DATA),
                "HEAP_VA":u(HEAP),"CACHE_VA":u(CACHE),"STOP_VA":u(STOP),"DISPATCH":"\n".join(dispatch)}.items():
        source=source.replace(k,v)
    services=[(slot,target,imports[target],tuple(rets)) for slot,(target,rets) in iat.items()]
    services.extend((slot,stub,name,(ret,)) for _,ret,slot,name,stub in win32)
    return source,services,len(nodes)

def oracle(pe,services,regs,stack,data,heap,blob,stamp):
    cpu=Uc(UC_ARCH_X86,UC_MODE_64)
    mapped=pefile.PE(data=pe.b).get_memory_mapped_image()
    size=pe.u32(pe.opt+56)
    cpu.mem_map(BASE,(size+4095)&~4095);cpu.mem_write(BASE,mapped)
    cpu.mem_map(STOP&~4095,4096)
    for base,raw in ((STACK,stack),(DATA,data),(HEAP,heap)):
        cpu.mem_map(base,len(raw));cpu.mem_write(base,raw)
    lookup={};pages=set()
    for slot,stub,name,rets in services:
        page=stub&~4095
        if page not in pages:cpu.mem_map(page,4096);pages.add(page)
        cpu.mem_write(slot,struct.pack("<Q",stub));cpu.mem_write(stub,b"\xc3")
        lookup[stub]=(name,rets)
    for reg,val in zip(UC_REG,regs):cpu.reg_write(reg,val)
    cpu.reg_write(x.UC_X86_REG_EFLAGS,regs[16])
    crt=ReadOnlyCRT(OwnedReadOnlyFile(blob,filename="core.ini",open=False))
    count=0;last=None;events=[];allocations=0;meta=[]
    def hook(uc,pc,size,ctx):
        nonlocal count,last,allocations
        if pc not in lookup:
            if pc in (BASE+0x157ce9,BASE+0x158529,BASE+0x15c0a6,BASE+0x2aae76,BASE+0x2aae7a):raise ValueError("Unsupported original config branch "+hex(pc))
            # Unicorn reports REP iterations as separate code-hook events.
            if pc!=last or pc not in (BASE+0x1576a4,BASE+0x1576c9):count+=1
            last=pc;return
        last=pc
        name,rets=lookup[pc]
        sp=uc.reg_read(x.UC_X86_REG_RSP)
        ret=struct.unpack("<Q",uc.mem_read(sp,8))[0]
        if sp%16!=8 or ret not in rets:raise ValueError("Original import ABI mismatch")
        a,b,c,d=(uc.reg_read(r) for r in (x.UC_X86_REG_RCX,x.UC_X86_REG_RDX,x.UC_X86_REG_R8,x.UC_X86_REG_R9))
        if name in ReadOnlyCRT.SUPPORTED:value=crt.dispatch(uc,name,a,b,c,d)
        elif name=="malloc":
            sizes=(len(blob),20,296)
            offsets=(0,192,224)
            if allocations>=len(sizes) or a!=sizes[allocations]:raise ValueError("Original allocation sequence changed")
            value=HEAP+offsets[allocations];allocations+=1
        elif name in ("memcpy","memmove","memset"):
            if c>4096:raise ValueError("Original memory transfer too large")
            if c:uc.mem_write(a,bytes([b&255])*c if name=="memset" else bytes(uc.mem_read(b,c)))
            value=a
        elif name=="CreateFileA":
            creation=struct.unpack("<I",uc.mem_read(sp+40,4))[0]
            flags=struct.unpack("<I",uc.mem_read(sp+48,4))[0]
            templ=struct.unpack("<Q",uc.mem_read(sp+56,8))[0]
            if bytes(uc.mem_read(a,9))!=b"core.ini\0" or (b,c,d,creation,flags,templ)!=(0x80000000,1,0,3,0,0):raise ValueError("Original metadata open ABI mismatch")
            value=HANDLE;meta.append(name)
        elif name=="GetFileTime":
            if meta!=["CreateFileA"] or (a,b,c)!=(HANDLE,0,0):raise ValueError("Original metadata query ABI mismatch")
            uc.mem_write(d,struct.pack("<Q",stamp));value=1;meta.append(name)
        elif name=="CloseHandle":
            if meta!=["CreateFileA","GetFileTime"] or a!=HANDLE:raise ValueError("Original metadata close ABI mismatch")
            value=1;meta.append(name)
        else:raise ValueError("Unsupported service")
        events.append(name);uc.reg_write(x.UC_X86_REG_RAX,value&MASK)
    cpu.hook_add(UC_HOOK_CODE,hook)
    cpu.emu_start(START,STOP,count=20000)
    if cpu.reg_read(x.UC_X86_REG_RIP)!=STOP:raise ValueError("Original config fixture did not reach read checkpoint")
    if events!=["fopen","fseek","ftell","malloc","fseek","fread","fclose","CreateFileA","GetFileTime","CloseHandle","malloc","memmove","malloc","memset","memcpy","memcpy","memcpy"]:
        raise ValueError("Original config service sequence changed")
    if crt.file.open or crt.bytes_returned!=len(blob) or allocations!=3:raise ValueError("Original config read incomplete")
    return ([cpu.reg_read(r) for r in UC_REG]+[cpu.reg_read(x.UC_X86_REG_EFLAGS),STOP,count,len(events)],
            bytes(cpu.mem_read(STACK,len(stack))),bytes(cpu.mem_read(DATA,len(data))),
            bytes(cpu.mem_read(HEAP,len(heap))))

def run(path,core,stamp):
    pe=PE(path);blob=core.read_bytes()
    if hashlib.sha256(pe.b).hexdigest()!=SHA or len(blob)!=179:raise ValueError("Private input changed")
    code,services,nodes=generate(pe)
    with tempfile.TemporaryDirectory(prefix="mxb-config-read-") as folder:
        p=Path(folder);(p/"read.c").write_text(code);lib=p/"read.so"
        sources=[ROOT/"runtime"/n for n in ("mxb_guest_memory.c","mxb_guest_crt.c","mxb_pe_guest_image.c","mxb_config_file.c")]
        subprocess.run(["cc","-shared","-fPIC","-O2","-I"+str(ROOT/"runtime"),str(p/"read.c"),*map(str,sources),"-o",str(lib)],check=True)
        replay=C.CDLL(str(lib)).replay
        replay.argtypes=[C.c_void_p,C.c_size_t,C.c_void_p,C.c_size_t,C.c_uint64,C.POINTER(C.c_uint64),C.c_void_p,C.c_void_p,C.c_void_p]
        for seed in range(1,9):
            regs,flags,_=initial(seed,[]);regs[1]=OUT;regs[2]=DATA;regs[4]=SP
            before=regs+[flags,0,0,0]
            stack=bytearray([seed])*STACK_SIZE
            struct.pack_into('<Q',stack,SP-STACK,STOP)
            data=bytearray([0xa5]*4096);data[:9]=b"core.ini\0"
            heap=bytes([0x77])*HEAP_SIZE
            expected,es,ed,eh=oracle(pe,services,before,bytes(stack),bytes(data),heap,blob,stamp)
            rr=(C.c_uint64*20)(*before)
            ss=(C.c_uint8*STACK_SIZE).from_buffer_copy(stack);dd=(C.c_uint8*4096).from_buffer_copy(data)
            hh=(C.c_uint8*HEAP_SIZE).from_buffer_copy(heap)
            if not replay(pe.b,len(pe.b),blob,len(blob),stamp,rr,ss,dd,hh):
                raise ValueError(f"Native config read failed case {seed} at {hex(rr[17])}, steps={rr[18]}, status={rr[19]}")
            actual=list(rr)
            if (actual[16]^expected[16])&CMP_FLAGS:raise ValueError("Config read flags mismatch")
            actual[16]=expected[16]
            if actual!=expected or bytes(ss)!=es or bytes(dd)!=ed or bytes(hh)!=eh:
                diff=[i for i,(a,b) in enumerate(zip(actual,expected)) if a!=b]
                raise ValueError(f"Config read mismatch registers={diff}, stack={bytes(ss)!=es}, data={bytes(dd)!=ed}, heap={bytes(hh)!=eh}")
            if eh[:len(blob)]!=blob or int.from_bytes(ed[OUT-DATA:OUT-DATA+4],"little")!=1:
                raise ValueError("Original file payload or returned cache ID differs")
        print(f"PASS: complete isolated original plain config loader and cache insertion; 8 cases; {nodes} static nodes; {expected[18]} dynamic steps; {expected[19]} services; {len(blob)} exact private bytes; full GPR, flags, stack and heap matched")
if __name__=="__main__":
    p=argparse.ArgumentParser();p.add_argument("--owned-exe",required=True,type=Path);p.add_argument("--core",required=True,type=Path);p.add_argument("--filetime",required=True,type=Path)
    a=p.parse_args();run(a.owned_exe,a.core,int(a.filetime.read_text()))
