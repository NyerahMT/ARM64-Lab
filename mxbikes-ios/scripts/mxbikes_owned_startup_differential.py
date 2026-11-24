"""Replay identical host service observations into original x64 and native process entry."""
import argparse
import ctypes as C
import struct
import subprocess
import tempfile
from pathlib import Path

from unicorn import Uc, UC_ARCH_X86, UC_MODE_64, UC_HOOK_CODE
from unicorn import x86_const as x
from mxbikes_native_cfg_lift import UC_REG, STACK
from mxbikes_native_slice_lift import ROOT
from mxbikes_private_apple_directory import prepare
from mxbikes_private_apple_startup import prepare_startup

BASE=0x140000000
COOKIE=BASE+0x3928a0
DEFAULT=0x2b992ddfa232
MASK=(1<<64)-1
FRONTIER=BASE+0x2ab02c

# The C bridge keeps the C process layout authoritative. Only the normalized
# register/stack snapshot and caller-owned input file cross the Python ABI.
BRIDGE=r"""
#include <stdlib.h>
#include "mxb_owned_startup.h"
#include "mxb_pe_guest_image.h"
#include "mx_import_registry.h"
extern int mxb_private_startup(MXBOwnedStartup *,const mx_import_runtime *);
static uint64_t mono(void *x){return ((uint64_t *)x)[0];}
static uint64_t wall(void *x){return ((uint64_t *)x)[1];}
static uint32_t pid(void *x){return (uint32_t)((uint64_t *)x)[2];}
static uint32_t tid(void *x){return (uint32_t)((uint64_t *)x)[3];}
static int write_bytes(void *m,uint64_t a,const uint8_t *p,uint32_t n){return mxb_guest_write(m,a,p,n);}
int replay(const uint8_t *file,size_t n,uint64_t *vals,uint64_t *regs,uint8_t *stack){
    MXBPEImage layout;MXBOwnedStartup p={0};
    if(!mxb_pe_plan(file,n,&layout))return 0;
    void *backing=malloc(layout.image_size);
    if(!backing)return 0;
    int ok=0;
    if(!mxb_pe_map(&p.cpu.memory,file,n,backing,layout.image_size,&layout) ||
       !mxb_guest_map(&p.cpu.memory,0x720000000ULL,p.stack,sizeof(p.stack),3) ||
       !mxb_guest_write(&p.cpu.memory,0x1403928a0ULL,vals+4,8))goto done;
    for(unsigned i=0;i<16;i++)p.cpu.r[i]=regs[i];
    p.cpu.flags=regs[16];p.pc=layout.image_base+layout.entry_rva;
    const mx_clock_source clock={vals,mono,wall,NULL};
    const mx_import_runtime runtime={&clock,write_bytes,&p.cpu.memory,vals,pid,tid};
    if(!mxb_private_startup(&p,&runtime))goto done;
    for(unsigned i=0;i<16;i++)regs[i]=p.cpu.r[i];
    regs[16]=p.cpu.flags;regs[17]=p.pc;regs[18]=p.instructions;regs[19]=p.services;
    if(!mxb_guest_read(&p.cpu.memory,0x1403928a0ULL,regs+20,16))goto done;
    for(unsigned i=0;i<sizeof(p.stack);i++)stack[i]=p.stack[i];
    ok=1;
done:
    free(backing);return ok;
}
"""


def run(path):
    import pefile
    raw=path.read_bytes()
    pe=pefile.PE(data=raw)
    mapped=pe.get_memory_mapped_image()
    with tempfile.TemporaryDirectory() as tmp:
        d=Path(tmp)
        prepare(path,d)
        prepare_startup(path,d)
        (d/"bridge.c").write_text(BRIDGE)
        runtime=ROOT/"runtime"
        common=ROOT.parent/"runtime"
        libpath=d/"entry.so"
        subprocess.run(["cc","-O2","-std=c11","-shared","-fPIC","-I"+str(runtime),"-I"+str(common),
                        str(d/"bridge.c"),str(d/"mxb_private_startup.c"),
                        *[str(runtime/file) for file in ("mxb_guest_memory.c","mxb_pe_guest_image.c")],
                        *[str(common/file) for file in ("mx_time_compat.c","mx_guest_imports.c","mx_import_registry.c")],
                        "-o",str(libpath)],check=True)
        replay=C.CDLL(str(libpath)).replay
        replay.argtypes=[C.c_void_p,C.c_size_t,C.POINTER(C.c_uint64),C.POINTER(C.c_uint64),C.c_void_p]
        for seed in range(8):
            mono=123456789000000+seed
            wall=1600000000000000000+1000*seed
            pid,tid=51+seed,99+seed
            filetime=wall//100+116444736000000000
            if seed==7:
                # Exercise the collision adjustment by choosing service observations
                # whose low 48 XOR bits reproduce the default security cookie.
                tick=mono//1000000 & 0xffffffff
                low=(DEFAULT ^ mono ^ tid ^ pid ^ tick) & ((1<<48)-1)
                filetime=(filetime & ~((1<<48)-1)) | low
                wall=(filetime-116444736000000000)*100
            cookie=DEFAULT if seed%2 or seed==0 else seed+0x1020304
            regs=[((seed+1)*(i+3)*0x1010101010101)&MASK for i in range(16)]
            regs[4]=STACK+0xc08
            flags=0x202 | (0x8d5 if seed%2 else 0)
            state=(C.c_uint64*22)(*regs,flags)
            vals=(C.c_uint64*5)(mono,wall,pid,tid,cookie)
            stack=(C.c_uint8*4096)()
            if not replay(raw,len(raw),vals,state,stack):raise ValueError("Native entry failed")
            cpu=Uc(UC_ARCH_X86,UC_MODE_64)
            cpu.mem_map(BASE,pe.OPTIONAL_HEADER.SizeOfImage)
            cpu.mem_write(BASE,mapped)
            cpu.mem_map(STACK,4096)
            cpu.mem_write(COOKIE,struct.pack("<Q",cookie))
            for reg,value in zip(UC_REG,regs):cpu.reg_write(reg,value)
            cpu.reg_write(x.UC_X86_REG_EFLAGS,flags)
            # Actual indirect CALL and RET run on x64. The five explicitly
            # modeled service bodies receive the same observations as native.
            service_page=0x750000000
            cpu.mem_map(service_page,4096)
            services={}
            names={"GetSystemTimeAsFileTime","GetCurrentThreadId","GetCurrentProcessId","GetTickCount","QueryPerformanceCounter"}
            for dll in pe.DIRECTORY_ENTRY_IMPORT:
                if dll.dll.lower()!=b"kernel32.dll":continue
                for symbol in dll.imports:
                    name=(symbol.name or b"").decode("ascii")
                    if name not in names:continue
                    pc=service_page+16*len(services);services[pc]=name
                    cpu.mem_write(symbol.address,struct.pack("<Q",pc));cpu.mem_write(pc,b"\xc3")
            if set(services.values())!=names:raise ValueError("Missing original IAT symbol")
            visited=[];called=[]
            def service(uc,pc,size,context):
                if pc not in services:
                    visited.append(pc)
                    return
                name=services[pc];called.append(name);dest=uc.reg_read(x.UC_X86_REG_RCX)
                if name=="GetSystemTimeAsFileTime":uc.mem_write(dest,struct.pack("<Q",filetime))
                elif name=="QueryPerformanceCounter":
                    uc.mem_write(dest,struct.pack("<Q",mono));uc.reg_write(x.UC_X86_REG_RAX,1)
                else:
                    result={"GetCurrentThreadId":tid,"GetCurrentProcessId":pid,"GetTickCount":mono//1000000 & 0xffffffff}
                    uc.reg_write(x.UC_X86_REG_RAX,result[name])
            cpu.hook_add(UC_HOOK_CODE,service)
            cpu.emu_start(BASE+pe.OPTIONAL_HEADER.AddressOfEntryPoint,FRONTIER,count=96)
            expected=[cpu.reg_read(reg) for reg in UC_REG]+[
                cpu.reg_read(x.UC_X86_REG_EFLAGS),cpu.reg_read(x.UC_X86_REG_RIP),len(visited),len(called),
                *struct.unpack("<QQ",cpu.mem_read(COOKIE,16))]
            if list(state)!=expected or bytes(stack)!=bytes(cpu.mem_read(STACK,4096)):
                raise ValueError(f"Original/native process state mismatch in case {seed}")
            if seed==7 and state[20]!=DEFAULT+1:raise ValueError("Collision path missed")
    print("PASS: 8 original-entry cases, 16 registers, flags, stack, cookie pair, service and instruction counts")


if __name__=="__main__":
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--owned-exe",type=Path,required=True)
    run(parser.parse_args().owned_exe)
