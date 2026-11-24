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
FRONTIER=BASE+0x2bbdcc

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
    uint64_t *fmode=(uint64_t *)((uint8_t *)backing+0x321500);
    uint64_t *commode=(uint64_t *)((uint8_t *)backing+0x3214f8);
    *fmode=0x760001000ULL;*commode=*fmode+4;
    uint32_t inputs[2]={(uint32_t)vals[5],(uint32_t)vals[6]};
    if(!mxb_guest_write(&p.cpu.memory,0x1403d85bcULL,inputs,4) ||
       !mxb_guest_write(&p.cpu.memory,0x1403d85b8ULL,inputs+1,4))goto done;
    uint8_t initial[0x4a0];
    for(unsigned i=0;i<sizeof(initial);i++)initial[i]=(uint8_t)(i+vals[6]);
    if(!mxb_guest_write(&p.cpu.memory,0x1403de328ULL,initial,sizeof(initial)))goto done;
    p.exception_filter=vals[7];
    p.file_modes[0]=0x11223344;p.file_modes[1]=0x55667788;
    for(unsigned i=0;i<16;i++)p.cpu.r[i]=regs[i];
    p.cpu.flags=regs[16];p.pc=layout.image_base+layout.entry_rva;
    for(unsigned i=0;i<16;i++){p.cpu.xmm[i][0]=regs[192+2*i];p.cpu.xmm[i][1]=regs[193+2*i];}
    const mx_clock_source clock={vals,mono,wall,NULL};
    const mx_import_runtime runtime={&clock,write_bytes,&p.cpu.memory,vals,pid,tid};
    if(!mxb_private_startup(&p,&runtime))goto done;
    for(unsigned i=0;i<16;i++)regs[i]=p.cpu.r[i];
    regs[16]=p.cpu.flags;regs[17]=p.pc;regs[18]=p.instructions;regs[19]=p.services;
    if(!mxb_guest_read(&p.cpu.memory,0x1403928a0ULL,regs+20,16))goto done;
    if(!mxb_guest_read(&p.cpu.memory,0x140e4ada8ULL,regs+22,8) ||
       !mxb_guest_read(&p.cpu.memory,0x140e4ada0ULL,regs+23,4))goto done;
    regs[24]=p.app_type;
    if(!mxb_guest_read(&p.cpu.memory,0x1403d801cULL,regs+25,4))goto done;
    if(!mxb_guest_read(&p.cpu.memory,0x140e4adb0ULL,regs+26,16))goto done;
    regs[28]=p.file_modes[0];regs[29]=p.file_modes[1];regs[30]=p.exception_filter;regs[31]=p.first_exit_handler;
    if(!mxb_guest_read(&p.cpu.memory,0x1403d8018ULL,regs+32,4) ||
       !mxb_guest_read(&p.cpu.memory,0x1403d8020ULL,regs+33,24) ||
       !mxb_guest_read(&p.cpu.memory,0x1403d9b10ULL,regs+36,24) ||
       !mxb_guest_read(&p.cpu.memory,0x760002000ULL,regs+39,40) ||
       !mxb_guest_read(&p.cpu.memory,0x1403de328ULL,regs+44,0x4a0))goto done;
    for(unsigned i=0;i<16;i++){regs[192+2*i]=p.cpu.xmm[i][0];regs[193+2*i]=p.cpu.xmm[i][1];}
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
            state=(C.c_uint64*224)(*regs,flags)
            vectors=[((0x102030405060708*(i+1)*(seed+1))&MASK) for i in range(32)]
            for i,value in enumerate(vectors):state[192+i]=value
            vals=(C.c_uint64*8)(mono,wall,pid,tid,cookie,seed*31,seed*17,seed*0x10000)
            stack=(C.c_uint8*4096)()
            if not replay(raw,len(raw),vals,state,stack):raise ValueError("Native entry failed")
            cpu=Uc(UC_ARCH_X86,UC_MODE_64)
            cpu.mem_map(BASE,pe.OPTIONAL_HEADER.SizeOfImage)
            cpu.mem_write(BASE,mapped)
            teb=0x760000000
            cpu.mem_map(teb,4096)
            cpu.mem_write(teb+8,struct.pack("<Q",STACK+4096))
            cpu.mem_write(teb+0x30,struct.pack("<Q",teb))
            cpu.reg_write(x.UC_X86_REG_GS_BASE,teb)
            cpu.mem_map(STACK,4096)
            cpu.mem_write(BASE+0x3d85bc,struct.pack("<I",vals[5]))
            cpu.mem_write(BASE+0x3d85b8,struct.pack("<I",vals[6]))
            cpu.mem_write(BASE+0x3de328,bytes((i+vals[6])&255 for i in range(0x4a0)))
            cpu.mem_write(COOKIE,struct.pack("<Q",cookie))
            for reg,value in zip(UC_REG,regs):cpu.reg_write(reg,value)
            cpu.reg_write(x.UC_X86_REG_EFLAGS,flags)
            for i in range(16):cpu.reg_write(getattr(x,f'UC_X86_REG_XMM{i}'),vectors[2*i]|(vectors[2*i+1]<<64))
            # Actual indirect CALL and RET run on x64. The five explicitly
            # modeled service bodies receive the same observations as native.
            service_page=0x750000000
            cpu.mem_map(service_page,4096)
            services={}
            names={"GetStartupInfoA","GetSystemTimeAsFileTime","GetCurrentThreadId","GetCurrentProcessId","GetTickCount","QueryPerformanceCounter"}
            for dll in pe.DIRECTORY_ENTRY_IMPORT:
                if dll.dll.lower()!=b"kernel32.dll":continue
                for symbol in dll.imports:
                    name=(symbol.name or b"").decode("ascii")
                    if name not in names:continue
                    pc=service_page+16*len(services);services[pc]=name
                    cpu.mem_write(symbol.address,struct.pack("<Q",pc));cpu.mem_write(pc,b"\xc3")
            if set(services.values())!=names:raise ValueError("Missing original IAT symbol")
            iterator=service_page+4096
            cpu.mem_map(iterator,4096)
            # Win64 shadow space, then a real x64 indirect call through slot 1.
            cpu.mem_write(iterator,bytes.fromhex("488d6424d8 ff5108"))
            cpu.mem_write(iterator+8,bytes.fromhex("ff15 72000000 488d642428 c3"))
            cpu.mem_map(0x760001000,4096)
            cpu.mem_write(0x760001000,struct.pack("<II",0x11223344,0x55667788))
            plain_iterator=iterator+0x100
            cpu.mem_write(plain_iterator,bytes.fromhex("488d6424d8 ff5108"))
            cpu.mem_write(plain_iterator+8,bytes.fromhex("ff15 72000000"))
            handlers=[]
            app_type=0;exception_filter=vals[7]
            for dll in pe.DIRECTORY_ENTRY_IMPORT:
                for symbol in dll.imports:
                    name=(symbol.name or b"").decode("ascii")
                    if dll.dll.lower()==b"msvcr90.dll":
                        if name=="_initterm":cpu.mem_write(symbol.address,struct.pack("<Q",plain_iterator))
                        if name=="_initterm_e":
                            cpu.mem_write(symbol.address,struct.pack("<Q",iterator))
                        if name in ("_fmode","_commode"):
                            cpu.mem_write(symbol.address,struct.pack("<Q",0x760001000+(4 if name=="_commode" else 0)))
                    if (dll.dll.lower(),name) in ((b"msvcr90.dll","__getmainargs"),(b"msvcr90.dll","_decode_pointer"),(b"msvcr90.dll","_onexit"),(b"msvcr90.dll","__set_app_type"),(b"msvcr90.dll","_encode_pointer"),(b"kernel32.dll","SetUnhandledExceptionFilter")):
                        pc=service_page+16*len(services)
                        services[pc]=name;cpu.mem_write(pc,b"\xc3")
                        cpu.mem_write(symbol.address,struct.pack("<Q",pc))
            visited=[];called=[]
            def service(uc,pc,size,context):
                nonlocal app_type,exception_filter
                if pc in (plain_iterator,plain_iterator+5,plain_iterator+8):
                    if pc==plain_iterator:
                        begin=uc.reg_read(x.UC_X86_REG_RCX);end=uc.reg_read(x.UC_X86_REG_RDX)
                        if end-begin!=32 or struct.unpack("<4Q",uc.mem_read(begin,32))!=(0,BASE+0x2aafc4,BASE+0x320770,BASE+0x320790):
                            raise ValueError("Original void initializer table mismatch")
                        cpu.mem_write(plain_iterator+0x80,bytes(uc.mem_read(begin+16,8)))
                    return
                if pc==iterator:
                    begin=uc.reg_read(x.UC_X86_REG_RCX);end=uc.reg_read(x.UC_X86_REG_RDX)
                    if end-begin!=24 or struct.unpack("<QQQ",uc.mem_read(begin,24))!=(0,BASE+0x2ab234,BASE+0x2ab714):
                        raise ValueError("Original callback table mismatch")
                    cpu.mem_write(iterator+0x80,bytes(uc.mem_read(begin+16,8)))
                    called.append("_initterm_e")
                    return
                if pc in (iterator+8,iterator+14) and uc.reg_read(x.UC_X86_REG_EAX)!=0:
                    raise ValueError("Original initializer failed")
                if iterator<=pc<iterator+20:return
                if pc not in services:
                    visited.append(pc)
                    return
                name=services[pc];called.append(name);dest=uc.reg_read(x.UC_X86_REG_RCX)
                if name=="__set_app_type":app_type=dest
                elif name=="_encode_pointer":
                    key=struct.unpack("<Q",uc.mem_read(COOKIE,8))[0]
                    v=dest^key
                    uc.reg_write(x.UC_X86_REG_RAX,((v<<17)|(v>>47))&MASK)
                elif name=="__getmainargs":
                    block=0x760002000
                    uc.mem_map(block,4096)
                    uc.mem_write(block,struct.pack("<3Q",block+24,0,0)+b"mxbikes.exe\0")
                    uc.mem_write(dest,struct.pack("<I",1))
                    uc.mem_write(uc.reg_read(x.UC_X86_REG_RDX),struct.pack("<Q",block))
                    uc.mem_write(uc.reg_read(x.UC_X86_REG_R8),struct.pack("<Q",block+16))
                    uc.reg_write(x.UC_X86_REG_RAX,0)
                elif name=="_decode_pointer":
                    key=struct.unpack("<Q",uc.mem_read(COOKIE,8))[0]
                    uc.reg_write(x.UC_X86_REG_RAX,(((dest>>17)|(dest<<47))&MASK)^key)
                elif name=="_onexit":
                    handlers.append(dest);uc.reg_write(x.UC_X86_REG_RAX,dest)
                elif name=="SetUnhandledExceptionFilter":
                    uc.reg_write(x.UC_X86_REG_RAX,exception_filter);exception_filter=dest
                elif name=="GetStartupInfoA":uc.mem_write(dest,struct.pack("<I",104)+bytes(100))
                elif name=="GetSystemTimeAsFileTime":uc.mem_write(dest,struct.pack("<Q",filetime))
                elif name=="QueryPerformanceCounter":
                    uc.mem_write(dest,struct.pack("<Q",mono));uc.reg_write(x.UC_X86_REG_RAX,1)
                else:
                    result={"GetCurrentThreadId":tid,"GetCurrentProcessId":pid,"GetTickCount":mono//1000000 & 0xffffffff}
                    uc.reg_write(x.UC_X86_REG_RAX,result[name])
            cpu.hook_add(UC_HOOK_CODE,service)
            cpu.emu_start(BASE+pe.OPTIONAL_HEADER.AddressOfEntryPoint,FRONTIER,count=1700)
            expected=[cpu.reg_read(reg) for reg in UC_REG]+[
                cpu.reg_read(x.UC_X86_REG_EFLAGS),cpu.reg_read(x.UC_X86_REG_RIP),len(visited),len(called),
                *struct.unpack("<QQ",cpu.mem_read(COOKIE,16)),
                *struct.unpack("<Q",cpu.mem_read(BASE+0xe4ada8,8)),*struct.unpack("<I",cpu.mem_read(BASE+0xe4ada0,4)),app_type,*struct.unpack("<I",cpu.mem_read(BASE+0x3d801c,4)),
                *struct.unpack("<QQ",cpu.mem_read(BASE+0xe4adb0,16)),*struct.unpack("<II",cpu.mem_read(0x760001000,8)),exception_filter,*handlers,
                *struct.unpack("<I",cpu.mem_read(BASE+0x3d8018,4)),*struct.unpack("<3Q",cpu.mem_read(BASE+0x3d8020,24)),
                *struct.unpack("<3Q",cpu.mem_read(BASE+0x3d9b10,24)),*struct.unpack("<5Q",cpu.mem_read(0x760002000,40)),
                *struct.unpack("<148Q",cpu.mem_read(BASE+0x3de328,0x4a0))]
            for i in range(16):
                vector=cpu.reg_read(getattr(x,f"UC_X86_REG_XMM{i}"));expected.extend((vector&MASK,vector>>64))
            if list(state)!=expected or bytes(stack)!=bytes(cpu.mem_read(STACK,4096)):
                differing=[i for i,(actual,wanted) in enumerate(zip(state,expected)) if actual!=wanted]
                stack_diff=sum(a!=b for a,b in zip(stack,cpu.mem_read(STACK,4096)))
                raise ValueError(f"Original/native process state mismatch case {seed}; fields={differing}; stack bytes={stack_diff}")
            if seed==7 and state[20]!=DEFAULT+1:raise ValueError("Collision path missed")
    print(f"PASS: 8 original-entry cases; frontier={hex(FRONTIER)}; last case instructions={state[18]}; services={state[19]}; 1184 object/global bytes; all GPRs, 16 XMM registers, flags and stack matched")


if __name__=="__main__":
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--owned-exe",type=Path,required=True)
    run(parser.parse_args().owned_exe)
