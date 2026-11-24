"""Generate a private Apple native entry wrapper and first CRT initializer."""
import hashlib
import struct
from pathlib import Path

from mxbikes_native_cfg_lift import EXTRA, MEMORY_RUNTIME, SHA, decode_cfg, u
from mxbikes_first_callee_emu import import_slots
from tools.crt_cfg_lift import translate_crt_cfg
from tools.entry_wrapper import decode_entry_wrapper
from tools.pe_probe import PE


def prepare_startup(executable: Path, destination: Path):
    if hashlib.sha256(executable.read_bytes()).hexdigest()!=SHA:
        raise ValueError("Wrong owned executable")
    pe=PE(executable)
    base=pe.u64(pe.opt+24)
    entry=pe.u32(pe.opt+16)
    wrapper=pe.read_rva(entry,18)
    control=decode_entry_wrapper(wrapper,entry)
    callee=int(control["direct_call_rva"],16)
    frontier=int(control["tail_jmp_rva"],16)
    if (entry,callee,frontier)!=(0x2ab31c,0x2ab954,0x2ab02c):
        raise ValueError("Unexpected startup wrapper")
    slots={r:(dll,name) for r,dll,name in import_slots(pe)}
    child,metadata=translate_crt_cfg(pe.read_rva(callee,179),callee,slots,base)
    if metadata["decoded_instructions"]!=39 or len(metadata["imports"])!=5:
        raise ValueError("Incomplete first initializer")
    checks=[]
    for item in metadata["imports"]:
        site=int(item["rva"],16)
        call=pe.read_rva(site,6)
        if call[:2]!=b"\xff\x15":raise ValueError("Expected original indirect CALL")
        slot=site+6+struct.unpack_from("<i",call,2)[0]
        value=struct.unpack("<Q",pe.read_rva(slot,8))[0]
        checks.append(f"if(load(&p->cpu,{u(base+slot)},8)!={u(value)} || p->cpu.fault)return 0;")
    def unit(code,address,stop,name):
        body,_,_=decode_cfg([(base+address,code)],base+address,base+stop)
        return body.replace("lifted_begin",name+"_begin").replace("lifted_resume",name+"_resume")
    prefix=unit(wrapper[:9],entry,callee,"entry")
    tail=unit(wrapper[9:],entry+9,frontier,"tail")
    runner=r"""
#include "mxb_owned_startup.h"
int mxb_private_startup(MXBOwnedStartup *p,const mx_import_runtime *runtime){
    if(!p || p->pc!=ENTRY_PC)return 0;
    IAT_CHECKS
    Cursor c=entry_begin();
    if(entry_resume(&p->cpu,&c,2)!=0 || c.pc!=CHILD_PC)return 0;
    mx_cfg_region regions[2];
    unsigned n=0;
    for(unsigned i=0;i<p->cpu.memory.count;i++){
        const MXBGuestRegion *r=&p->cpu.memory.regions[i];
        if((r->permissions & (MXB_MEM_READ|MXB_MEM_WRITE))!=(MXB_MEM_READ|MXB_MEM_WRITE))continue;
        /* Expose only the mapped cookie globals and our Win64 stack. */
        if(r->bytes!=p->stack && !(COOKIE_VA>=r->base && COOKIE_VA-r->base<r->length))continue;
        if(n==2)return 0;
        regions[n++]=(mx_cfg_region){r->base,r->bytes,r->length};
    }
    if(n!=2)return 0;
    mx_cfg_memory memory={regions,n};
    mx_crt_state s={0};
    s.rax=p->cpu.r[0];s.rcx=p->cpu.r[1];s.rbx=p->cpu.r[3];s.rsp=p->cpu.r[4];
    s.rsi=p->cpu.r[6];s.rdi=p->cpu.r[7];s.r11=p->cpu.r[11];s.rip=c.pc;
    s.zf=(p->cpu.flags & 0x40u)!=0;
    int rc;
    while((rc=lifted_crt_run(&s,&memory))==MX_CRT_PAUSED_IMPORT){
        if(s.imports>=5 || lifted_crt_resume_import(&s,runtime)!=1)return 0;
    }
    if(rc!=MX_CRT_RETURNED || s.rip!=RETURN_PC || s.fault)return 0;
    p->cpu.r[0]=s.rax;p->cpu.r[1]=s.rcx;p->cpu.r[3]=s.rbx;p->cpu.r[4]=s.rsp;
    p->cpu.r[6]=s.rsi;p->cpu.r[7]=s.rdi;p->cpu.r[11]=s.r11;
    /* The first instruction after RET is ADD RSP, imm; it defines all
     * arithmetic flags before the next guest frontier can observe them. */
    c=tail_begin();
    if(tail_resume(&p->cpu,&c,2)!=0 || c.pc!=FRONTIER_PC)return 0;
    p->pc=c.pc;p->services=s.imports;p->instructions=4u+s.instructions;
    return 1;
}
"""
    fields={"ENTRY_PC":base+entry,"CHILD_PC":base+callee,"RETURN_PC":base+entry+9,
            "FRONTIER_PC":base+frontier,"COOKIE_VA":base+0x3928a0}
    for name,value in fields.items():runner=runner.replace(name,u(value))
    runner=runner.replace("IAT_CHECKS","\n    ".join(checks))
    (destination/"mxb_private_startup.c").write_text(MEMORY_RUNTIME+EXTRA+prefix+tail+child+runner)
