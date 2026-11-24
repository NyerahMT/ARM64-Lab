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
    mappings=[]
    checks=[]
    startup_info_site=0x2ab043
    for item in [*metadata["imports"],{"rva":hex(startup_info_site)}]:
        site=int(item["rva"],16)
        call=pe.read_rva(site,6)
        if call[:2]!=b"\xff\x15":raise ValueError("Expected original indirect CALL")
        slot=site+6+struct.unpack_from("<i",call,2)[0]
        if site==startup_info_site and (slots[slot][0].lower(),slots[slot][1])!=("kernel32.dll","GetStartupInfoA"):
            raise ValueError("Unrecognized process startup service")
        value=struct.unpack("<Q",pe.read_rva(slot,8))[0]
        index=len(checks)
        mappings.append(f"p->import_values[{index}]={u(value)};")
        mappings.append(f"if(!mxb_guest_map(&memory,{u(base+slot)},(uint8_t *)&p->import_values[{index}],8,MXB_MEM_READ))return 0;")
        checks.append(f"if(load(&p->cpu,{u(base+slot)},8)!={u(value)} || p->cpu.fault)return 0;")
    def unit(code,address,stop,name,gs_base=None):
        body,_,_=decode_cfg([(base+address,code)],base+address,base+stop,gs_base=gs_base)
        return body.replace("lifted_begin",name+"_begin").replace("lifted_resume",name+"_resume")
    prefix=unit(wrapper[:9],entry,callee,"entry")
    tail=unit(wrapper[9:],entry+9,frontier,"tail")
    teb=0x760000000
    prologue=unit(pe.read_rva(frontier,startup_info_site-frontier),frontier,startup_info_site,"prologue")
    resume=startup_info_site+6
    thread=unit(pe.read_rva(resume,0x2ab05b-resume),resume,0x2ab05b,"thread",gs_base=teb)
    from capstone import Cs, CS_ARCH_X86, CS_MODE_64
    from capstone.x86 import X86_OP_MEM, X86_OP_REG
    decoder=Cs(CS_ARCH_X86,CS_MODE_64);decoder.detail=True
    cas=next(decoder.disasm(pe.read_rva(0x2ab05b,9),0x2ab05b))
    dest,src=cas.operands
    if not (cas.mnemonic=="lock cmpxchg" and cas.size==9 and dest.type==X86_OP_MEM and dest.size==8
            and cas.reg_name(dest.mem.base)=="rip" and not dest.mem.index and not dest.mem.segment
            and src.type==X86_OP_REG and cas.reg_name(src.reg)=="rdi"):
        raise ValueError("Original startup lock operation changed")
    lock=base+cas.address+cas.size+dest.mem.disp
    state_addr=base+0xe4ada0
    # These two initializers reside in the zero-filled portion of the PE.
    def zero_fill(address,size):
        rva=address-base
        return any(start+raw<=rva and rva+size<=start+virtual for _,virtual,start,raw,_,_ in pe.sections)
    if not zero_fill(lock,8) or not zero_fill(state_addr,4):raise ValueError("Unexpected CRT BSS layout")
    guard_start=0x2ab064
    guard,static_pages,_=decode_cfg([(base+guard_start,pe.read_rva(guard_start,0x2ab0b6-guard_start))],
        base+guard_start,base+0x2ab0b6,alternate_stops=(base+0x2ab066,base+0x2ab08a,base+0x2ab0c9))
    guard=guard.replace("lifted_begin","guard_begin").replace("lifted_resume","guard_resume")
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
    c=prologue_begin();
    if(prologue_resume(&p->cpu,&c,5)!=0 || c.pc!=STARTUP_INFO_PC)return 0;
    uint64_t sp=p->cpu.r[MXB_RSP], dst=p->cpu.r[MXB_RCX];
    /* GUI process defaults: cb=104, no inherited handles or window flags. */
    uint8_t info[104]={104};
    if((sp&15u) || sp<8 || dst<sp+32 ||
       !mxb_guest_check(&p->cpu.memory,sp-8,40,MXB_MEM_WRITE) ||
       !mxb_guest_check(&p->cpu.memory,dst,sizeof(info),MXB_MEM_WRITE))return 0;
    store(&p->cpu,sp-8,STARTUP_RESUME,8);
    if(p->cpu.fault || !mxb_guest_write(&p->cpu.memory,dst,info,sizeof(info)))return 0;
    p->thread_environment[1]=UINT64_C(0x720001000);
    p->thread_environment[6]=TEB_VA;
    if(!mxb_guest_map(&p->cpu.memory,TEB_VA,(uint8_t *)p->thread_environment,
                      sizeof(p->thread_environment),MXB_MEM_READ))return 0;
    c=thread_begin();
    if(thread_resume(&p->cpu,&c,8)!=0 || c.pc!=LOCK_PC)return 0;
    unsigned total=4u+s.instructions+5u+1u+c.steps;
    /* A single startup thread owns this process and all its guest memory. */
    uint64_t old=load(&p->cpu,CRT_LOCK_VA,8);
    if(p->cpu.fault || !mxb_guest_check(&p->cpu.memory,CRT_LOCK_VA,8,MXB_MEM_WRITE))return 0;
    sub_flags(&p->cpu,p->cpu.r[MXB_RAX],old,64);
    if(p->cpu.r[MXB_RAX]==old)store(&p->cpu,CRT_LOCK_VA,p->cpu.r[MXB_RDI],8);
    else p->cpu.r[MXB_RAX]=old;
    c=guard_begin();
    if(p->cpu.fault || guard_resume(&p->cpu,&c,32)!=0 || c.pc!=INIT_TABLE_PC)return 0;
    p->pc=c.pc;p->services=s.imports+1;p->instructions=total+1+c.steps;
    return 1;
}
"""
    fields={"STARTUP_INFO_PC":base+startup_info_site,"STARTUP_RESUME":base+resume,"CRT_LOCK_VA":lock,"INIT_TABLE_PC":base+0x2ab0b6,"TEB_VA":teb,"LOCK_PC":base+0x2ab05b,"ENTRY_PC":base+entry,"CHILD_PC":base+callee,"RETURN_PC":base+entry+9,
            "FRONTIER_PC":base+frontier,"COOKIE_VA":base+0x3928a0}
    for name,value in fields.items():runner=runner.replace(name,u(value))
    runner=runner.replace("IAT_CHECKS","\n    ".join(checks))
    (destination/"mxb_private_startup.c").write_text(MEMORY_RUNTIME+EXTRA+prefix+tail+prologue+thread+guard+child+runner)

    values=",".join(str(b) for b in pe.read_rva(0x3928a0,16))
    launcher=[
        "int mxb_native_launch(MXBOwnedStartup *p){",
        "if(!p || p->pc)return 0;",
        "MXBGuestMemory memory={0};",
        f"static const uint8_t initial[16]={{{values}}};",
        "for(unsigned i=0;i<16;i++)p->initial_globals[i]=initial[i];",
        f"if(!mxb_guest_map(&memory,{u(base+0x3928a0)},p->initial_globals,16,MXB_MEM_READ|MXB_MEM_WRITE))return 0;",
        f"if(!mxb_guest_map(&memory,{u(lock)},(uint8_t *)&p->crt_lock,8,3))return 0;",
        f"if(!mxb_guest_map(&memory,{u(state_addr)},(uint8_t *)&p->crt_phase,4,3))return 0;",
        *mappings,
        f"return mxb_owned_startup(p,&memory,{u(base+entry)});",
        "}",
    ]
    (destination/"mxb_launch.inc").write_text("\n".join(launcher)+"\n")
