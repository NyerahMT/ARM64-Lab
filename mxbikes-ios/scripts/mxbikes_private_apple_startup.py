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
    table=0x321a88
    first=0x2ab234
    call=next(decoder.disasm(pe.read_rva(0x2ab0b6,5),0x2ab0b6))
    if call.mnemonic!="call" or call.operands[0].imm!=0x2ab948:raise ValueError("Unexpected table call")
    def check_import(site,mnemonic,name,library="msvcr90.dll"):
        ins=next(decoder.disasm(pe.read_rva(site,6),site))
        mem=ins.operands[0].mem
        if ins.mnemonic!=mnemonic or ins.size!=6 or ins.reg_name(mem.base)!="rip":raise ValueError(name)
        slot=ins.address+ins.size+mem.disp
        dll,symbol=slots[slot]
        if dll.lower()!=library or symbol!=name:raise ValueError(name)
        return slot
    walk_slot=check_import(0x2ab948,"jmp","_initterm_e")
    app_slot=check_import(0x2ab2a4,"call","__set_app_type")
    check_import(0x2ab2ae,"call","_encode_pointer")
    header=executable.read_bytes()[:pe.u32(pe.opt+60)]
    nt=struct.unpack_from("<I",header,60)[0]
    data_maps=[]
    def map_value(rva,data):
        index=len(data_maps)
        value=int.from_bytes(data,"little")
        data_maps.append(f"p->callback_metadata[{index}]={u(value)}; "
                         f"if(!mxb_guest_map(&memory,{u(base+rva)},(uint8_t *)&p->callback_metadata[{index}],{len(data)},1))return 0;")
    for rva,size in ((0,2),(60,4),(nt,4),(nt+24,2),(nt+0x84,4),(nt+0xf8,4)):
        map_value(rva,header[rva:rva+size])
    for rva in (table,table+8,table+16,walk_slot,app_slot):map_value(rva,pe.read_rva(rva,8))
    if struct.unpack("<QQQ",pe.read_rva(table,24))!=(0,base+first,base+0x2ab714):raise ValueError("Unexpected initializer table")
    callback=unit(pe.read_rva(first,0x2ab2a4-first),first,0x2ab2a4,"callback")
    app_tail=unit(pe.read_rva(0x2ab2aa,4),0x2ab2aa,0x2ab2ae,"app_tail")
    app_flag=base+0x2ab2a4+0x12cd78
    encode_slot=check_import(0x2ab2ae,"call","_encode_pointer")
    filter_slot=check_import(0x2ab71f,"call","SetUnhandledExceptionFilter","kernel32.dll")
    for rva,size in ((encode_slot,8),(filter_slot,8),(0x3928cc,4),(0x3928c8,4)):
        map_value(rva,pe.read_rva(rva,size))
    modes=0x760001000
    for i,(slot,name) in enumerate(((0x321500,"_fmode"),(0x3214f8,"_commode"))):
        if slots[slot][0].lower()!="msvcr90.dll" or slots[slot][1]!=name:raise ValueError(name)
        map_value(slot,struct.pack("<Q",modes+4*i))
    def region(name,spans,start,stop,alternates=(),register_calls=None):
        windows=[(base+a,pe.read_rva(a,b-a)) for a,b in spans]
        code,_,_=decode_cfg(windows,base+start,stop,alternate_stops=tuple(base+a for a in alternates),register_calls=register_calls)
        return code.replace("lifted_begin",name+"_begin").replace("lifted_resume",name+"_resume")
    # The authenticated PE has an empty local table and no custom locale/math
    # handler requests. Other paths stop explicitly before their dependencies.
    finish=region("finish",((0x2ab2b4,0x2ab319),(0x2ab7fc,0x2ab834),(0x2ab950,0x2ab953)),
                  0x2ab2b4,0x750001008,(0x2ab816,0x2ab2fa,0x2ab30c))
    filter_entry=unit(pe.read_rva(0x2ab714,11),0x2ab714,0x2ab71f,"filter_entry")
    filter_exit=region("filter_exit",((0x2ab725,0x2ab72c),),0x2ab725,0x75000100e)
    after_walk=region("after_walk",((0x2ab0bb,0x2ab0ec),),0x2ab0bb,base+0x2ab0ec,(0x2ab0bf,0x2ab0fb))
    plain_table=0x321a60
    plain_call=next(decoder.disasm(pe.read_rva(0x2ab0ec,5),0x2ab0ec))
    if plain_call.mnemonic!="call" or plain_call.operands[0].imm!=0x2ab942:
        raise ValueError("Unexpected void initializer call")
    plain_slot=check_import(0x2ab942,"jmp","_initterm")
    decode_slot=check_import(0x2ab744,"call","_decode_pointer")
    onexit_slot=check_import(0x2ab758,"call","_onexit")
    plain_targets=struct.unpack("<4Q",pe.read_rva(plain_table,32))
    if plain_targets!=(0,base+0x2aafc4,base+0x320770,base+0x320790):
        raise ValueError("Unexpected void initializer table")
    for rva in (plain_slot,decode_slot,onexit_slot,*range(plain_table,plain_table+32,8)):
        map_value(rva,pe.read_rva(rva,8))
    plain_entry=region("plain_entry",((0x2aafc4,0x2aafd4),(0x2ab7e4,0x2ab7ed),(0x2ab734,0x2ab744)),
                       0x2aafc4,base+0x2ab744)
    decoded=region("decoded",((0x2ab74a,0x2ab758),),0x2ab74a,base+0x2ab758,(0x2ab760,))
    registered=region("registered",((0x2ab75e,0x2ab760),(0x2ab7de,0x2ab7e4)),0x2ab75e,base+0x2ab7ed)
    args_slot=check_import(0x2ab00a,"call","__getmainargs")
    map_value(args_slot,pe.read_rva(args_slot,8))
    for addr,size in ((0x3d85b0,8),(0x3d8030,8),(0x3d9b10,24),(0x3de328,0x248),(0x3d8020,16),(0x3d8018,4)):
        if not zero_fill(base+addr,size):raise ValueError("Unexpected startup global initializer")
    map_value(0x3d85b0,bytes(8))
    args_entry=region("args_entry",((0x2ab7ed,0x2ab7fb),),0x2ab7ed,base+0x2aafd4)
    args_setup=region("args_setup",((0x2aafd4,0x2ab00a),),0x2aafd4,base+0x2ab00a)
    args_return=region("args_return",((0x2ab010,0x2ab01a),(0x2ab024,0x2ab029)),0x2ab010,0x750001108,(0x2ab01a,))
    constructor=region("constructor",((0x320770,0x320780),(0x2d2a70,0x2d2ad6),
        (0x3042b0,0x3042df),(0x309e20,0x309e4d),(0x30a490,0x30a4ab),
        (0x2dd590,0x2dd5ee),(0x30b144,0x30b1ab),(0x2abbd0,0x2abbd4),(0x2fcf40,0x2fcf8a)),
        0x320770,base+0x2e84c0,register_calls={base+0x30b17c:base+0x2abbd0})
    for rva in (0x3d85bc,0x3d85b8):
        if not zero_fill(base+rva,4):raise ValueError("Unexpected file-mode initializer")
        map_value(rva,bytes(4))
    runner=r"""
#include "mxb_owned_startup.h"
#include "mx_crt_services.h"
#include "mx_crt_process_services.h"
#include <string.h>
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
    /* Original CALL and IAT thunk enter the modeled MSVCR table walker. */
    if(load(&p->cpu,WALK_SLOT,8)!=WALK_VALUE || p->cpu.fault)return 0;
    uint64_t first_slot=p->cpu.r[MXB_RCX], end=p->cpu.r[MXB_RDX];
    if(first_slot!=TABLE_BEGIN || end!=TABLE_BEGIN+24)return 0;
    uint64_t target=0;
    for(uint64_t at=first_slot;at<end && !target;at+=8)target=load(&p->cpu,at,8);
    if(p->cpu.fault || target!=CALLBACK_PC)return 0;
    sp=p->cpu.r[MXB_RSP];
    if((sp&15u) || sp<56 || !mxb_guest_check(&p->cpu.memory,sp-56,56,MXB_MEM_WRITE))return 0;
    store(&p->cpu,sp-8,INIT_TABLE_PC+5,8);
    /* The modeled iterator reserves Win64 shadow space for its callback.
     * Its return address identifies the continuation inside the adapter. */
    store(&p->cpu,sp-56,WALK_CONT,8);
    p->cpu.r[MXB_RSP]=sp-56;
    c=callback_begin();
    if(callback_resume(&p->cpu,&c,64)!=0 || c.pc!=APP_CALL)return 0;
    p->instructions+=2u+c.steps;
    sp=p->cpu.r[MXB_RSP];
    if(load(&p->cpu,APP_SLOT,8)!=APP_VALUE || p->cpu.fault || (sp&15u) ||
       p->cpu.r[MXB_RCX]!=2 || !mxb_guest_check(&p->cpu.memory,sp-8,40,MXB_MEM_WRITE))return 0;
    store(&p->cpu,sp-8,APP_CALL+6,8);
    p->app_type=2;
    c=app_tail_begin();
    if(p->cpu.fault || app_tail_resume(&p->cpu,&c,1)!=0)return 0;
    p->instructions+=1u+c.steps;p->services+=1;p->pc=c.pc;
    if(load(&p->cpu,ENC_SLOT,8)!=ENC_VALUE || p->cpu.fault)return 0;
    store(&p->cpu,sp-8,ENC_RETURN,8);
    mx_crt_services crt={0};
    crt.pointer_key=load(&p->cpu,COOKIE_VA,8);
    if(!crt.pointer_key || p->cpu.fault)return 0;
    p->cpu.r[MXB_RAX]=mx_crt_encode_pointer(&crt,p->cpu.r[MXB_RCX]);
    if(!mxb_guest_map(&p->cpu.memory,MODES_VA,(uint8_t *)p->file_modes,8,3))return 0;
    c=finish_begin();
    if(finish_resume(&p->cpu,&c,128)!=0 || c.pc!=WALK_CONT || (uint32_t)p->cpu.r[MXB_RAX])return 0;
    p->instructions+=1u+c.steps;p->services++;
    if(load(&p->cpu,TABLE_BEGIN+16,8)!=FILTER_ENTRY || p->cpu.fault)return 0;
    sp=p->cpu.r[MXB_RSP]-8;
    store(&p->cpu,sp,WALK_CONT+6,8);p->cpu.r[MXB_RSP]=sp;
    c=filter_entry_begin();
    if(p->cpu.fault || filter_entry_resume(&p->cpu,&c,8)!=0)return 0;
    p->instructions+=c.steps;
    if(load(&p->cpu,FILTER_SLOT,8)!=FILTER_VALUE || p->cpu.fault)return 0;
    store(&p->cpu,p->cpu.r[MXB_RSP]-8,FILTER_RETURN,8);
    p->cpu.r[MXB_RAX]=p->exception_filter;
    p->exception_filter=p->cpu.r[MXB_RCX];
    c=filter_exit_begin();
    if(p->cpu.fault || filter_exit_resume(&p->cpu,&c,8)!=0 || (uint32_t)p->cpu.r[MXB_RAX])return 0;
    p->instructions+=1u+c.steps;p->services++;
    sp=p->cpu.r[MXB_RSP]+40;
    if(load(&p->cpu,sp,8)!=INIT_TABLE_PC+5 || p->cpu.fault)return 0;
    p->cpu.r[MXB_RSP]=sp+8;
    c=after_walk_begin();
    if(after_walk_resume(&p->cpu,&c,16)!=0 || c.pc!=PLAIN_TABLE_PC)return 0;
    p->pc=c.pc;p->instructions+=c.steps;p->services++;
    if(load(&p->cpu,VOID_SLOT,8)!=VOID_VALUE || p->cpu.r[MXB_RCX]!=VOID_BEGIN ||
       p->cpu.r[MXB_RDX]!=VOID_BEGIN+32 || load(&p->cpu,VOID_BEGIN,8) ||
       load(&p->cpu,VOID_BEGIN+8,8)!=VOID_FIRST || p->cpu.fault)return 0;
    sp=p->cpu.r[MXB_RSP];
    if((sp&15u) || sp<56 || !mxb_guest_check(&p->cpu.memory,sp-56,56,MXB_MEM_WRITE))return 0;
    store(&p->cpu,sp-8,PLAIN_TABLE_PC+5,8);
    store(&p->cpu,sp-56,VOID_CONT,8);p->cpu.r[MXB_RSP]=sp-56;
    c=plain_entry_begin();
    if(plain_entry_resume(&p->cpu,&c,32)!=0 || c.pc!=DECODE_CALL)return 0;
    p->instructions+=2u+c.steps;
    if(load(&p->cpu,DECODE_SLOT,8)!=DECODE_VALUE || p->cpu.fault)return 0;
    store(&p->cpu,p->cpu.r[MXB_RSP]-8,DECODE_CALL+6,8);
    p->cpu.r[MXB_RAX]=mx_crt_decode_pointer(&crt,p->cpu.r[MXB_RCX]);
    c=decoded_begin();
    if(decoded_resume(&p->cpu,&c,16)!=0 || c.pc!=ONEXIT_CALL)return 0;
    p->instructions+=1u+c.steps;p->services++;
    if(load(&p->cpu,ONEXIT_SLOT,8)!=ONEXIT_VALUE || p->cpu.fault)return 0;
    store(&p->cpu,p->cpu.r[MXB_RSP]-8,ONEXIT_CALL+6,8);
    p->cpu.r[MXB_RAX]=mx_crt_service_onexit(&crt,p->cpu.r[MXB_RCX]);
    if(crt.onexit_count!=1 || p->cpu.fault)return 0;
    p->first_exit_handler=crt.onexit[0];
    c=registered_begin();
    if(registered_resume(&p->cpu,&c,16)!=0 || c.pc!=REGISTER_RETURN)return 0;
    p->instructions+=1u+c.steps;p->services++;p->pc=c.pc;
    c=args_entry_begin();
    if(args_entry_resume(&p->cpu,&c,32)!=0)return 0;
    p->instructions+=c.steps;
    c=args_setup_begin();
    if(args_setup_resume(&p->cpu,&c,32)!=0 || c.pc!=ARGS_CALL)return 0;
    p->instructions+=c.steps;
    sp=p->cpu.r[MXB_RSP];
    if((sp&15u) || load(&p->cpu,ARGS_SLOT,8)!=ARGS_VALUE ||
       load(&p->cpu,sp+32,8)!=ARGS_INFO || p->cpu.fault)return 0;
    /* Supply the single virtual process name and an empty environment. */
    const uint64_t argv_cells[3]={ARGS_VA+24,0,0};
    memcpy(p->argument_block,argv_cells,sizeof(argv_cells));
    memcpy(p->argument_block+24,"mxbikes.exe",sizeof("mxbikes.exe"));
    if(!mxb_guest_map(&p->cpu.memory,ARGS_VA,p->argument_block,sizeof(p->argument_block),1))return 0;
    mx_cfg_region arg_regions[4]={{ARGS_VA,p->argument_block,sizeof(p->argument_block)}};
    const unsigned sizes[3]={4,8,8};
    for(unsigned i=0;i<3;i++){
        uint64_t out=p->cpu.r[i==0?MXB_RCX:i==1?MXB_RDX:MXB_R8];
        int found=0;
        for(unsigned j=0;j<p->cpu.memory.count;j++){
            const MXBGuestRegion *r=&p->cpu.memory.regions[j];
            if((r->permissions&3)!=3 || out<r->base || out-r->base>r->length ||
               sizes[i]>r->length-(out-r->base))continue;
            arg_regions[i+1]=(mx_cfg_region){out,r->bytes+(out-r->base),sizes[i]};
            found=1;break;
        }
        if(!found)return 0;
    }
    mx_cfg_memory arg_mem={arg_regions,4};
    mx_crt_process process_args={0};
    if(mx_crt_process_bind_args(&process_args,&arg_mem,1,ARGS_VA,ARGS_VA+16)!=1 ||
       mx_crt_process_getmainargs(&process_args,p->cpu.r[MXB_RCX],p->cpu.r[MXB_RDX],
          p->cpu.r[MXB_R8],(uint32_t)p->cpu.r[MXB_R9],&p->cpu.r[MXB_RAX])!=1)return 0;
    store(&p->cpu,sp-8,ARGS_CALL+6,8);
    c=args_return_begin();
    if(p->cpu.fault || args_return_resume(&p->cpu,&c,16)!=0 || c.pc!=VOID_CONT)return 0;
    p->instructions+=1u+c.steps;p->services++;
    if(load(&p->cpu,VOID_BEGIN+16,8)!=SECOND_PC || p->cpu.fault)return 0;
    sp=p->cpu.r[MXB_RSP]-8;
    store(&p->cpu,sp,VOID_CONT+6,8);p->cpu.r[MXB_RSP]=sp;
    c=constructor_begin();
    if(p->cpu.fault || constructor_resume(&p->cpu,&c,256)!=0 || c.pc!=SUBOBJECT_PC)return 0;
    p->pc=c.pc;p->instructions+=c.steps;
    return 1;
}
"""
    fields={"STARTUP_INFO_PC":base+startup_info_site,"STARTUP_RESUME":base+resume,"CRT_LOCK_VA":lock,"INIT_TABLE_PC":base+0x2ab0b6,"TEB_VA":teb,"LOCK_PC":base+0x2ab05b,"ENTRY_PC":base+entry,"CHILD_PC":base+callee,"RETURN_PC":base+entry+9,
            "FRONTIER_PC":base+frontier,"COOKIE_VA":base+0x3928a0}
    fields.update(TABLE_BEGIN=base+table,WALK_SLOT=base+walk_slot,WALK_VALUE=struct.unpack("<Q",pe.read_rva(walk_slot,8))[0],
                  CALLBACK_PC=base+first,APP_CALL=base+0x2ab2a4,APP_SLOT=base+app_slot,
                  APP_VALUE=struct.unpack("<Q",pe.read_rva(app_slot,8))[0],WALK_CONT=0x750001008)
    fields.update(ENC_SLOT=base+encode_slot,ENC_VALUE=struct.unpack("<Q",pe.read_rva(encode_slot,8))[0],ENC_RETURN=base+0x2ab2b4,
                  FILTER_SLOT=base+filter_slot,FILTER_VALUE=struct.unpack("<Q",pe.read_rva(filter_slot,8))[0],
                  FILTER_ENTRY=base+0x2ab714,FILTER_RETURN=base+0x2ab725,MODES_VA=modes,PLAIN_TABLE_PC=base+0x2ab0ec)
    fields.update(VOID_SLOT=base+plain_slot,VOID_BEGIN=base+plain_table,VOID_FIRST=plain_targets[1],
                  VOID_CONT=0x750001108,DECODE_CALL=base+0x2ab744,DECODE_SLOT=base+decode_slot,
                  ONEXIT_CALL=base+0x2ab758,ONEXIT_SLOT=base+onexit_slot,REGISTER_RETURN=base+0x2ab7ed)
    for name,slot in (("VOID_VALUE",plain_slot),("DECODE_VALUE",decode_slot),("ONEXIT_VALUE",onexit_slot)):
        fields[name]=int.from_bytes(pe.read_rva(slot,8),"little")
    fields.update(ARGS_CALL=base+0x2ab00a,ARGS_SLOT=base+args_slot,ARGS_VALUE=int.from_bytes(pe.read_rva(args_slot,8),"little"),
                  ARGS_INFO=base+0x3d8034,ARGS_VA=0x760002000,SECOND_PC=plain_targets[2],SUBOBJECT_PC=base+0x2e84c0)
    for name,value in fields.items():runner=runner.replace(name,u(value))
    runner=runner.replace("IAT_CHECKS","\n    ".join(checks))
    (destination/"mxb_private_startup.c").write_text(MEMORY_RUNTIME+EXTRA+prefix+tail+prologue+thread+guard+callback+app_tail+finish+filter_entry+filter_exit+after_walk+plain_entry+decoded+registered+args_entry+args_setup+args_return+constructor+child+runner)

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
        *mappings,*data_maps,
        *[f"if(!mxb_guest_map(&memory,{u(base+addr)},(uint8_t *){ptr},{size},3))return 0;"
          for addr,ptr,size in ((0x3d8018,"&p->argument_count",4),(0x3d8020,"p->argument_globals",24),
                                (0x3d9b10,"p->object_header",24),(0x3de328,"p->subobjects",0x248))],
        f"if(!mxb_guest_map(&memory,{u(base+0xe4adb0)},(uint8_t *)p->exit_bounds,16,3))return 0;",
        f"if(!mxb_guest_map(&memory,{u(app_flag)},(uint8_t *)&p->managed_app,4,3))return 0;",
        f"return mxb_owned_startup(p,&memory,{u(base+entry)});",
        "}",
    ]
    (destination/"mxb_launch.inc").write_text("\n".join(launcher)+"\n")
