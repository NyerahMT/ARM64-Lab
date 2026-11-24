"""Generate a private Apple native entry wrapper and first CRT initializer."""
import hashlib
import re
import struct
from pathlib import Path

from mxbikes_native_cfg_lift import EXTRA, MEMORY_RUNTIME, SHA, decode_cfg, u, owned_filename_input, FILENAME_GLOBAL
from mxbikes_main_joined_callee_native import inspect_original
from mxbikes_native_local_discovery import discover_pe
from mxbikes_private_apple_data import prepare_data
from mxbikes_first_callee_emu import import_slots
from tools.crt_cfg_lift import translate_crt_cfg
from tools.entry_wrapper import decode_entry_wrapper
from tools.pe_probe import PE


def prepare_startup(executable: Path, destination: Path):
    if hashlib.sha256(executable.read_bytes()).hexdigest()!=SHA:
        raise ValueError("Wrong owned executable")
    pe=PE(executable)
    prepare_data(pe,destination)
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
        if index>=48 or not 1<=len(data)<=8:raise ValueError('Startup metadata capacity')
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
    for addr,size in ((0x3d85b0,8),(0x3d8030,8),(0x3d9b10,24),(0x3de328,0x4a0),(0x3d8020,16),(0x3d8018,4)):
        if not zero_fill(base+addr,size):raise ValueError("Unexpected startup global initializer")
    map_value(0x3d85b0,bytes(8))
    args_entry=region("args_entry",((0x2ab7ed,0x2ab7fb),),0x2ab7ed,base+0x2aafd4)
    args_setup=region("args_setup",((0x2aafd4,0x2ab00a),),0x2aafd4,base+0x2ab00a)
    args_return=region("args_return",((0x2ab010,0x2ab01a),(0x2ab024,0x2ab029)),0x2ab010,0x750001108,(0x2ab01a,))
    # The next original constructor returns to its original parent call site.
    # Decode the parent CALL rather than assuming an arbitrary guest return.
    parent_calls=[ins for ins in decoder.disasm(pe.read_rva(0x2d2a70,0x66),0x2d2a70)
                  if ins.mnemonic=="call" and ins.operands[0].type==2
                  and ins.operands[0].imm==0x2e84c0]
    if len(parent_calls)!=1 or parent_calls[0].address+parent_calls[0].size!=0x2d2ad6:
        raise ValueError("Unexpected fourth constructor return")
    # The leaf without unwind metadata has a bounded decoding window. Only
    # reachable instructions are lifted; unknown forms still reject generation.
    constructor=region("constructor",((0x320770,0x320780),(0x2d2a70,0x2d2ad6),
        (0x3042b0,0x3042df),(0x309e20,0x309e4d),(0x30a490,0x30a4ab),
        (0x2dd590,0x2dd5ee),(0x30b144,0x30b1ab),(0x2abbd0,0x2abbd4),(0x2fcf40,0x2fcf8a)),
        0x320770,base+0x2e84c0,register_calls={base+0x30b17c:base+0x2abbd0})
    fourth=region("fourth",((0x2e84c0,0x2e8542),(0x30a490,0x30a4ab),
        (0x2dbe70,0x2dbe93),(0x30b144,0x30b1ab),(0x2abbd0,0x2abbd4)),
        0x2e84c0,base+0x2d2ad6,register_calls={base+0x30b17c:base+0x2abbd0})
    parent_tail=region("parent_tail",((0x2d2ad6,0x2d2b6a),(0x2dbe70,0x2dbe93)),
                       0x2d2ad6,base+0x2d2b6a)
    # Discover the remaining local constructor's complete direct-call closure
    # from original executable bytes. The following parent call is the stop.
    next_windows=discover_pe(pe,base,base+0x2d2b6a,base+0x2bbd90,max_nodes=256)
    next_code,_,_=decode_cfg(next_windows,base+0x2d2b6a,base+0x2bbd90)
    next_constructor=next_code.replace("lifted_begin","next_constructor_begin").replace("lifted_resume","next_constructor_resume")
    final_prefix=region("final_prefix",((0x2bbd90,0x2bbdcc),),0x2bbd90,base+0x2bbdcc)
    # Resolve the C++ virtual target from the exact original constructor's
    # RIP-relative vtable load and the final helper's memory CALL operand.
    vtable=next(decoder.disasm(pe.read_rva(0x2e84dc,7),0x2e84dc))
    virtual=next(decoder.disasm(pe.read_rva(0x2bbdcc,3),0x2bbdcc))
    vm=vtable.operands[1].mem;cm=virtual.operands[0].mem
    if (vtable.mnemonic!="lea" or vtable.reg_name(vm.base)!="rip" or vm.index
            or virtual.mnemonic!="call" or virtual.operands[0].type!=X86_OP_MEM
            or virtual.reg_name(cm.base)!="rax" or cm.index or cm.disp!=8):
        raise ValueError("Unexpected original virtual call identity")
    slot=vtable.address+vtable.size+vm.disp+cm.disp
    target=int.from_bytes(pe.read_rva(slot,8),"little")
    if not base<=target<base+(1<<32):raise ValueError("Original virtual target outside image")
    # The original table cell is read-only in the generated private app.
    map_value(slot,pe.read_rva(slot,8))
    print("Private original virtual constructor target RVA:",hex(target-base))
    virtual_windows=discover_pe(pe,base,base+0x2bbdcc,base+0x2bbdcf,
                               register_calls={base+0x2bbdcc:target},max_nodes=256)
    virtual_code,_,_=decode_cfg(virtual_windows,base+0x2bbdcc,base+0x2bbdcf,
                               register_calls={base+0x2bbdcc:target})
    virtual_body=virtual_code.replace("lifted_begin","virtual_body_begin").replace("lifted_resume","virtual_body_resume")
    # Complete both authentic returns, including the initializer wrapper.
    # The nonzero validation message path is an unresolved dependency, not
    # forced to succeed; only the original zero result continues.
    complete_second=region("complete_second",((0x2bbdcf,0x2bbdfc),),
                           0x2bbdcf,base+0x2d2bb9,(0x2bf540,))
    parent_return=region("parent_return",((0x2d2bb9,0x2d2bcd),),0x2d2bb9,base+0x320780)
    # The second and third void initializers both register actual original
    # destructor callbacks via the same onexit wrapper.
    second_exit=region("second_exit",((0x320780,0x320790),(0x2ab7e4,0x2ab7ed),(0x2ab734,0x2ab744)),
                       0x320780,base+0x2ab744)
    third_exit=region("third_exit",((0x320790,0x32079c),(0x2ab7e4,0x2ab7ed),(0x2ab734,0x2ab744)),
                      0x320790,base+0x2ab744)
    second_exit_return=region("second_exit_return",((0x2ab7ed,0x2ab7fb),),0x2ab7ed,0x75000110e)
    third_exit_return=region("third_exit_return",((0x2ab7ed,0x2ab7fb),),0x2ab7ed,0x750001114)
    # Finish the genuine CRT startup lock/state transition. A non-null TLS
    # callback requires an adapter and stops at its original branch.
    tls_addr=base+0xe4adc8
    if not zero_fill(tls_addr,8):raise ValueError("Unexpected TLS initializer pointer")
    release=region("release",((0x2ab0f1,0x2ab112),),0x2ab0f1,base+0x2ab131,(0x2ab112,))
    acmd=next(decoder.disasm(pe.read_rva(0x2ab131,7),0x2ab131))
    cmd_slot=acmd.address+acmd.size+acmd.operands[1].mem.disp
    if (acmd.mnemonic!="mov" or acmd.size!=7 or acmd.reg_name(acmd.operands[1].mem.base)!="rip"
            or cmd_slot!=0x3214d0 or slots[cmd_slot][0].lower()!="msvcr90.dll"
            or slots[cmd_slot][1]!="_acmdln"):
        raise ValueError("Unexpected original command-line data import")
    ascii_slot=check_import(0x2ab1ce,"call","_ismbblead")
    cmd_ptr=0x760003000
    map_value(cmd_slot,struct.pack("<Q",cmd_ptr))
    map_value(ascii_slot,pe.read_rva(ascii_slot,8))
    # Compile every local parser branch. Pause at the original CRT call and
    # resume at its actual return PC using the same persistent cursor.
    scan_windows=[(base+a,pe.read_rva(a,b-a)) for a,b in
                  ((0x2ab131,0x2ab18b),(0x2ab1b9,0x2ab1ce),(0x2ab1d4,0x2ab1ed))]
    scan_code,_,_=decode_cfg(scan_windows,base+0x2ab131,base+0x136710,
                            alternate_stops=(base+0x2ab1ce,),
                            additional_entries=(base+0x2ab1d4,))
    scan=scan_code.replace("lifted_begin","scan_begin").replace("lifted_resume","scan_resume")
    # Join the already verified original empty-command-line path to the same
    # entry CPU, stack and original BSS, rather than a separately seeded probe.
    main_layout,_,callee_code=inspect_original(pe)
    main_globals=[(main_layout[k],n) for k,n in
                  (("arg0_va",8),("arg1_va",8),("show_va",4),("callee_global0",8),("callee_global1",4))]
    def writable_initial(address,size):
        rva=address-base
        for _,virtual,start,raw,_,flags in pe.sections:
            if start<=rva and rva+size<=start+max(virtual,raw) and flags&0x80000000:
                n=min(size,max(0,start+raw-rva))
                return (pe.read_rva(rva,n) if n else b"")+bytes(size-n)
        raise ValueError("Game global outside writable original section: "+hex(rva))
    game_maps=[]
    for i,(address,size) in enumerate(main_globals):
        value=int.from_bytes(writable_initial(address,size),"little")
        game_maps.append(f"p->winmain_globals[{i}]={u(value)};")
        game_maps.append(f"if(!mxb_guest_map(&memory,{u(address)},(uint8_t *)&p->winmain_globals[{i}],{size},3))return 0;")
    filename_initial=writable_initial(FILENAME_GLOBAL,262)
    game_maps.append("static const uint8_t filename_initial[262]={"+",".join(map(str,filename_initial))+"};")
    game_maps.append("memcpy(p->filename_buffer,filename_initial,262);")
    game_maps.append(f"if(!mxb_guest_map(&memory,{u(FILENAME_GLOBAL)},p->filename_buffer,262,3))return 0;")
    # The private differential bridge uses the exact same original addresses.
    (destination/"mxb_game_startup_layout.h").write_text("\n".join(
        f"#define MXB_GAME_GLOBAL_{i} {u(address)}" for i,(address,_) in enumerate(main_globals))+"\n"+
        f"#define MXB_GAME_FILENAME {u(FILENAME_GLOBAL)}\n")
    main_windows=[(base+0x136710,pe.read_rva(0x136710,0x136756-0x136710)),
                  (base+0x136120,callee_code),(base+0x136207,pe.read_rva(0x136207,3))]
    main_code,_,_=decode_cfg(main_windows,base+0x136710,base+0x136756,
                            alternate_stops=(main_layout["fallthrough_va"],))
    main_body=main_code.replace("lifted_begin","main_body_begin").replace("lifted_resume","main_body_resume")
    module_slot=check_import(0x136756,"call","GetModuleFileNameA","kernel32.dll")
    cwd_slot=check_import(0x13676c,"call","SetCurrentDirectoryA","kernel32.dll")
    for rva in (module_slot,cwd_slot):map_value(rva,pe.read_rva(rva,8))
    filename_windows,filename_entry,filename_stop,_,filename_imports,filename_iat=owned_filename_input(executable)
    disk_slots={address:int.from_bytes(pe.read_rva(address-base,8),"little") for address in filename_iat}
    for address in sorted(filename_iat):map_value(address-base,pe.read_rva(address-base,8))
    filename_code,_,_=decode_cfg(filename_windows,filename_entry,filename_stop,
                                 filename_imports,filename_iat,disk_imports=disk_slots)
    filename_body=filename_code.replace("lifted_begin","filename_body_begin").replace("lifted_resume","filename_body_resume")
    cwd_prefix=unit(pe.read_rva(0x136769,3),0x136769,0x13676c,"cwd_prefix")
    game_handoff=unit(pe.read_rva(0x136772,0x136784-0x136772),0x136772,0x133e80,"game_handoff")
    init_body=unit(pe.read_rva(0x133e80,0x133efb-0x133e80),0x133e80,0x133640,"init_body")
    # The empty command-line path takes the original short branch. Keep
    # nonempty command-line and security-failure branches as explicit stops.
    subinit=region("subinit",((0x133640,0x13366e),(0x133c9a,0x133cb5),(0x2aae60,0x2aae76)),
                   0x133640,base+0x133efb,(0x13366e,0x2aae76,0x2aae7a))
    platform_handoff=unit(pe.read_rva(0x133efb,0x133f08-0x133efb),0x133efb,0x130580,"platform_handoff")
    platform_prefix=unit(pe.read_rva(0x130580,0x1305ae-0x130580),0x130580,0x2aaebc,"platform_prefix")
    check_import(0x2aaebc,"jmp","fopen")
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
    p->thread_environment[1]=UINT64_C(0x720000000)+MXB_STARTUP_STACK_SIZE;
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
    c=fourth_begin();
    if(fourth_resume(&p->cpu,&c,256)!=0 || c.pc!=FOURTH_RETURN || p->cpu.fault)return 0;
    p->pc=c.pc;p->instructions+=c.steps;
    c=parent_tail_begin();
    if(parent_tail_resume(&p->cpu,&c,128)!=0 || c.pc!=PARENT_TAIL_END || p->cpu.fault)return 0;
    p->pc=c.pc;p->instructions+=c.steps;
    c=next_constructor_begin();
    if(next_constructor_resume(&p->cpu,&c,512)!=0 || c.pc!=NEXT_CONSTRUCTOR_END || p->cpu.fault)return 0;
    p->pc=c.pc;p->instructions+=c.steps;
    c=final_prefix_begin();
    if(final_prefix_resume(&p->cpu,&c,32)!=0 || c.pc!=FINAL_PREFIX_END || p->cpu.fault)return 0;
    p->pc=c.pc;p->instructions+=c.steps;
    c=virtual_body_begin();
    if(virtual_body_resume(&p->cpu,&c,512)!=0 || c.pc!=VIRTUAL_RETURN || p->cpu.fault)return 0;
    p->pc=c.pc;p->instructions+=c.steps;
    c=complete_second_begin();
    int continuation_status=complete_second_resume(&p->cpu,&c,128);
    p->pc=c.pc;
    if(continuation_status||c.pc!=PARENT_RETURN_PC||p->cpu.fault)return 0;
    p->instructions+=c.steps;
    c=parent_return_begin();
    continuation_status=parent_return_resume(&p->cpu,&c,32);
    p->pc=c.pc;
    if(continuation_status||c.pc!=SECOND_EXIT_PC||p->cpu.fault)return 0;
    p->instructions+=c.steps;
    for(unsigned index=0;index<2;index++){
        c=index?third_exit_begin():second_exit_begin();
        int rc=index?third_exit_resume(&p->cpu,&c,32):second_exit_resume(&p->cpu,&c,32);
        p->pc=c.pc;
        if(rc||c.pc!=DECODE_CALL||p->cpu.fault)return 0;
        p->instructions+=c.steps;
        if(load(&p->cpu,DECODE_SLOT,8)!=DECODE_VALUE||p->cpu.fault)return 0;
        store(&p->cpu,p->cpu.r[MXB_RSP]-8,DECODE_CALL+6,8);
        p->cpu.r[MXB_RAX]=mx_crt_decode_pointer(&crt,p->cpu.r[MXB_RCX]);
        c=decoded_begin();
        if(decoded_resume(&p->cpu,&c,16)!=0||c.pc!=ONEXIT_CALL||p->cpu.fault)return 0;
        p->instructions+=1u+c.steps;p->services++;
        if(load(&p->cpu,ONEXIT_SLOT,8)!=ONEXIT_VALUE||p->cpu.fault)return 0;
        store(&p->cpu,p->cpu.r[MXB_RSP]-8,ONEXIT_CALL+6,8);
        p->cpu.r[MXB_RAX]=mx_crt_service_onexit(&crt,p->cpu.r[MXB_RCX]);
        if(crt.onexit_count!=index+2||p->cpu.fault)return 0;
        p->other_exit_handlers[index]=crt.onexit[index+1];
        c=registered_begin();
        if(registered_resume(&p->cpu,&c,16)!=0||c.pc!=REGISTER_RETURN||p->cpu.fault)return 0;
        p->instructions+=1u+c.steps;p->services++;
        c=index?third_exit_return_begin():second_exit_return_begin();
        rc=index?third_exit_return_resume(&p->cpu,&c,16):second_exit_return_resume(&p->cpu,&c,16);
        p->pc=c.pc;
        if(rc||c.pc!=VOID_CONT+6u*(index+1u)||p->cpu.fault)return 0;
        p->instructions+=c.steps;
        if(!index){
            if(load(&p->cpu,VOID_BEGIN+24,8)!=THIRD_PC||p->cpu.fault)return 0;
            sp=p->cpu.r[MXB_RSP];
            if((sp&15u)||sp<8||!mxb_guest_check(&p->cpu.memory,sp-8,40,MXB_MEM_WRITE))return 0;
            store(&p->cpu,sp-8,VOID_CONT+12,8);p->cpu.r[MXB_RSP]=sp-8;
            p->pc=THIRD_PC;
        }
    }
    sp=p->cpu.r[MXB_RSP]+40;
    if(load(&p->cpu,sp,8)!=PLAIN_TABLE_PC+5||p->cpu.fault)return 0;
    p->cpu.r[MXB_RSP]=sp+8;
    p->pc=PLAIN_TABLE_PC+5;p->services++;
    c=release_begin();
    continuation_status=release_resume(&p->cpu,&c,32);p->pc=c.pc;
    if(continuation_status||c.pc!=CMDLINE_PC||p->cpu.fault)return 0;
    p->instructions+=c.steps;
    p->command_line_ptr=ARGS_VA+24;
    if(!mxb_guest_map(&p->cpu.memory,CMD_PTR_VA,(uint8_t *)&p->command_line_ptr,8,1))return 0;
    c=scan_begin();
    for(unsigned calls=0;calls<128;calls++){
        int rc=scan_resume(&p->cpu,&c,1024);p->pc=c.pc;
        if(rc||p->cpu.fault)return 0;
        if(c.pc==WINMAIN_PC){
            p->instructions+=c.steps;
            if(p->cpu.r[MXB_RCX]!=IMAGE_BASE||p->cpu.r[MXB_RDX]!=0||
               p->cpu.r[MXB_R8]!=ARGS_VA+35||p->cpu.r[MXB_R9]!=10)return 0;
            break;
        }
        if(c.pc!=ASCII_CALL||load(&p->cpu,ASCII_SLOT,8)!=ASCII_VALUE||
           p->cpu.fault||p->cpu.r[MXB_RCX]>127)return 0;
        /* C-locale ASCII characters are not multibyte lead bytes. No unknown
         * non-ASCII code page is silently accepted. The original CALL/RET
         * return slot is retained in guest stack memory. */
        sp=p->cpu.r[MXB_RSP];
        if((sp&15u)||sp<8||!mxb_guest_check(&p->cpu.memory,sp-8,40,MXB_MEM_WRITE))return 0;
        store(&p->cpu,sp-8,ASCII_RETURN,8);
        if(p->cpu.fault)return 0;
        p->cpu.r[MXB_RAX]=0;
        p->instructions++;p->services++;
        c.pc=ASCII_RETURN;
    }
    if(p->pc!=WINMAIN_PC)return 0;
    c=main_body_begin();
    continuation_status=main_body_resume(&p->cpu,&c,128);p->pc=c.pc;
    if(continuation_status||c.pc!=MODULE_CALL||p->cpu.fault)return 0;
    p->instructions+=c.steps;
    /* A virtual install path, not an executable launched on iOS. */
    static const char module_path[]="C:\\MXBikes\\mxbikes.exe";
    static const char directory[]="C:\\MXBikes\\";
    sp=p->cpu.r[MXB_RSP];
    uint64_t out=p->cpu.r[MXB_RDX];
    if(load(&p->cpu,MODULE_SLOT,8)!=MODULE_VALUE||p->cpu.fault||
       p->cpu.r[MXB_RCX]!=0||p->cpu.r[MXB_R8]!=260||out!=sp+0x140||
       (sp&15u)||sp<8||!mxb_guest_check(&p->cpu.memory,sp-8,40,MXB_MEM_WRITE)||
       !mxb_guest_check(&p->cpu.memory,out,260,MXB_MEM_WRITE))return 0;
    store(&p->cpu,sp-8,MODULE_RETURN,8);
    if(p->cpu.fault||!mxb_guest_write(&p->cpu.memory,out,module_path,sizeof(module_path)))return 0;
    p->cpu.r[MXB_RAX]=sizeof(module_path)-1u;
    p->instructions++;p->services++;
    uint64_t before=p->cpu.completed_crt_calls;
    c=filename_body_begin();
    continuation_status=filename_body_resume(&p->cpu,&c,1024);p->pc=c.pc;
    if(continuation_status||c.pc!=FILENAME_RETURN||p->cpu.fault||
       p->cpu.r[MXB_RAX]!=FILENAME_VA)return 0;
    uint64_t calls=p->cpu.completed_crt_calls-before;
    if(calls!=1u||calls>c.steps)return 0;
    p->instructions+=c.steps-(unsigned)calls;p->services+=(unsigned)calls;
    c=cwd_prefix_begin();
    continuation_status=cwd_prefix_resume(&p->cpu,&c,4);p->pc=c.pc;
    if(continuation_status||c.pc!=CWD_CALL||p->cpu.fault)return 0;
    p->instructions+=c.steps;
    char result[sizeof(directory)];
    if(load(&p->cpu,CWD_SLOT,8)!=CWD_VALUE||p->cpu.fault||
       p->cpu.r[MXB_RCX]!=FILENAME_VA||
       !mxb_guest_read(&p->cpu.memory,FILENAME_VA,result,sizeof(result))||
       memcmp(result,directory,sizeof(result)))return 0;
    sp=p->cpu.r[MXB_RSP];
    if((sp&15u)||sp<8||!mxb_guest_check(&p->cpu.memory,sp-8,40,MXB_MEM_WRITE))return 0;
    /* This directory is the declared virtual install root. No host chdir
     * or entitlement result is performed; future VFS opens use this root. */
    memcpy(p->current_directory,result,sizeof(result));
    store(&p->cpu,sp-8,CWD_RETURN,8);
    if(p->cpu.fault)return 0;
    p->cpu.r[MXB_RAX]=1;
    p->instructions++;p->services++;
    c=game_handoff_begin();
    continuation_status=game_handoff_resume(&p->cpu,&c,16);p->pc=c.pc;
    if(continuation_status||c.pc!=GAME_INIT_PC||p->cpu.fault)return 0;
    p->instructions+=c.steps;
    c=init_body_begin();
    continuation_status=init_body_resume(&p->cpu,&c,64);p->pc=c.pc;
    if(continuation_status||c.pc!=GAME_SUBINIT_PC||p->cpu.fault)return 0;
    p->instructions+=c.steps;
    c=subinit_begin();
    continuation_status=subinit_resume(&p->cpu,&c,64);p->pc=c.pc;
    if(continuation_status||c.pc!=GAME_SUBINIT_RETURN||p->cpu.fault)return 0;
    p->instructions+=c.steps;
    c=platform_handoff_begin();
    continuation_status=platform_handoff_resume(&p->cpu,&c,16);p->pc=c.pc;
    if(continuation_status||c.pc!=PLATFORM_INIT_PC||p->cpu.fault)return 0;
    p->instructions+=c.steps;
    c=platform_prefix_begin();
    continuation_status=platform_prefix_resume(&p->cpu,&c,16);p->pc=c.pc;
    if(continuation_status||c.pc!=FOPEN_THUNK_PC||p->cpu.fault)return 0;
    p->instructions+=c.steps;
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
                  ARGS_INFO=base+0x3d8034,ARGS_VA=0x760002000,SECOND_PC=plain_targets[2],SUBOBJECT_PC=base+0x2e84c0,FOURTH_RETURN=base+0x2d2ad6,PARENT_TAIL_END=base+0x2d2b6a,NEXT_CONSTRUCTOR_END=base+0x2bbd90,FINAL_PREFIX_END=base+0x2bbdcc,VIRTUAL_RETURN=base+0x2bbdcf,THIRD_PC=plain_targets[3],PARENT_RETURN_PC=base+0x2d2bb9,SECOND_EXIT_PC=base+0x320780,CMDLINE_PC=base+0x2ab131,CMD_PTR_VA=cmd_ptr,WINMAIN_PC=base+0x136710,IMAGE_BASE=base,ASCII_CALL=base+0x2ab1ce,ASCII_RETURN=base+0x2ab1d4,ASCII_SLOT=base+ascii_slot,ASCII_VALUE=int.from_bytes(pe.read_rva(ascii_slot,8),'little'))
    fields.update(MODULE_CALL=base+0x136756,MODULE_RETURN=base+0x13675c,MODULE_SLOT=base+module_slot,MODULE_VALUE=int.from_bytes(pe.read_rva(module_slot,8),'little'),FILENAME_RETURN=base+0x136769,FILENAME_VA=FILENAME_GLOBAL,CWD_CALL=base+0x13676c,CWD_RETURN=base+0x136772,CWD_SLOT=base+cwd_slot,CWD_VALUE=int.from_bytes(pe.read_rva(cwd_slot,8),'little'),GAME_INIT_PC=base+0x133e80,GAME_SUBINIT_PC=base+0x133640,GAME_SUBINIT_RETURN=base+0x133efb,PLATFORM_INIT_PC=base+0x130580,FOPEN_THUNK_PC=base+0x2aaebc)
    runner=re.sub(r'\b(?:'+ '|'.join(map(re.escape,fields)) + r')\b',lambda m:u(fields[m[0]]),runner)
    runner=runner.replace("IAT_CHECKS","\n    ".join(checks))
    (destination/"mxb_private_startup.c").write_text(MEMORY_RUNTIME+EXTRA+prefix+tail+prologue+thread+guard+callback+app_tail+finish+filter_entry+filter_exit+after_walk+plain_entry+decoded+registered+args_entry+args_setup+args_return+constructor+fourth+parent_tail+next_constructor+final_prefix+virtual_body+complete_second+parent_return+second_exit+third_exit+second_exit_return+third_exit_return+release+scan+main_body+filename_body+cwd_prefix+game_handoff+init_body+subinit+platform_handoff+platform_prefix+child+runner)

    values=",".join(str(b) for b in pe.read_rva(0x3928a0,16))
    launcher=[
        "#include <string.h>",
        "extern int mxb_private_data_init(MXBOwnedStartup *,MXBGuestMemory *);",
        "int mxb_native_launch(MXBOwnedStartup *p){",
        "if(!p || p->pc)return 0;",
        "MXBGuestMemory memory={0};",
        f"static const uint8_t initial[16]={{{values}}};",
        "for(unsigned i=0;i<16;i++)p->initial_globals[i]=initial[i];",
        f"if(!mxb_guest_map(&memory,{u(base+0x3928a0)},p->initial_globals,16,MXB_MEM_READ|MXB_MEM_WRITE))return 0;",
        f"if(!mxb_guest_map(&memory,{u(lock)},(uint8_t *)&p->crt_lock,8,3))return 0;",
        f"if(!mxb_guest_map(&memory,{u(state_addr)},(uint8_t *)&p->crt_phase,4,3))return 0;",
        f"if(!mxb_guest_map(&memory,{u(tls_addr)},(uint8_t *)&p->tls_callback,8,3))return 0;",
        *mappings,*data_maps,*game_maps,
        *[f"if(!mxb_guest_map(&memory,{u(base+addr)},(uint8_t *){ptr},{size},3))return 0;"
          for addr,ptr,size in ((0x3d8018,"&p->argument_count",4),(0x3d8020,"p->argument_globals",24),
                                (0x3d9b10,"p->object_header",24),(0x3de328,"p->subobjects",0x4a0))],
        f"if(!mxb_guest_map(&memory,{u(base+0xe4adb0)},(uint8_t *)p->exit_bounds,16,3))return 0;",
        f"if(!mxb_guest_map(&memory,{u(app_flag)},(uint8_t *)&p->managed_app,4,3))return 0;",
        "if(!mxb_private_data_init(p,&memory))return 0;",
        f"return mxb_owned_startup(p,&memory,{u(base+entry)});",
        "}",
    ]
    (destination/"mxb_launch.inc").write_text("\n".join(launcher)+"\n")
