#!/usr/bin/env python3
"""Run authentic MX Bikes main -> two mocked Win64 imports -> filename helper
through MOVSX EAX,[RAX], TEST EAX,EAX and JE, diff x64 vs native ARM64.

Original PE is SHA pinned and instruction identity checked. Five host
scenarios include the actual modeled path byte and explicit runtime-memory
mutations (0,0x7f,0x80,0xff) at the validated jump boundary, not modifications
to the original executable or proof of more game initialization.
"""
from pathlib import Path
import hashlib,json,struct,subprocess,sys,tempfile
from capstone import Cs,CS_ARCH_X86,CS_MODE_64,CS_GRP_JUMP
from capstone.x86 import X86_OP_IMM
from unicorn import Uc,UC_HOOK_CODE
from unicorn.x86_const import (
 UC_X86_REG_RIP,UC_X86_REG_RSP,UC_X86_REG_RAX,
 UC_X86_REG_RBX,UC_X86_REG_RCX,UC_X86_REG_RDX,
 UC_X86_REG_R8,UC_X86_REG_R9,UC_X86_REG_RDI,
 UC_X86_REG_RSI,UC_X86_REG_R10,UC_X86_REG_R11,UC_X86_REG_EFLAGS
)
from mxbikes_joined_strcpy_native import (
 BASE,MAIN,AFTER_IMPORT,HOST_STUB,GUEST_CRT,PATH,PATH_LEN,WINDOW,
 verify_next_import,inspect_original,new_cpu,ENTRY_SP,TEST_INPUT,
 SEED_RBX,SEED_RDI,SEED_RSI,SEED_R11,EXE_SHA,MAX,
 original_thunk,CASES,NUM_CASES,original_run,original_main_with_module_name,
 original_probe,original_joined,verify_helper,generate_joined,
 STACK_MAIN_RSP
)
from mxbikes_post_strcpy_native import verify_source,append_to_existing_native
from mxbikes_after_strcpy_jump_probe import run as probe_next
from mxbikes_post_strcpy_probe import discover as discover_first,reference as reference_first
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/"arm64-lab"))
from tools.pe_probe import PE
from tools.import_aot_smoke import execute_arm64_elf

START=0x15b7cf
JCC=0x15b7d9
TAKEN=0x15b801
FALLTHROUGH=0x15b7db
INPUTS=[PATH[0],0,0x5c,0x80,0xff]

def verify_branch(pe):
    md=Cs(CS_ARCH_X86,CS_MODE_64);md.detail=True
    decoded=list(md.disasm(pe.read_rva(START,12),START))
    forms=[("mov","rax, qword ptr [rsp + 0x28]"),
           ("movsx","eax, byte ptr [rax]"),
           ("test","eax, eax"),
           ("je","0x15b801")]
    if (len(decoded)!=4 or [(x.mnemonic,x.op_str) for x in decoded]!=forms or
        decoded[-1].address!=JCC or
        not decoded[-1].group(CS_GRP_JUMP) or
        len(decoded[-1].operands)!=1 or
        decoded[-1].operands[0].type!=X86_OP_IMM or
        decoded[-1].operands[0].imm!=TAKEN or
        decoded[-1].address+decoded[-1].size!=FALLTHROUGH):
        raise RuntimeError("Original filename helper MOVSX/TEST/JE identity changed")
    return len(decoded)

def original_branch(pe,first_iat,second_iat,dest,test_index,byte,follow_successor=False,follow_slash_loop=False,follow_loop_iteration=False,follow_second_loopback=False,follow_third_backslash=False,follow_to_nul=False,follow_separator_finalize=False,follow_helper_return=False):
    cpu=new_cpu(pe)
    cpu.mem_map(HOST_STUB,0x2000)
    cpu.mem_write(HOST_STUB,b"\xc3")
    cpu.mem_write(GUEST_CRT,b"\xc3")
    cpu.mem_write(BASE+first_iat,struct.pack("<Q",HOST_STUB))
    cpu.mem_write(BASE+second_iat,struct.pack("<Q",GUEST_CRT))
    cpu.mem_write(TEST_INPUT,b"\x00")
    cpu.mem_write(ENTRY_SP,struct.pack("<Q",BASE+0x777777))
    seeds={
      UC_X86_REG_RIP:BASE+MAIN,UC_X86_REG_RSP:ENTRY_SP,
      UC_X86_REG_RAX:0x888876543210+test_index,
      UC_X86_REG_RBX:SEED_RBX,UC_X86_REG_RCX:BASE,
      UC_X86_REG_RDX:0,UC_X86_REG_R8:TEST_INPUT,UC_X86_REG_R9:10,
      UC_X86_REG_RDI:SEED_RDI,UC_X86_REG_RSI:SEED_RSI,
      UC_X86_REG_R11:SEED_R11,UC_X86_REG_R10:0x78123456789,
      UC_X86_REG_EFLAGS:0x202|[0,1,0x40,0x80,0xc1,0x41,0x200,0x81][test_index%8]
    }
    for reg,value in seeds.items():cpu.reg_write(reg,value)
    calls=[]
    def imports(u,pc,ins_length,ctx):
        if pc==HOST_STUB:
            if (u.reg_read(UC_X86_REG_RCX)!=0 or
                u.reg_read(UC_X86_REG_RDX)!=STACK_MAIN_RSP+0x140 or
                u.reg_read(UC_X86_REG_R8)!=WINDOW):
                raise RuntimeError("Original filename API arguments changed")
            u.mem_write(STACK_MAIN_RSP+0x140,PATH+b"\x00")
            u.reg_write(UC_X86_REG_RAX,PATH_LEN)
            calls.append("module")
        elif pc==GUEST_CRT:
            if(u.reg_read(UC_X86_REG_RCX)!=dest or
               u.reg_read(UC_X86_REG_RDX)!=STACK_MAIN_RSP+0x140):
                raise RuntimeError("Original strcpy API arguments changed")
            buf=bytearray()
            for n in range(MAX):
                c=bytes(u.mem_read(STACK_MAIN_RSP+0x140+n,1))
                buf+=c
                if c==b"\x00":break
            else:raise RuntimeError("Original bounded strcpy exceeded limit")
            u.mem_write(dest,bytes(buf))
            u.reg_write(UC_X86_REG_RAX,dest)
            calls.append("strcpy")
    cpu.hook_add(UC_HOOK_CODE,imports)
    cpu.emu_start(BASE+MAIN,BASE+START,timeout=6000000,count=160)
    if(cpu.reg_read(UC_X86_REG_RIP)!=BASE+START or
       calls!=["module","strcpy"] or
       bytes(cpu.mem_read(dest,1))!=PATH[:1]):
        raise RuntimeError("Original game did not reach next branch after two modeled imports")
    # Explicitly controlled test mutation at branch entry. The normal case
    # keeps the actual modeled module filename byte.
    if byte!=PATH[0]:
        cpu.mem_write(dest,bytes([byte]))
    cpu.emu_start(BASE+START,0,timeout=1000000,count=4)
    if follow_successor:
        next_pc=cpu.reg_read(UC_X86_REG_RIP)
        expected=BASE+TAKEN if byte==0 else BASE+FALLTHROUGH
        if next_pc!=expected:
            raise RuntimeError("Original JE first branch did not reach successor")
        count=2 if byte==0 else 4
        cpu.emu_start(next_pc,0,timeout=1000000,count=count)
    if follow_slash_loop:
        if not follow_successor:
            raise RuntimeError("Cannot run third branch without second branch")
        if byte not in (PATH[0],0x2f,0x80,0xff):
            raise RuntimeError("The x64 third-branch fixture only covers non-backslash bytes")
        if cpu.reg_read(UC_X86_REG_RIP)!=BASE+0x15b7e8:
            raise RuntimeError("Original normal filename third branch initial PC differs")
        cpu.emu_start(BASE+0x15b7e8,0,timeout=1000000,count=4)
        if byte==0x2f:
            if cpu.reg_read(UC_X86_REG_RIP)!=BASE+0x15b7f5:
                raise RuntimeError("Original slash comparison did not take fallthrough path")
        else:
            if cpu.reg_read(UC_X86_REG_RIP)!=BASE+0x15b7ff:
                raise RuntimeError("Original 0x2F JNE did not reach expected loop-back JMP")
            cpu.emu_start(BASE+0x15b7ff,0,timeout=1000000,count=1)
            if cpu.reg_read(UC_X86_REG_RIP)!=BASE+0x15b7c1:
                raise RuntimeError("Original JMP failed to reach loop header 0x15B7C1")
    if follow_loop_iteration:
        if (not follow_slash_loop or byte not in (PATH[0],0x80,0xff) or
            cpu.reg_read(UC_X86_REG_RIP)!=BASE+0x15b7c1):
            raise RuntimeError("Next original filename iteration requires real loop entry")
        cpu.emu_start(BASE+0x15b7c1,0,timeout=1000000,count=7)
        end=(BASE+0x15b801 if PATH[1]==0 else BASE+0x15b7db)
        if cpu.reg_read(UC_X86_REG_RIP)!=end:
            raise RuntimeError("Original x64 next filename iterator branch mismatch")
    if follow_second_loopback:
        if not follow_loop_iteration or cpu.reg_read(UC_X86_REG_RIP)!=BASE+0x15b7db:
            raise RuntimeError("Second separator check requires executed x64 loop increment")
        if PATH[1]!=ord(":"):
            raise RuntimeError("Original modeled filename second byte changed")
        # Execute original second-character CMP '\\', then CMP '/',
        # and the actual unconditional backward JMP. Stop at next header.
        cpu.emu_start(BASE+0x15b7db,0,timeout=1000000,count=4)
        if cpu.reg_read(UC_X86_REG_RIP)!=BASE+0x15b7e8:
            raise RuntimeError("Second x64 backslash check changed its destination")
        cpu.emu_start(BASE+0x15b7e8,0,timeout=1000000,count=4)
        if cpu.reg_read(UC_X86_REG_RIP)!=BASE+0x15b7ff:
            raise RuntimeError("Second x64 slash check changed its destination")
        cpu.emu_start(BASE+0x15b7ff,0,timeout=1000000,count=1)
        if cpu.reg_read(UC_X86_REG_RIP)!=BASE+0x15b7c1:
            raise RuntimeError("Second original filename backward jump failed")
    if follow_third_backslash:
        if not follow_second_loopback or cpu.reg_read(UC_X86_REG_RIP)!=BASE+0x15b7c1:
            raise RuntimeError("Third x64 original separator requires completed second loopback")
        if PATH[2]!=0x5c:
            raise RuntimeError("Original modeled filename third character is no longer backslash")
        cpu.emu_start(BASE+0x15b7c1,0,timeout=1000000,count=7)
        if cpu.reg_read(UC_X86_REG_RIP)!=BASE+0x15b7db:
            raise RuntimeError("Third x64 loop body did not reach non-NUL branch")
        cpu.emu_start(BASE+0x15b7db,0,timeout=1000000,count=4)
        if cpu.reg_read(UC_X86_REG_RIP)!=BASE+0x15b7f5:
            raise RuntimeError("Third x64 backslash compare did not take original JE")
    walked_original=0
    if follow_to_nul:
        if not follow_third_backslash or byte!=PATH[0] or (
            cpu.reg_read(UC_X86_REG_RIP)!=BASE+0x15b7f5):
            raise RuntimeError("Full x64 original string walk requires authentic third-backslash state")
        # Preserve the original x64 decoder, real arithmetic flags and real
        # path data; stop BEFORE original post-NUL RVA 0x15B809.
        visited=[]
        def stop_at_original_nul_exit(u,pc,ins_size,ctx):
            visited.append(pc)
            if len(visited)>600:
                raise RuntimeError("Original full filename walker exceeded code budget")
            if pc==BASE+0x15b809:
                u.emu_stop()
        stop_hook=cpu.hook_add(UC_HOOK_CODE,stop_at_original_nul_exit)
        cpu.emu_start(BASE+0x15b7f5,0,timeout=3000000,count=600)
        # Remove the one-shot stop hook before executing the next real block.
        cpu.hook_del(stop_hook)
        if (cpu.reg_read(UC_X86_REG_RIP)!=BASE+0x15b809 or
            visited[-1]!=BASE+0x15b809):
            raise RuntimeError("Original x64 filename walker did not reach its post-NUL branch")
        walked_original=len(visited)-1
        if walked_original!=314:
            raise RuntimeError("Original full string loop instruction count drifted: "+
                               str(walked_original))
        saved_separator=struct.unpack(
            "<Q",bytes(cpu.mem_read(
                cpu.reg_read(UC_X86_REG_RSP)+0x20,8)))[0]
        if saved_separator!=dest+10:
            raise RuntimeError("Original path parser last backslash did not point to index 10")
    if follow_separator_finalize:
        if not follow_to_nul or cpu.reg_read(UC_X86_REG_RIP)!=BASE+0x15b809:
            raise RuntimeError("Original separator finalization needs authentic post-NUL path")
        # Execute original MOV/MOV/LEA/JMP to the shared helper exit PC.
        cpu.emu_start(BASE+0x15b809,0,timeout=1000000,count=4)
        if cpu.reg_read(UC_X86_REG_RIP)!=BASE+0x15b862:
            raise RuntimeError("Original x64 separator-present finalization lost shared exit")
        if (bytes(cpu.mem_read(dest+10,1))!=b"\\" or
            bytes(cpu.mem_read(dest+11,1))!=b"\x00" or
            bytes(cpu.mem_read(dest+12,1))!=b"x" or
            cpu.reg_read(UC_X86_REG_RAX)!=dest):
            raise RuntimeError("Original x64 directory buffer NUL and returned base changed")
    if follow_helper_return:
        if (not follow_separator_finalize or
            cpu.reg_read(UC_X86_REG_RIP)!=BASE+0x15b862):
            raise RuntimeError("x64 filename helper return requires completed separator path")
        cpu.emu_start(BASE+0x15b862,0,timeout=1000000,count=2)
        if (cpu.reg_read(UC_X86_REG_RIP)!=BASE+0x136769 or
            cpu.reg_read(UC_X86_REG_RSP)!=STACK_MAIN_RSP):
            raise RuntimeError("Original filename helper did not restore main Win64 caller frame")
        return_slot=struct.unpack(
            "<Q",bytes(cpu.mem_read(STACK_MAIN_RSP-8,8)))[0]
        if return_slot!=BASE+0x136769:
            raise RuntimeError("Original helper guest Win64 RET slot no longer matches")
    flags=cpu.reg_read(UC_X86_REG_EFLAGS)
    regs={
        "rax":UC_X86_REG_RAX,"rbx":UC_X86_REG_RBX,
        "rcx":UC_X86_REG_RCX,"rdx":UC_X86_REG_RDX,
        "r8":UC_X86_REG_R8,"r9":UC_X86_REG_R9,
        "rdi":UC_X86_REG_RDI,"rsi":UC_X86_REG_RSI,
        "r11":UC_X86_REG_R11,"rsp":UC_X86_REG_RSP,
        "rip":UC_X86_REG_RIP,
    }
    result={name:cpu.reg_read(reg) for name,reg in regs.items()}
    original_local_rsp=(result["rsp"]-0x40 if follow_helper_return else
                        result["rsp"])
    result.update({
       "cf":int(bool(flags&1)),"sf":int(bool(flags&128)),
       "zf":int(bool(flags&64)),"byte":byte,
       "pointer":struct.unpack("<Q",bytes(cpu.mem_read(original_local_rsp+0x28,8)))[0],
       "original_byte_after_mutation":int.from_bytes(cpu.mem_read(dest,1),"little"),
       "scan_instructions":walked_original,
       "separator_finish_instructions":4 if follow_separator_finalize else 0,
       "helper_return_instructions":2 if follow_helper_return else 0,
       "helper_return_was_executed":follow_helper_return,
       "original_directory_NUL_after_last_sep":(
           bytes(cpu.mem_read(dest+11,1))==b"\x00"
           if follow_separator_finalize else False),
       "last_separator":(
           struct.unpack("<Q",bytes(cpu.mem_read(original_local_rsp+0x20,8)))[0]
           if follow_to_nul else 0)
    })
    if not follow_successor and result["rip"]!=(BASE+TAKEN if byte==0 else BASE+FALLTHROUGH):
        raise RuntimeError("Original JE branch destination disagrees with original source byte")
    expected_pointer=(dest+len(PATH) if follow_to_nul else
                      dest+(2 if follow_third_backslash else 1)
                      if follow_loop_iteration else dest)
    if result["pointer"]!=expected_pointer or result["original_byte_after_mutation"]!=byte:
        raise RuntimeError("Original helper pointer or source memory differs")
    return result

def extend_native(src,refs,dest):
    before="static int final_strcpy_smoke(void){"
    if src.count(before)!=1:
        raise RuntimeError("Prior native joined helper has changed")
    order=("rax","rbx","rcx","rdx","r8","r9","rdi","rsi","r11","rsp","rip")
    lines=[]
    for item in refs:
        values=[item[x] for x in order]
        lines.append("{"+
            ",".join("UINT64_C("+str(v)+")" for v in values)+","+
            ",".join(str(item[x]) for x in ("cf","zf","sf","byte"))+","+
            "UINT64_C("+str(item["pointer"])+")}")
    extra=r'''
#include "mx_game_path_after_strcpy_branch.h"
#define STRCPY_BRANCH_START (BASE+UINT64_C(0x15b7cf))
#define STRCPY_BRANCH_TAKEN (BASE+UINT64_C(0x15b801))
#define STRCPY_BRANCH_FALLTHROUGH (BASE+UINT64_C(0x15b7db))
typedef struct {
    uint64_t rax,rbx,rcx,rdx,r8,r9,rdi,rsi,r11,rsp,rip;
    uint8_t cf,zf,sf,byte;
    uint64_t pointer;
} original_branch_case;
static const original_branch_case branch_reference[STRCPY_GUEST_CASES]={
__BRANCH_CASES__
};
static const mx_game_path_after_strcpy_branch_layout branch_layout={
 STRCPY_BRANCH_START,STRCPY_BRANCH_TAKEN,STRCPY_BRANCH_FALLTHROUGH
};
'''
    extra=extra.replace("__BRANCH_CASES__",",\n".join(lines))
    src=src.replace(before,extra+"\n"+before)
    anchor='''   if(read_guest(&guest,s.rsp+0x20U,8U)!=a->local0 ||
      read_guest(&guest,s.rsp+0x28U,8U)!=a->local1)return 65;
 }'''
    new='''   if(read_guest(&guest,s.rsp+0x20U,8U)!=a->local0 ||
      read_guest(&guest,s.rsp+0x28U,8U)!=a->local1)return 65;
   const original_branch_case*br=&branch_reference[k];
   uint8_t selected_byte=br->byte;
   if(!mx_cfg_transfer(&guest,STRING_DEST,&selected_byte,1U,1))return 66;
   mx_game_path_after_strcpy_branch_result outcome={0};
   if(mx_game_path_after_strcpy_branch(&s,&guest,&branch_layout,&outcome)!=
      MX_GAME_PATH_BRANCH_REACHED)return 67;
   if(s.rax!=br->rax||s.rbx!=br->rbx||s.rcx!=br->rcx||
      s.rdx!=br->rdx||s.r8!=br->r8||s.r9!=br->r9||
      s.rdi!=br->rdi||s.rsi!=br->rsi||s.r11!=br->r11||
      s.rsp!=br->rsp||s.rip!=br->rip||
      s.cf!=br->cf||s.zf!=br->zf||s.sf!=br->sf||
      outcome.source_pointer!=br->pointer||
      outcome.source_byte!=br->byte||
      outcome.branch_taken!=(br->byte==0U)||
      s.instructions!=40U)return 68;
 }'''
    if src.count(anchor)!=1:raise RuntimeError("Current native helper block insertion point changed")
    return src.replace(anchor,new)

def run(executable,out):
    pe=PE(executable)
    if hashlib.sha256(pe.b).hexdigest()!=EXE_SHA:
        raise RuntimeError("Original game SHA changed")
    verify_branch(pe)
    _,_,last_constant=verify_source(pe)
    main_layout,_,_=inspect_original(pe)
    iat_module=verify_next_import(pe)
    iat_strcpy,dest=original_thunk(pe)
    if dest!=last_constant:
        raise RuntimeError("Original filename helper source pointer differs from copied path")
    _,helper_stop,first_constant=verify_helper(pe)
    if first_constant!=last_constant:
        raise RuntimeError("Original helper source and destination alias unexpectedly changed")
    initial=[original_run(pe,main_layout,k) for k in range(NUM_CASES)]
    module_refs=[(k,original_main_with_module_name(pe,main_layout,iat_module,k))
                 for k in CASES]
    helper_refs=[(k,original_probe(pe,main_layout,iat_module,helper_stop,k))
                 for k in CASES]
    strcpy_refs=[(k,original_joined(pe,main_layout,iat_module,iat_strcpy,dest,k))
                 for k in CASES]
    _,first_stop=discover_first(pe)
    after_refs=[reference_first(pe,iat_module,iat_strcpy,dest,first_stop,k,
                execute_direct_jump=True) for k in CASES]
    orig_branches=[original_branch(pe,iat_module,iat_strcpy,dest,k,val)
                   for k,val in zip(CASES,INPUTS)]
    base=generate_joined(main_layout,initial,module_refs,
                         helper_refs,strcpy_refs,first_constant,dest)
    after=append_to_existing_native(base,after_refs,last_constant)
    full=extend_native(after,orig_branches,dest)
    with tempfile.TemporaryDirectory(prefix="mxb-jcc-after-strcpy-") as td:
        root=Path(td)
        src=root/"private-native-jcc-verified.c"
        src.write_text(full)
        flags=["-std=c11","-O2","-Wall","-Wextra","-Werror",
               "-I",str(ROOT/"arm64-lab"/"runtime")]
        host=root/"host"
        result=subprocess.run(["cc",*flags,"-DHOST",str(src),"-o",str(host)],
                              capture_output=True,text=True)
        if result.returncode:
            raise RuntimeError("Host original-branch native compile failed: "+result.stderr[-3500:])
        result=subprocess.run([str(host)],capture_output=True,text=True)
        if result.returncode:
            raise RuntimeError("Host native branch comparison returned "+str(result.returncode))
        arm=root/"native-jcc-after-strcpy.elf"
        result=subprocess.run(["clang","--target=aarch64-unknown-linux-gnu",
             "-fuse-ld=lld","-nostdlib","-static","-ffreestanding",
             "-fno-builtin","-fno-stack-protector",*flags,
             "-Wl,-e,smoke","-Wl,-z,max-page-size=4096",
             "-Wl,--build-id=none",str(src),"-o",str(arm)],
             capture_output=True,text=True)
        if result.returncode:
            raise RuntimeError("ARM64 native branch compile failed: "+result.stderr[-3500:])
        outcome=execute_arm64_elf(arm,instruction_budget=1950000,timeout_us=15000000)
        if outcome["arm64_smoke_exit"]!=0:
            raise RuntimeError("ARM64 branch differential failed: "+
                               str(outcome["arm64_smoke_exit"]))
    out.mkdir(parents=True,exist_ok=True)
    taken=sum(item["rip"]==BASE+TAKEN for item in orig_branches)
    report={
      "sha_verified_original_game":True,
      "linked_native_game_main_through_strcpy":True,
      "new_original_guest_instructions_executed_on_arm64":4,
      "native_differential_successful_cases":len(orig_branches),
      "original_x64_tested_cases":len(orig_branches),
      "normal_filename_byte_tested":PATH[0],
      "controlled_runtime_memory_modification_samples":INPUTS[1:],
      "JE_taken_tests":taken,
      "JE_fallthrough_tests":len(orig_branches)-taken,
      "original_branch_taken_rva":hex(TAKEN),
      "original_fallthrough_rva":hex(FALLTHROUGH),
      "signed_movsx_flags_tested":True,
      "full_successor_executed":False,
      "full_game_engine_booted":False,
      "iOS_binary_produced":False,
      "caveat":"Two original Win32/CRT imports are modeled. Only bounded original MOV/MOVSX/TEST/JE translated; neither successor executes. Test variants alter guest-memory path byte after modeled strcpy."
    }
    (out/"joined-after-strcpy-branch.json").write_text(json.dumps(report,indent=2)+"\n")
    lines=["# MX Bikes — original filename-helper MOVSX/TEST/JE joined natively","",
           "- Original real-game connected main to strcpy to JE: **PASS**",
           "- New original x64 instructions executed in ARM64: **4**",
           "- Matching x64 vs executed native ARM64 tests: **"+
             str(len(orig_branches))+"/"+str(len(orig_branches))+"**",
           "- Zero-byte branch taken cases: **"+str(taken)+"**",
           "- Nonzero fallthrough cases: **"+str(len(orig_branches)-taken)+"**",
           "- Tested signed byte inputs: **0x80, 0xFF**",
           "- Original native branch destination: **0x15B801 / 0x15B7DB**",
           "",
           "**Original modeled module path case plus controlled guest-byte mutations. "
           "Both Windows imports are models, and branch successors, engine, graphics and iOS are not running.**",""]
    summary="\n".join(lines)
    (out/"joined-after-strcpy-branch.md").write_text(summary)
    print(summary)
    return report

if __name__=="__main__":
    if len(sys.argv)!=3:
        raise SystemExit("usage: after_strcpy_branch.py original-game.exe report-dir")
    run(Path(sys.argv[1]),Path(sys.argv[2]))
