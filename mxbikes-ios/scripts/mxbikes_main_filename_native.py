#!/usr/bin/env python3
"""Join original x64 main->callee return->KERNEL32 GetModuleFileNameA.

Original path executes from authentic MX Bikes main through callee's genuine
RET and original indirect IAT CALL. The original Win64 API boundary uses an
explicit *deterministic modeled host response*, not a real Windows process.
Native ARM64 executes the same proven first blocks and bounded portable API.
No next-main instruction, game engine, or actual Win32 process is executed.
"""
from pathlib import Path
import hashlib,json,struct,subprocess,sys,tempfile

from capstone import Cs,CS_ARCH_X86,CS_MODE_64,CS_GRP_CALL
from capstone.x86 import X86_OP_MEM
from unicorn import UC_HOOK_CODE,UC_ARCH_X86,UC_MODE_64
from unicorn.x86_const import (
 UC_X86_REG_RIP,UC_X86_REG_RSP,UC_X86_REG_RAX,UC_X86_REG_RBX,
 UC_X86_REG_RCX,UC_X86_REG_RDX,UC_X86_REG_R8,UC_X86_REG_R9,
 UC_X86_REG_RDI,UC_X86_REG_RSI,UC_X86_REG_R11,UC_X86_REG_R10,
 UC_X86_REG_EFLAGS
)
from mxbikes_main_joined_callee_native import (
    BASE,MAIN,CALLEE,CALL_SITE,AFTER_CALL,CODE_DATA,STACK,ENTRY_SP,
    TEST_INPUT,SEED_RBX,SEED_RDI,SEED_RSI,SEED_R11,EXE_SHA,
    verify_main,inspect_original,new_cpu,generate,original_run,NUM_CASES,
    BYTE_CASES
)
from mxbikes_first_callee_emu import import_slots

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/"arm64-lab"))
from tools.pe_probe import PE
from tools.import_aot_smoke import execute_arm64_elf

CALL_IMPORT=0x136756
AFTER_IMPORT=0x13675c
HOST_STUB=0x730000000
PATH=b"C:\\MXBikes\\mxbikes.exe"
PATH_LEN=len(PATH)
WINDOW=0x104

def verify_next_import(pe):
    md=Cs(CS_ARCH_X86,CS_MODE_64);md.detail=True
    decoded=list(md.disasm(pe.read_rva(AFTER_CALL,AFTER_IMPORT-AFTER_CALL),AFTER_CALL))
    forms=[
       ("lea","rdx, [rsp + 0x140]"),
       ("mov","r8d, 0x104"),
       ("xor","ecx, ecx"),
       ("call","qword ptr [rip + 0x1ea964]")
    ]
    if (len(decoded)!=4 or [(x.mnemonic,x.op_str) for x in decoded]!=forms or
        decoded[-1].address!=CALL_IMPORT or
        sum(x.size for x in decoded)!=AFTER_IMPORT-AFTER_CALL or
        not decoded[-1].group(CS_GRP_CALL)):
        raise RuntimeError("Original game GetModuleFileNameA caller identity changed")
    op=decoded[-1].operands[0]
    if (op.type!=X86_OP_MEM or
        decoded[-1].reg_name(op.mem.base)!="rip" or
        op.mem.index or op.mem.segment):
        raise RuntimeError("Unexpected original imported CALL operand")
    slot=decoded[-1].address+decoded[-1].size+op.mem.disp
    imports={(int(rva),str(dll).lower(),str(name).lower())
             for rva,dll,name in import_slots(pe)}
    if (slot,"kernel32.dll","getmodulefilenamea") not in imports:
        raise RuntimeError("Original IAT slot is not KERNEL32.dll GetModuleFileNameA")
    return slot

def original_main_with_module_name(pe,layout,slot,index):
    if BYTE_CASES[index]!=0:
        raise RuntimeError("Model currently covers only genuine returning empty-command path")
    uc=new_cpu(pe)
    uc.mem_map(HOST_STUB,4096)
    uc.mem_write(HOST_STUB,b"\xc3") # synthetic API RET instruction
    uc.mem_write(BASE+slot,struct.pack("<Q",HOST_STUB))
    uc.mem_write(TEST_INPUT,b"\x00")
    uc.mem_write(ENTRY_SP,struct.pack("<Q",BASE+0x777777))
    initial={
      UC_X86_REG_RIP:BASE+MAIN,UC_X86_REG_RSP:ENTRY_SP,
      UC_X86_REG_RAX:0x888876543210+index,
      UC_X86_REG_RBX:SEED_RBX,UC_X86_REG_RCX:BASE,
      UC_X86_REG_RDX:0,UC_X86_REG_R8:TEST_INPUT,UC_X86_REG_R9:10,
      UC_X86_REG_RDI:SEED_RDI,UC_X86_REG_RSI:SEED_RSI,
      UC_X86_REG_R11:SEED_R11,UC_X86_REG_R10:0x78123456789,
      UC_X86_REG_EFLAGS:0x202|[0,1,0x40,0x80,0xc1,0x41,0x200,0x81][index%8]
    }
    for reg,value in initial.items():uc.reg_write(reg,value)
    seen=[]
    def emulate_known_api(cpu,pc,size,_):
        if pc!=HOST_STUB:return
        seen.append(pc)
        rcx=cpu.reg_read(UC_X86_REG_RCX)
        destination=cpu.reg_read(UC_X86_REG_RDX)
        size=cpu.reg_read(UC_X86_REG_R8)
        expected_dest=ENTRY_SP-0x288+0x140
        if(rcx!=0 or size!=WINDOW or destination!=expected_dest):
            cpu.emu_stop()
            raise RuntimeError("Original Win64 GetModuleFileNameA arguments changed")
        cpu.mem_write(destination,PATH+b"\x00")
        cpu.reg_write(UC_X86_REG_RAX,PATH_LEN)
    uc.hook_add(UC_HOOK_CODE,emulate_known_api)
    uc.emu_start(BASE+MAIN,BASE+AFTER_IMPORT,timeout=4000000,count=75)
    if(uc.reg_read(UC_X86_REG_RIP)!=BASE+AFTER_IMPORT or len(seen)!=1):
        raise RuntimeError("Original main did not return from the modeled Windows import")
    flags=uc.reg_read(UC_X86_REG_EFLAGS)
    names={
      "rax":UC_X86_REG_RAX,"rbx":UC_X86_REG_RBX,
      "rcx":UC_X86_REG_RCX,"rdx":UC_X86_REG_RDX,
      "r8":UC_X86_REG_R8,"r9":UC_X86_REG_R9,
      "rdi":UC_X86_REG_RDI,"rsi":UC_X86_REG_RSI,
      "r11":UC_X86_REG_R11,"r10":UC_X86_REG_R10,
      "rip":UC_X86_REG_RIP,"rsp":UC_X86_REG_RSP
    }
    observed={name:uc.reg_read(reg) for name,reg in names.items()}
    observed.update({
       "cf":int(bool(flags&1)),"zf":int(bool(flags&64)),
       "sf":int(bool(flags&128)),
       "buffer":list(bytes(uc.mem_read(observed["rdx"],PATH_LEN+1))),
       "guest_stack_import_return":struct.unpack(
           "<Q",bytes(uc.mem_read(ENTRY_SP-0x288-8,8)))[0],
       "guest_stack_main_return":struct.unpack(
           "<Q",bytes(uc.mem_read(ENTRY_SP,8)))[0],
       "cookie":struct.unpack("<Q",bytes(
           uc.mem_read(ENTRY_SP-0x288+0x250,8)))[0],
       "callee_global0":struct.unpack("<Q",bytes(
           uc.mem_read(layout["callee_global0"],8)))[0],
       "callee_global1":struct.unpack("<I",bytes(
           uc.mem_read(layout["callee_global1"],4)))[0]
    })
    if(observed["rax"]!=PATH_LEN or observed["rsp"]!=ENTRY_SP-0x288 or
       observed["guest_stack_import_return"]!=BASE+AFTER_IMPORT or
       observed["buffer"]!=list(PATH+b"\x00")):
        raise RuntimeError("Modeled original x64 Windows import output invalid")
    return observed

APPEND=r'''
#include "mx_game_module_filename.h"
#define IMPORT_CALL UINT64_C(__IMPORT_CALL__)
#define AFTER_IMPORT UINT64_C(__AFTER_IMPORT__)
#define MODULE_PATH_LEN __MODULE_PATH_LEN__U
static const uint8_t host_module_path[MODULE_PATH_LEN+1U]=__MODULE_STRING__;
typedef struct {
 uint32_t test_index;
 uint64_t expected[12]; /* GP x9 + R10 + RSP + RIP */
 uint8_t cf,zf,sf;
 uint8_t buffer[MODULE_PATH_LEN+1U];
 uint64_t import_return, main_return,cookie,global0,global1;
} path_result;
static const path_result path_fixtures[__PATH_CASES__]={
__PATH_FIXTURES__
};
static int filename_smoke(void){
 mx_cfg_region regions[PAGE_COUNT+2U];
 regions[0].base=STACK;regions[0].data=stack_bytes;regions[0].length=131072U;
 regions[1].base=DATA;regions[1].data=input_data;regions[1].length=4096U;
 for(unsigned j=0;j<PAGE_COUNT;j++){
    regions[2U+j].base=mapped_original_pages[j];
    regions[2U+j].data=original_image_pages[j];
    regions[2U+j].length=4096U;
 }
 mx_cfg_memory mem={regions,PAGE_COUNT+2U};
 mx_native_link_registry registry={0};
 registry.entries=callable;registry.count=1U;registry.max_depth=4U;
 if(mx_native_link_seal(&registry)!=MX_NATIVE_LINK_OK)return 10;
 mx_game_module_context context={host_module_path,MODULE_PATH_LEN};
 for(unsigned k=0;k<__PATH_CASES__;k++){
   const path_result *test=&path_fixtures[k];
   const fixture *base=&fixtures[test->test_index];
   if(base->in_byte!=0U)return 11;
   for(unsigned j=0;j<131072U;j++)stack_bytes[j]=0U;
   for(unsigned j=0;j<PAGE_COUNT;j++)
      for(unsigned x=0;x<4096U;x++)original_image_pages[j][x]=0U;
   input_data[0x100U]=0U;
   uint64_t cookie=base->pre[0],g0=base->pre[4];
   uint64_t arg0=base->pre[1],arg1=base->pre[2];
   uint32_t show=(uint32_t)base->pre[3],g1=(uint32_t)base->pre[5];
   uint64_t main_ret=BASE+UINT64_C(0x777777);
   if(!mx_cfg_transfer(&mem,COOKIE,&cookie,8U,1)||
      !mx_cfg_transfer(&mem,ARG0,&arg0,8U,1)||
      !mx_cfg_transfer(&mem,ARG1,&arg1,8U,1)||
      !mx_cfg_transfer(&mem,SHOW,&show,4U,1)||
      !mx_cfg_transfer(&mem,CALLEE_G0,&g0,8U,1)||
      !mx_cfg_transfer(&mem,CALLEE_G1,&g1,4U,1)||
      !mx_cfg_transfer(&mem,ENTRY_SP,&main_ret,8U,1))return 12;
   mx_crt_cluster_state s={0};
   s.rip=MAIN;s.rsp=ENTRY_SP;
   s.rax=UINT64_C(0x888876543210)+test->test_index;
   s.rbx=UINT64_C(0x123456789abcd);
   s.rcx=BASE;s.rdx=0U;s.r8=TEST_INPUT;s.r9=10U;
   s.rdi=UINT64_C(0x5778899aabbcc);
   s.rsi=UINT64_C(0x1123456789abc);
   s.r11=UINT64_C(0x54111122223333);
   s.cf=0U;s.sf=0U;s.zf=0U;
   int status=main_to_callee(&s,&mem,&registry);
   if(status!=MX_NATIVE_LINK_OK ||s.rip!=AFTER_CALL)return 13;
   if(mx_game_main_filename_prepare(&s,AFTER_CALL,IMPORT_CALL)!=MX_GAME_FILENAME_OK)
       return 14;
   if(s.rip!=IMPORT_CALL ||s.rcx!=0U ||s.r8!=0x104U ||
      s.rdx!=s.rsp+0x140U ||s.zf!=1U ||s.cf||s.sf)
       return 15;
   if(mx_game_main_filename_import_call(
          &s,&mem,&context,IMPORT_CALL,AFTER_IMPORT)!=MX_GAME_FILENAME_OK)
       return 16;
   const uint64_t got[12]={
     s.rax,s.rbx,s.rcx,s.rdx,s.r8,s.r9,s.rdi,s.rsi,s.r11,
     current_branch.r10,s.rsp,s.rip
   };
   for(unsigned n=0;n<12U;n++)if(got[n]!=test->expected[n])return 17;
   if(s.cf!=test->cf ||s.zf!=test->zf ||s.sf!=test->sf)return 18;
   for(unsigned n=0;n<MODULE_PATH_LEN+1U;n++){
     uint8_t byte=0U;
     if(!mx_cfg_transfer(&mem,s.rdx+n,&byte,1U,0) ||
        byte!=test->buffer[n])return 19;
   }
   if(read_guest(&mem,ENTRY_SP-0x288U-8U,8U)!=test->import_return ||
      read_guest(&mem,ENTRY_SP,8U)!=test->main_return ||
      read_guest(&mem,ENTRY_SP-0x288U+0x250U,8U)!=test->cookie ||
      read_guest(&mem,CALLEE_G0,8U)!=test->global0 ||
      read_guest(&mem,CALLEE_G1,4U)!=test->global1)return 20;
   if(s.imports!=1U ||s.instructions!=23U)return 21;
 }
 /* Explicit unsafe/missing WinAPI state fails closed. */
 mx_cfg_region fake_region={DATA,input_data,4096U};
 mx_cfg_memory fake_mem={&fake_region,1U};
 mx_crt_cluster_state bad={0};
 bad.rdx=DATA+0x100U;bad.r8=0x104U;
 mx_game_module_context absent={0};
 if(mx_game_get_module_filename_a(&bad,&fake_mem,&absent)!=
    MX_GAME_FILENAME_UNSUPPORTED)return 22;
 bad.rcx=BASE;
 if(mx_game_get_module_filename_a(&bad,&fake_mem,&context)!=
    MX_GAME_FILENAME_UNSUPPORTED)return 23;
 bad.rcx=0U;bad.rdx=BASE+UINT64_C(0xdead00);
 if(mx_game_get_module_filename_a(&bad,&fake_mem,&context)!=
    MX_GAME_FILENAME_UNMAPPED)return 24;
 return 0;
}
'''

def generate_filename_stage(layout,references,path_reference):
    parent_source,pages=generate(layout,references)
    if(parent_source.count("#ifdef HOST")!=1):
        raise RuntimeError("Joined native test main signature changed")
    sample=[]
    order=("rax","rbx","rcx","rdx","r8","r9","rdi","rsi","r11","r10","rsp","rip")
    for index,expect in path_reference:
        nums=[expect[name] for name in order]
        suffix=(expect["guest_stack_import_return"],
                expect["guest_stack_main_return"],
                expect["cookie"],expect["callee_global0"],
                expect["callee_global1"])
        sample.append("{"+str(index)+",{"+
          ",".join("UINT64_C("+str(v)+")" for v in nums)+"},"+
          ",".join(str(expect[f]) for f in ("cf","zf","sf"))+
          ",{"+",".join(str(v) for v in expect["buffer"])+"},"+
          ",".join("UINT64_C("+str(v)+")" for v in suffix)+"}")
    extra=APPEND
    consts={
       "__IMPORT_CALL__":BASE+CALL_IMPORT,
       "__AFTER_IMPORT__":BASE+AFTER_IMPORT,
       "__MODULE_PATH_LEN__":PATH_LEN,
       "__MODULE_STRING__":json.dumps(PATH.decode("ascii")),
       "__PATH_CASES__":len(path_reference),
       "__PATH_FIXTURES__":",\n".join(sample)
    }
    for key,value in consts.items():extra=extra.replace(key,str(value))
    if "__PATH_" in extra:
        raise RuntimeError("Native module path fixture not fully expanded")
    if parent_source.count("int smoke(void){")!=1:
        raise RuntimeError("Original native smoke entry signature changed")
    parent_source=parent_source.replace("int smoke(void){",
                                        "static int prior_smoke(void){")
    parent_source=parent_source.replace(
        "#ifdef HOST",
        extra+"\nint smoke(void){int first=prior_smoke();return first?first:filename_smoke();}\n#ifdef HOST")
    return parent_source,pages

def run(executable,directory):
    pe=PE(executable)
    if hashlib.sha256(pe.b).hexdigest()!=EXE_SHA:
        raise RuntimeError("Original executable SHA changed")
    verify_main(executable)
    layout,_,_=inspect_original(pe)
    slot=verify_next_import(pe)
    first_stage_refs=[original_run(pe,layout,k) for k in range(NUM_CASES)]
    chosen=[k for k in range(NUM_CASES) if BYTE_CASES[k]==0]
    original_cases=[(k,original_main_with_module_name(pe,layout,slot,k))
                    for k in chosen]
    source,pages=generate_filename_stage(layout,first_stage_refs,original_cases)
    with tempfile.TemporaryDirectory(prefix="mxb-path-import-native-") as td:
        tmp=Path(td);c=tmp/"private-original-main-win32-import.c"
        c.write_text(source)
        flags=["-std=c11","-O2","-Wall","-Wextra","-Werror",
               "-I",str(ROOT/"arm64-lab"/"runtime")]
        host=tmp/"host"
        p=subprocess.run(["cc",*flags,"-DHOST",str(c),"-o",str(host)],
                         capture_output=True,text=True)
        if p.returncode:raise RuntimeError("Host compiler: "+p.stderr[-2600:])
        p=subprocess.run([str(host)],capture_output=True,text=True)
        if p.returncode:raise RuntimeError("Joined native host mismatch code "+str(p.returncode))
        arm=tmp/"guest-win32-path-aarch64.elf"
        p=subprocess.run(["clang","--target=aarch64-unknown-linux-gnu",
             "-fuse-ld=lld","-nostdlib","-static","-ffreestanding",
             "-fno-builtin","-fno-stack-protector",*flags,
             "-Wl,-e,smoke","-Wl,-z,max-page-size=4096",
             "-Wl,--build-id=none",str(c),"-o",str(arm)],
             capture_output=True,text=True)
        if p.returncode:raise RuntimeError("ARM64 compile: "+p.stderr[-2600:])
        result=execute_arm64_elf(arm,instruction_budget=1950000,timeout_us=15000000)
        if result["arm64_smoke_exit"]!=0:
            raise RuntimeError("Guest Win32 path original-vs-ARM64 mismatch "+str(result["arm64_smoke_exit"]))
    directory.mkdir(parents=True,exist_ok=True)
    report={
       "original_executable_sha_verified":True,
       "original_main_to_callee_joined":True,
       "original_empty_callee_return_to_main":True,
       "post_return_original_instructions_executed_natively":3,
       "authentic_original_iat":"KERNEL32.dll!GetModuleFileNameA",
       "authentic_import_call_site_rva":hex(CALL_IMPORT),
       "original_api_response":"controlled deterministic host model",
       "module_filename_service_executed_native_arm64":True,
       "original_x64_modeled_service_cases":len(original_cases),
       "native_arm64_modeled_service_cases":len(original_cases),
       "native_original_game_main_continuation_rva":hex(AFTER_IMPORT),
       "guest_buffer_length":PATH_LEN+1,
       "guest_memory_path_bytes_differential":True,
       "unsupported_winapi_inputs_refused":True,
       "original_windows_kernel32_executed":False,
       "real_executable_file_location_resolved":False,
       "subsequent_game_main_instruction_executed":False,
       "engine_initialized":False,
       "iOS_application_built":False,
       "scope":"Joined original main, native callee empty-path RET, three post-return instructions, and original KERNEL32 IAT CALL with explicit modeled module filename."
    }
    (directory/"game-main-getmodulefilename-native.json").write_text(json.dumps(report,indent=2)+"\n")
    summary="\n".join([
       "# MX Bikes real game-main native GetModuleFileNameA handoff","",
       "- Original game main -> original callee return joined: **YES**",
       "- New post-return original game-main instructions executed natively: **3**",
       "- Original direct Win64 import identity: **KERNEL32.dll!GetModuleFileNameA**",
       "- Original-x64 controlled API response / native ARM64 matching cases: **"+
           str(len(original_cases))+"/"+str(len(original_cases))+"**",
       "- Original guest path bytes, ABI registers, flags and return stack compared: **YES**",
       "- Native return to original game main: **0x13675c**",
       "- Unsupported or unmapped API inputs rejected: **YES**",
       "",
       "**The filename is a synthetic, explicitly supplied host fixture, not a discovered real Windows process path. "
       "We stop at the instruction after the import. The game engine and rendering are not running.**",""
    ])
    (directory/"game-main-getmodulefilename-native.md").write_text(summary)
    print(summary)
    return report

if __name__=="__main__":
    if len(sys.argv)!=3:
        raise SystemExit("usage: original_game_module_name.py SHA-verified-exe outdir")
    run(Path(sys.argv[1]),Path(sys.argv[2]))
