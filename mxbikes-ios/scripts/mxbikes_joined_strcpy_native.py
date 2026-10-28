#!/usr/bin/env python3
"""Continuous original MX Bikes main -> module filename -> helper -> strcpy.

Original x64 executes owned PE CALLs, indirect IAT thunk instructions, and
controlled explicitly modeled KERNEL32/MSVCR90 service responses. Native
AArch64 executes real prefix/linker/helpers and bounded compatible services.
Original Windows DLL bodies themselves are not executed in either mode.
Stops at helper RVA 0x15b7aa; no full engine or rendering.
"""
from pathlib import Path
import hashlib,json,struct,subprocess,sys,tempfile
from unicorn import UC_HOOK_CODE
from unicorn.x86_const import (
 UC_X86_REG_RIP,UC_X86_REG_RSP,UC_X86_REG_RAX,UC_X86_REG_RCX,
 UC_X86_REG_RDX,UC_X86_REG_R8,UC_X86_REG_R9,
 UC_X86_REG_RBX,UC_X86_REG_RDI,UC_X86_REG_RSI,
 UC_X86_REG_R11,UC_X86_REG_R10,UC_X86_REG_EFLAGS
)
from mxbikes_main_filename_native import (
 BASE,MAIN,AFTER_IMPORT,AFTER_CALL,CALL_IMPORT,HOST_STUB,
 PATH,PATH_LEN,WINDOW,verify_next_import,
 inspect_original,new_cpu,original_run,
 original_main_with_module_name,NUM_CASES,BYTE_CASES,
 ENTRY_SP,TEST_INPUT,SEED_RBX,SEED_RDI,SEED_RSI,SEED_R11,EXE_SHA
)
from mxbikes_filename_helper_native import (
 generate_next_source,verify_helper,NEXT_CALL,AFTER_HELPER_CALL
)
from mxbikes_msvcr90_strcpy_native import original_thunk,THUNK,RETURN,MAX
from mxbikes_post_filename_probe import original_probe
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/"arm64-lab"))
from tools.pe_probe import PE
from tools.import_aot_smoke import execute_arm64_elf

GUEST_CRT=HOST_STUB+0x1000
STACK_MAIN_RSP=ENTRY_SP-0x288
HELPER_LOCAL_RSP=STACK_MAIN_RSP-8-0x38
CASES=[k for k in range(NUM_CASES) if BYTE_CASES[k]==0]

def original_joined(pe,layout,module_iat,strcpy_iat,dest,k):
    uc=new_cpu(pe)
    uc.mem_map(HOST_STUB,0x2000)
    uc.mem_write(HOST_STUB,b"\xc3")
    uc.mem_write(GUEST_CRT,b"\xc3")
    uc.mem_write(BASE+module_iat,struct.pack("<Q",HOST_STUB))
    uc.mem_write(BASE+strcpy_iat,struct.pack("<Q",GUEST_CRT))
    uc.mem_write(TEST_INPUT,b"\x00")
    uc.mem_write(ENTRY_SP,struct.pack("<Q",BASE+0x777777))
    regs={
      UC_X86_REG_RIP:BASE+MAIN,UC_X86_REG_RSP:ENTRY_SP,
      UC_X86_REG_RAX:0x888876543210+k,UC_X86_REG_RBX:SEED_RBX,
      UC_X86_REG_RCX:BASE,UC_X86_REG_RDX:0,
      UC_X86_REG_R8:TEST_INPUT,UC_X86_REG_R9:10,
      UC_X86_REG_RDI:SEED_RDI,UC_X86_REG_RSI:SEED_RSI,
      UC_X86_REG_R11:SEED_R11,UC_X86_REG_R10:0x78123456789,
      UC_X86_REG_EFLAGS:0x202|[0,1,0x40,0x80,0xc1,0x41,0x200,0x81][k%8]
    }
    for r,v in regs.items():uc.reg_write(r,v)
    reached=[]
    def import_service(c,pc,size,ctx):
        if pc==HOST_STUB:
            if (c.reg_read(UC_X86_REG_RCX)!=0 or
               c.reg_read(UC_X86_REG_RDX)!=STACK_MAIN_RSP+0x140 or
               c.reg_read(UC_X86_REG_R8)!=WINDOW):
                raise RuntimeError("Original module API arguments changed")
            c.mem_write(STACK_MAIN_RSP+0x140,PATH+b"\x00")
            c.reg_write(UC_X86_REG_RAX,PATH_LEN)
            reached.append("GetModuleFileNameA")
        elif pc==GUEST_CRT:
            dst=c.reg_read(UC_X86_REG_RCX)
            src=c.reg_read(UC_X86_REG_RDX)
            if dst!=dest or src!=STACK_MAIN_RSP+0x140:
                raise RuntimeError("Original strcpy CRT arguments changed")
            data=bytearray()
            for i in range(MAX):
                b=bytes(c.mem_read(src+i,1))
                data+=b
                if b==b"\x00":break
            else:raise RuntimeError("Original helper string lacked NUL")
            c.mem_write(dst,bytes(data))
            c.reg_write(UC_X86_REG_RAX,dst)
            reached.append("strcpy")
    uc.hook_add(UC_HOOK_CODE,import_service)
    uc.emu_start(BASE+MAIN,BASE+RETURN,timeout=4500000,count=110)
    if(uc.reg_read(UC_X86_REG_RIP)!=BASE+RETURN or
       reached!=["GetModuleFileNameA","strcpy"]):
        raise RuntimeError("Original modeled x64 main+CRT path didn't reach helper continuation")
    flags=uc.reg_read(UC_X86_REG_EFLAGS)
    values={
      "rax":uc.reg_read(UC_X86_REG_RAX),"rdx":uc.reg_read(UC_X86_REG_RDX),
      "rcx":uc.reg_read(UC_X86_REG_RCX),"rsp":uc.reg_read(UC_X86_REG_RSP),
      "rip":uc.reg_read(UC_X86_REG_RIP),
      "cf":int(bool(flags&1)),"zf":int(bool(flags&64)),
      "sf":int(bool(flags&128)),
      "dest_bytes":list(bytes(uc.mem_read(dest,MAX))),
      "strcpy_return_slot":struct.unpack("<Q",bytes(uc.mem_read(HELPER_LOCAL_RSP-8,8)))[0],
      "helper_return_slot":struct.unpack("<Q",bytes(uc.mem_read(STACK_MAIN_RSP-8,8)))[0],
      "import_sequence":reached
    }
    if (values["rax"]!=dest or values["rsp"]!=HELPER_LOCAL_RSP or
       values["strcpy_return_slot"]!=BASE+RETURN or
       values["helper_return_slot"]!=BASE+AFTER_HELPER_CALL):
        raise RuntimeError("Original guest CRT call/return stack verification mismatch")
    return values

EXTRA=r'''
#include "mx_game_crt_strcpy.h"
#define STRING_DEST UINT64_C(__STRING_DEST__)
#define STRING_DEST_PAGE UINT64_C(__STRING_DEST_PAGE__)
#define IMPORT_STRCPY_CALL (BASE+UINT64_C(0x15b7a5))
#define IMPORT_STRCPY_THUNK (BASE+UINT64_C(0x2ab41a))
#define STRCPY_RETURN (BASE+UINT64_C(0x15b7aa))
#define STRCPY_GUEST_CASES __STRCPY_CASES__U
typedef struct {
 uint32_t case_index;
 uint64_t rax,rdx,rcx,rsp,rip;
 uint8_t cf,zf,sf;
 uint8_t dest_bytes[260];
 uint64_t strcpy_return,helper_return;
} joined_strcpy_case;
static const joined_strcpy_case strcpy_fixtures[STRCPY_GUEST_CASES]={
__STRCPY_FIXTURES__
};
static uint8_t destination_page[4096U];
static int final_strcpy_smoke(void){
 mx_cfg_region regions[PAGE_COUNT+3U];
 regions[0].base=STACK;regions[0].data=stack_bytes;regions[0].length=131072U;
 regions[1].base=DATA;regions[1].data=input_data;regions[1].length=4096U;
 for(unsigned j=0;j<PAGE_COUNT;j++){
   regions[2U+j].base=mapped_original_pages[j];
   regions[2U+j].data=original_image_pages[j];
   regions[2U+j].length=4096U;
 }
 regions[PAGE_COUNT+2U].base=STRING_DEST_PAGE;
 regions[PAGE_COUNT+2U].data=destination_page;
 regions[PAGE_COUNT+2U].length=4096U;
 mx_cfg_memory guest={regions,PAGE_COUNT+3U};
 mx_native_link_registry registry={0};
 registry.entries=linked_game_functions;registry.count=2U;
 registry.max_depth=4U;
 if(mx_native_link_seal(&registry)!=MX_NATIVE_LINK_OK)return 50;
 mx_game_module_context module={host_module_path,MODULE_PATH_LEN};
 for(unsigned k=0;k<STRCPY_GUEST_CASES;k++){
   const joined_strcpy_case*t=&strcpy_fixtures[k];
   const fixture*b=&fixtures[t->case_index];
   if(b->in_byte!=0U)return 51;
   for(unsigned n=0;n<131072U;n++)stack_bytes[n]=0U;
   for(unsigned p=0;p<PAGE_COUNT;p++)
      for(unsigned n=0;n<4096U;n++)original_image_pages[p][n]=0U;
   for(unsigned n=0;n<4096U;n++)destination_page[n]=0U;
   input_data[0x100U]=0U;
   uint64_t cookie=b->pre[0],arg0=b->pre[1],arg1=b->pre[2];
   uint64_t callee0=b->pre[4];
   uint32_t show=(uint32_t)b->pre[3],callee1=(uint32_t)b->pre[5];
   uint64_t main_ret=BASE+UINT64_C(0x777777);
   if(!mx_cfg_transfer(&guest,COOKIE,&cookie,8U,1)||
      !mx_cfg_transfer(&guest,ARG0,&arg0,8U,1)||
      !mx_cfg_transfer(&guest,ARG1,&arg1,8U,1)||
      !mx_cfg_transfer(&guest,SHOW,&show,4U,1)||
      !mx_cfg_transfer(&guest,CALLEE_G0,&callee0,8U,1)||
      !mx_cfg_transfer(&guest,CALLEE_G1,&callee1,4U,1)||
      !mx_cfg_transfer(&guest,ENTRY_SP,&main_ret,8U,1))
      return 52;
   mx_crt_cluster_state s={0};
   s.rip=MAIN;s.rsp=ENTRY_SP;
   s.rax=UINT64_C(0x888876543210)+t->case_index;
   s.rbx=UINT64_C(0x123456789abcd);
   s.rcx=BASE;s.rdx=0U;s.r8=TEST_INPUT;s.r9=10U;
   s.rdi=UINT64_C(0x5778899aabbcc);
   s.rsi=UINT64_C(0x1123456789abc);
   s.r11=UINT64_C(0x54111122223333);
   if(main_to_callee(&s,&guest,&registry)!=MX_NATIVE_LINK_OK)return 53;
   if(mx_game_main_filename_prepare(&s,AFTER_CALL,IMPORT_CALL)!=
      MX_GAME_FILENAME_OK)return 54;
   if(mx_game_main_filename_import_call(&s,&guest,&module,
      IMPORT_CALL,AFTER_IMPORT)!=MX_GAME_FILENAME_OK)return 55;
   if(mx_game_main_prepare_path_helper(&s,AFTER_IMPORT,HELPER_ENTRY_CALL)!=
      MX_GAME_PATH_HELPER_FRONTIER)return 56;
   s.instructions++;
   if(mx_native_link_call_prologue_frontier(
      &registry,&s,&guest,HELPER,HELPER_MAIN_RETURN,
      HELPER_FIRST_TRANSFER,0x38U)!=MX_NATIVE_LINK_FRONTIER_REACHED)
      return 57;
   if(mx_game_crt_strcpy_import_call(&s,&guest,
      IMPORT_STRCPY_CALL,IMPORT_STRCPY_THUNK,STRCPY_RETURN,260U)!=
      MX_GAME_STRCPY_OK)return 58;
   if(s.rax!=t->rax||s.rdx!=t->rdx||s.rcx!=t->rcx||
      s.rsp!=t->rsp||s.rip!=t->rip||
      s.cf!=t->cf||s.zf!=t->zf||s.sf!=t->sf||
      s.instructions!=32U||s.imports!=2U)
      return 59;
   for(unsigned n=0;n<260U;n++){
      uint8_t value=0U;
      if(!mx_cfg_transfer(&guest,STRING_DEST+n,&value,1U,0)||
         value!=t->dest_bytes[n])return 60;
   }
   if(read_guest(&guest,s.rsp-8U,8U)!=t->strcpy_return ||
      read_guest(&guest,ENTRY_SP-0x288U-8U,8U)!=t->helper_return)
      return 61;
 }
 if(registry.calls_attempted!=2U*STRCPY_GUEST_CASES ||
    registry.calls_completed!=STRCPY_GUEST_CASES ||
    registry.unresolved_calls||registry.active_depth)
    return 62;
 return 0;
}
'''

def generate_joined(layout,first_refs,name_refs,helper_refs,final_refs,constant,dest):
    base=generate_next_source(layout,first_refs,name_refs,helper_refs,constant)
    original_main="int smoke(void){int prior=earlier_smoke();return prior?prior:helper_smoke();}"
    if base.count(original_main)!=1:
        raise RuntimeError("Original helper test wrapper changed")
    base=base.replace(original_main,
        "static int before_strcpy_smoke(void){int prior=earlier_smoke();return prior?prior:helper_smoke();}")
    rows=[]
    for idx,values in final_refs:
        nums=[values[k] for k in ("rax","rdx","rcx","rsp","rip")]
        rows.append("{"+str(idx)+","+
           ",".join("UINT64_C("+str(v)+")" for v in nums)+","+
           ",".join(str(values[k]) for k in ("cf","zf","sf"))+","+
           "{"+",".join(str(x) for x in values["dest_bytes"])+"},"+
           "UINT64_C("+str(values["strcpy_return_slot"])+"),"+
           "UINT64_C("+str(values["helper_return_slot"])+")}")
    extra=EXTRA.replace("__STRING_DEST__",str(dest)).replace(
        "__STRING_DEST_PAGE__",str(dest&~4095)).replace(
        "__STRCPY_CASES__",str(len(final_refs))).replace(
        "__STRCPY_FIXTURES__",",\n".join(rows))
    if "__STRCPY" in extra or "__STRING" in extra:
        raise RuntimeError("Unexpanded native helper/CRT placeholders")
    src=base.replace("#ifdef HOST",extra+
      "\nint smoke(void){int x=before_strcpy_smoke();return x?x:final_strcpy_smoke();}\n#ifdef HOST")
    return src

def run(executable,out):
    pe=PE(executable)
    if hashlib.sha256(pe.b).hexdigest()!=EXE_SHA:
        raise RuntimeError("Original game executable SHA mismatch")
    layout,_,_=inspect_original(pe)
    first_slot=verify_next_import(pe)
    second_slot,dest=original_thunk(pe)
    _,stop,constant=verify_helper(pe)
    first_refs=[original_run(pe,layout,i) for i in range(NUM_CASES)]
    name_refs=[(i,original_main_with_module_name(pe,layout,first_slot,i))
               for i in CASES]
    helper_refs=[(i,original_probe(pe,layout,first_slot,stop,i))
                 for i in CASES]
    final_refs=[(i,original_joined(pe,layout,first_slot,second_slot,dest,i))
                for i in CASES]
    src=generate_joined(layout,first_refs,name_refs,helper_refs,final_refs,constant,dest)
    with tempfile.TemporaryDirectory(prefix="mxb-connected-crt-string-") as td:
        tmp=Path(td);private=tmp/"owned-game-joined-strcpy.c";private.write_text(src)
        args=["-std=c11","-O2","-Wall","-Wextra","-Werror",
              "-I",str(ROOT/"arm64-lab"/"runtime")]
        host=tmp/"host"
        p=subprocess.run(["cc",*args,"-DHOST",str(private),"-o",str(host)],
                         capture_output=True,text=True)
        if p.returncode:raise RuntimeError("Host compiler: "+p.stderr[-3000:])
        p=subprocess.run([str(host)],capture_output=True,text=True)
        if p.returncode:raise RuntimeError("Host joined native game mismatch exit "+str(p.returncode))
        arm=tmp/"joined-native-ARM64.elf"
        p=subprocess.run(["clang","--target=aarch64-unknown-linux-gnu",
           "-fuse-ld=lld","-nostdlib","-static","-ffreestanding",
           "-fno-builtin","-fno-stack-protector",*args,
           "-Wl,-e,smoke","-Wl,-z,max-page-size=4096",
           "-Wl,--build-id=none",str(private),"-o",str(arm)],
           capture_output=True,text=True)
        if p.returncode:raise RuntimeError("ARM64 compiler: "+p.stderr[-3000:])
        result=execute_arm64_elf(arm,instruction_budget=1950000,timeout_us=15000000)
        if result["arm64_smoke_exit"]!=0:
            raise RuntimeError("Native ARM64 connected-game string import mismatch")
    out.mkdir(parents=True,exist_ok=True)
    report={
        "original_game_SHA_verified":True,
        "main_callee_filename_and_helper_joined":True,
        "new_original_msvcr90_thunk_and_call_joined":True,
        "original_x64_vs_aarch64_joined_cases":len(final_refs),
        "first_import":"KERNEL32.dll!GetModuleFileNameA",
        "second_import":"MSVCR90.dll!strcpy",
        "native_guest_string_global_written":True,
        "original_helper_continuation_rva":hex(RETURN),
        "full_original_helper_returned":False,
        "original_win32_and_crt_dll_bodies_executed":False,
        "engine_initialized":False,"iOS_app_built":False,
        "scope":"The continuous native main path exercises two modeled imports and returns to original helper code at RVA 0x15b7aa"
    }
    (out/"joined-msvcr90-strcpy-native.json").write_text(json.dumps(report,indent=2)+"\n")
    text="\n".join([
       "# MX Bikes — joined native main through two original imported services","",
       "- Authentic native path: main → first callee RET → KERNEL32 GetModuleFileNameA → internal filename helper → MSVCR90 strcpy",
       "- Matched original x64 + controlled DLL model vs native ARM64: **"+str(len(final_refs))+"/"+str(len(final_refs))+"**",
       "- Verified guest global filename buffer, registers, flags and stack: **YES**",
       "- Next native continuation reached: **0x15b7aa**",
       "",
       "**Both external DLL responses are explicit portable models, not real DLL execution. Full engine startup and iOS graphics remain unimplemented.**",""
    ])
    (out/"joined-msvcr90-strcpy-native.md").write_text(text)
    print(text)
    return report

if __name__=="__main__":
    if len(sys.argv)!=3:
        raise SystemExit("usage: joined_strcpy.py original_exe metadata")
    run(Path(sys.argv[1]),Path(sys.argv[2]))
