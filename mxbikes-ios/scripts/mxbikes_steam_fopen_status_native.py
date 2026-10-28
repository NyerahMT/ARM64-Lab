#!/usr/bin/env python3
"""Cumulative AArch64 Win64 CRT fopen/TEST/JNE and success-path fseek setup.

Only the genuinely present DLL in the SHA-verified private owned ZIP
permits the guest FILE* token. This is an OPEN-STATUS adapter only, not
an implementation of DLL execution, fread, fseek, SteamAPI_Init or auth.

Dynamically differential original x64 modeled fopen service and host C and
actually executed AArch64. Stop before original fseek import CALL 0x1305D9.
"""
import json,sys
from pathlib import Path
from unicorn.x86_const import (
 UC_X86_REG_RIP,UC_X86_REG_RSP,UC_X86_REG_RAX,
 UC_X86_REG_RBX,UC_X86_REG_RCX,UC_X86_REG_RDX,
 UC_X86_REG_R8,UC_X86_REG_RSI,UC_X86_REG_RDI,
 UC_X86_REG_R12,UC_X86_REG_EFLAGS
)
import mxbikes_next_outer_init_native as previous
import mxbikes_steam_fopen_result_probe as fopen_ref
import mxbikes_init_child_successors_native as startup
import mxbikes_main_joined_callee_native as joined

BASE=joined.BASE
CALL=0x1305a9
AFTER=0x1305ae
RESULT_JNE=0x1305b4
OPEN=0x1305c0
MISSING=0x1305b6
FSEEK_CALL=0x1305d9
FILE_RVA=fopen_ref.FILE_ARG
MODE_RVA=fopen_ref.MODE_ARG
STRINGS_PAGE=0x342000
HANDLE=fopen_ref.HANDLE
EXPECTED=("rip","rsp","rax","rbx","rcx","rdx","r8","rsi","rdi",
          "r12","original_return_slot","saved_rbx","saved_rsi",
          "zf","sf","cf")
SYNTH=(0,1,2,0x80000000)
OWNED_DLL_PRESENT=False

def validate(pe):
    t,f=fopen_ref.validate(pe)
    if (t,f)!=(OPEN,MISSING):
        raise ValueError("Original Steam DLL fopen result branch changed")
    from capstone import Cs,CS_ARCH_X86,CS_MODE_64
    from capstone.x86 import X86_OP_IMM
    md=Cs(CS_ARCH_X86,CS_MODE_64);md.detail=True
    rows=list(md.disasm(pe.read_rva(OPEN,FSEEK_CALL+5-OPEN),OPEN))
    expected=[
       ("xor","edx, edx"),("mov","rcx, rax"),
       ("mov","qword ptr [rsp + 0x440], rbx"),
       ("lea","r8d, [rdx + 2]"),
       ("mov","qword ptr [rsp + 0x450], rsi"),
       ("call","0x2aaf28")
    ]
    if (len(rows)!=len(expected) or
        [(x.mnemonic,x.op_str) for x in rows]!=expected or
        rows[-1].address!=FSEEK_CALL or
        sum(x.size for x in rows)!=FSEEK_CALL+5-OPEN):
        raise ValueError("Original x64 fopen success fseek-prep instruction batch changed")

def reference(pe,dword,rbx,rsi,rdi,opened):
    if 1<dword<0x80000000:return None
    outcome,uc=fopen_ref.original_case(
       pe,dword,HANDLE if opened else 0,OPEN,MISSING,
       return_cpu=True,rbx=rbx,rsi=rsi,rdi=rdi)
    if opened:
        uc.emu_start(BASE+OPEN,BASE+FSEEK_CALL,
                     timeout=3000000,count=5)
        if uc.reg_read(UC_X86_REG_RIP)!=BASE+FSEEK_CALL:
            raise ValueError("Original guest x64 fopen success path did not reach fseek")
    else:
        if uc.reg_read(UC_X86_REG_RIP)!=BASE+MISSING:
            raise ValueError("Original guest x64 fopen fail branch unexpectedly succeeded")
    sp=uc.reg_read(UC_X86_REG_RSP)
    flags=uc.reg_read(UC_X86_REG_EFLAGS)
    row={
      "rip":uc.reg_read(UC_X86_REG_RIP),
      "rsp":sp,"rax":uc.reg_read(UC_X86_REG_RAX),
      "rbx":uc.reg_read(UC_X86_REG_RBX),
      "rcx":uc.reg_read(UC_X86_REG_RCX),
      "rdx":uc.reg_read(UC_X86_REG_RDX),
      "r8":uc.reg_read(UC_X86_REG_R8),
      "rsi":uc.reg_read(UC_X86_REG_RSI),
      "rdi":uc.reg_read(UC_X86_REG_RDI),
      "r12":uc.reg_read(UC_X86_REG_R12),
      "original_return_slot":int.from_bytes(uc.mem_read(sp-8,8),"little"),
      "saved_rbx":int.from_bytes(uc.mem_read(sp+0x440,8),"little"),
      "saved_rsi":int.from_bytes(uc.mem_read(sp+0x450,8),"little"),
      "zf":int(bool(flags&64)),
      "sf":int(bool(flags&128)),
      "cf":int(bool(flags&1))
    }
    if row["original_return_slot"]!=BASE+AFTER:
        raise ValueError("Original Win64 fopen return slot changed")
    if opened and (row["r12"]!=HANDLE or row["rcx"]!=HANDLE or
                   row["rdx"]!=0 or row["r8"]!=2 or
                   row["saved_rbx"]!=rbx or row["saved_rsi"]!=0):
        raise ValueError("Original x64 fopen-success argument setup drifted: "+
            repr({"r12":row["r12"],"rcx":row["rcx"],"rdx":row["rdx"],
                  "r8":row["r8"],"rbx_saved":row["saved_rbx"],
                  "rbx_seed":rbx,"rsi_saved":row["saved_rsi"],
                  "rsi_original_seed":rsi}))
    return row

def to_c(row):
    return " {"+",".join("UINT64_C("+str(row[k])+")" for k in EXPECTED)+"}"

def extend(pe,source,cases):
    validate(pe)
    if len(cases)!=16:raise ValueError("Original cumulative game parser coverage changed")
    refs=[]
    for _,r,_,kind in cases:
        valid=kind=="returned" and r["rip"]==BASE+joined.AFTER_CALL
        refs.append(reference(pe,r["callee_global1"],r["rbx"],r["rsi"],r["rdi"],
                              OWNED_DLL_PRESENT) if valid else None)
    syn=[reference(pe,dword,startup.SAVED_RBX,startup.SAVED_RSI,
                    startup.SAVED_RDI,OWNED_DLL_PRESENT) for dword in SYNTH]
    if sum(r is not None for r in syn)!=3:
        raise ValueError("Missing original x64 controlled-file-return reference variants")
    def rep(a,b):
        nonlocal source
        if source.count(a)!=1:raise ValueError("Original native startup source integration moved "+a[:65])
        source=source.replace(a,b)
    anchor="static int main_to_callee(mx_crt_cluster_state*s,mx_cfg_memory*m,"
    def c_initializer():
        raw=[(MODE_RVA & 4095,b"rb\x00"),
             (FILE_RVA & 4095,b"steam_api64.dll\x00")]
        points=[]
        for offset,data in raw:
            points.extend(f"[{offset+i}]={int(value)}U" for i,value in enumerate(data))
        return ",".join(points)
    literals=f"""
static uint8_t steam_file_name_and_mode_literals[4096U]={{{c_initializer()}}};
"""
    helper=f"""
/* Fail-closed, bounded original guest fopen file existence adapter.
 * This models FILE* open status only when the SHA-verified owned archive
 * contains the real DLL; it never executes, trusts or authenticates Steam.
 * No host filesystem functions or undocumented dynamic loading. */
static int native_original_owned_fopen_result(
    mx_crt_cluster_state*s,mx_cfg_memory*m,mx_init_extra_regs*extra,
    uint8_t owned_dll_present){{
 if(!s||!m||!extra||s->fault||s->rip!=UINT64_C({BASE+CALL})||
    (s->rsp&15U)!=0U||s->rsp<16U||
    s->rcx!=UINT64_C({BASE+FILE_RVA})||
    s->rdx!=UINT64_C({BASE+MODE_RVA}))return 130;
 static const uint8_t filename[]={{{",".join(str(k)+"U" for k in b"steam_api64.dll\x00")}}};
 static const uint8_t mode[]={{{",".join(str(k)+"U" for k in b"rb\x00")}}};
 uint8_t v=0U;
 for(unsigned i=0U;i<sizeof(filename);i++){{
    if(!mx_cfg_transfer(m,s->rcx+i,&v,1U,0)||
       v!=filename[i])return 131;
 }}
 for(unsigned i=0U;i<sizeof(mode);i++){{
    if(!mx_cfg_transfer(m,s->rdx+i,&v,1U,0)||
       v!=mode[i])return 132;
 }}
 const uint64_t ret_slot=s->rsp-8U;
 uint64_t old=0U;
 if(!mx_cfg_transfer(m,ret_slot,&old,8U,0))return 133;
 uint64_t retval=UINT64_C({BASE+AFTER});
 if(!mx_cfg_transfer(m,ret_slot,&retval,8U,1))return 134;
 const uint64_t pointer=owned_dll_present?UINT64_C({HANDLE}):0U;
 s->rax=pointer;extra->r12=pointer;
 s->zf=(uint8_t)(pointer==0U);s->sf=0U;s->cf=0U;
 s->rip=pointer?UINT64_C({BASE+OPEN}):UINT64_C({BASE+MISSING});
 s->imports+=1U;
 s->instructions+=6U; /* CALL, original JMP thunk, virtual RET,
                         * MOV R12,RAX, TEST, JNE */
 return MX_NATIVE_LINK_FRONTIER_REACHED;
}}
static int native_original_fseek_precontrol(mx_crt_cluster_state*s,
     mx_cfg_memory*m,mx_init_extra_regs*extra){{
 if(!s||!m||!extra||s->fault||
    s->rip!=UINT64_C({BASE+OPEN})||
    s->rax!=UINT64_C({HANDLE}))return 135;
 uint64_t old=0U;
 if(!mx_cfg_transfer(m,s->rsp+0x440U,&old,8U,0)||
    !mx_cfg_transfer(m,s->rsp+0x450U,&old,8U,0))return 136;
 uint64_t rbx=s->rbx,rsi=s->rsi;
 if(!mx_cfg_transfer(m,s->rsp+0x440U,&rbx,8U,1)||
    !mx_cfg_transfer(m,s->rsp+0x450U,&rsi,8U,1))return 137;
 s->rdx=0U;s->rcx=s->rax;s->r8=2U;
 s->zf=1U;s->sf=0U;s->cf=0U;
 s->rip=UINT64_C({BASE+FSEEK_CALL});
 s->instructions+=5U; /* original XOR, MOV, MOV, LEA, MOV */
 return MX_NATIVE_LINK_FRONTIER_REACHED;
}}
static int verify_original_fopen_and_seek(const mx_crt_cluster_state*s,
     mx_cfg_memory*m,const mx_init_extra_regs*extra,const uint64_t*ref){{
 if(s->rip!=ref[0])return 1;
 if(s->rsp!=ref[1])return 2;
 if(s->rax!=ref[2])return 3;
 if(s->rbx!=ref[3])return 4;
 if(s->rcx!=ref[4])return 5;
 if(s->rdx!=ref[5])return 6;
 if(s->r8!=ref[6])return 7;
 if(s->rsi!=ref[7])return 8;
 if(s->rdi!=ref[8])return 9;
 if(extra->r12!=ref[9])return 10;
 if(read_guest(m,s->rsp-8U,8U)!=ref[10])return 11;
 if(read_guest(m,s->rsp+0x440U,8U)!=ref[11])return 12;
 if(read_guest(m,s->rsp+0x450U,8U)!=ref[12])return 13;
 if(s->zf!=ref[13]||s->sf!=ref[14]||s->cf!=ref[15])return 14;
 return 0;
}}
"""
    rep(anchor,literals+helper+anchor)
    refs_c="static const uint64_t original_fopen_opened_refs[CASES][16]={"+",".join(
               to_c(r) if r else " {0}" for r in refs)+"};\n"
    syn_c="static const uint64_t original_fopen_synthetic[4][16]={"+",".join(
               to_c(r) if r else " {0}" for r in syn)+"};\n"
    rep(anchor,refs_c+syn_c+anchor)
    rep("mx_cfg_region regions[PAGE_COUNT+5U];",
        "mx_cfg_region regions[PAGE_COUNT+6U];")
    rep(" mx_cfg_memory mem={regions,PAGE_COUNT+5U};",
      f""" regions[PAGE_COUNT+5U].base=UINT64_C({BASE+STRINGS_PAGE});
 regions[PAGE_COUNT+5U].data=steam_file_name_and_mode_literals;
 regions[PAGE_COUNT+5U].length=4096U;
 mx_cfg_memory mem={{regions,PAGE_COUNT+6U}};""")
    rep(" unsigned next_initializer_frontiers=0U;",
        " unsigned next_initializer_frontiers=0U;\n unsigned actual_open_status_frontiers=0U;")
    after="         next_initializer_frontiers++;"
    native=f"""
         const unsigned before_open=s.instructions;
         const unsigned before_imports=s.imports;
         if(native_original_owned_fopen_result(&s,&mem,&extra,
                 {1 if OWNED_DLL_PRESENT else 0}U)!=MX_NATIVE_LINK_FRONTIER_REACHED)
             return 138;
         if(s.rip==UINT64_C({BASE+OPEN})){{
            if(native_original_fseek_precontrol(&s,&mem,&extra)!=
               MX_NATIVE_LINK_FRONTIER_REACHED)return 139;
         }}
         if(s.instructions!=before_open+
             ({5 if OWNED_DLL_PRESENT else 0}U+6U)||
            s.imports!=before_imports+1U)return 140;
         const int err=verify_original_fopen_and_seek(
              &s,&mem,&extra,original_fopen_opened_refs[i]);
         if(err)return 141+err;
         actual_open_status_frontiers++;
"""
    rep(after,after+"\n"+native)
    syn="          if(actual)return 192+actual;"
    syn_native=f"""
          if(original_fopen_synthetic[v][0]!=0U){{
             const unsigned before_open=trial.instructions;
             if(native_original_owned_fopen_result(&trial,&mem,&trial_extra,
                   {1 if OWNED_DLL_PRESENT else 0}U)!=MX_NATIVE_LINK_FRONTIER_REACHED)
                return 158;
             if(trial.rip==UINT64_C({BASE+OPEN})){{
                if(native_original_fseek_precontrol(&trial,&mem,&trial_extra)!=
                    MX_NATIVE_LINK_FRONTIER_REACHED)return 159;
             }}
             if(trial.instructions!=before_open+
                  (6U+{5 if OWNED_DLL_PRESENT else 0}U))return 160;
             const int mismatch=verify_original_fopen_and_seek(
                  &trial,&mem,&trial_extra,original_fopen_synthetic[v]);
             if(mismatch)return 161+mismatch;
          }}
"""
    rep(syn,syn+"\n"+syn_native)
    n=sum(r is not None for r in refs)
    gate=" if(next_initializer_frontiers!="+str(n)+"U)return 220;"
    rep(gate,gate+"\n if(actual_open_status_frontiers!="+str(n)+"U)return 175;")
    return source

def run(executable,out):
    from tools.pe_probe import PE
    global OWNED_DLL_PRESENT
    manifest_file=out/"owned-steam-file-manifest.json"
    if not manifest_file.is_file():
        raise ValueError("Cannot model fopen without private owned archive manifest")
    manifest=json.loads(manifest_file.read_text())
    if manifest["matching_owned_dll_count"] not in (0,1):
        raise ValueError("Ambiguous owned steam_api64.dll match")
    OWNED_DLL_PRESENT=(
         manifest["steam_api64_dll_present"] is True and
         manifest["matching_owned_dll_count"]==1 and
         isinstance(manifest["owned_dll_size_bytes"],int) and
         manifest["owned_dll_size_bytes"]>0)
    from tools.pe_probe import PE
    pe=PE(executable);validate(pe)
    prev=previous.run(executable,out,native_extension=extend)
    if not prev["aarch64_next_callee_first_block_executed"]:
        raise ValueError("Earlier original ARM64 initializer path regressed")
    report={
        "original_sha256":prev["original_sha256"],
        "original_service":"MSVCR90.dll!fopen",
        "original_argument_file":"steam_api64.dll",
        "original_argument_mode":"rb",
        "owned_dll_file_present":OWNED_DLL_PRESENT,
        "native_virtual_fopen_open_status_executed":True,
        "native_original_fseek_argument_setup_executed":OWNED_DLL_PRESENT,
        "next_original_import_call_rva":hex(FSEEK_CALL),
        "actual_host_file_stream_or_Steam_initialized":False,
        "first_loading_screen_rendered":False
    }
    (out/"joined-native-steam-fopen-status.json").write_text(json.dumps(report,indent=2)+"\n")
    lines=["# MX Bikes — owned-file open status / original fseek arguments on native ARM64","",
       "- Original SHA-pinned DLL name/mode: **steam_api64.dll / rb**",
       "- Private owned Steam DLL present: **"+str(OWNED_DLL_PRESENT)+"**",
       "- Original guest Win64 fopen status branch: **native executed**",
       "- Native original success-path fseek argument setup: **"+str(OWNED_DLL_PRESENT)+"**",
       "- Independent original x64 guest state and guest stack: **verified in host and AArch64**",
       "- Next original CRT import CALL: **"+hex(FSEEK_CALL)+"**",
       "","No actual Steam DLL execution, auth, original FILE stream reads, game engine, or iOS frame.",""]
    (out/"joined-native-steam-fopen-status.md").write_text("\n".join(lines))
    print("\n".join(lines))
    return report

if __name__=="__main__":
    if len(sys.argv)!=3:raise SystemExit("usage: steam_fopen_status.py owned.exe metadata-dir")
    run(Path(sys.argv[1]),Path(sys.argv[2]))
