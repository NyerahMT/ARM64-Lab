#!/usr/bin/env python3
"""Execute real security-cookie check and nested child RET to parent on AArch64.

Only branch-taken original x64 paths are supported. The checker comparison
and high-bit test must pass, otherwise the original failure path is refused.
Non-taken paths retain the prior verified ARM64 frontier.
"""
import json,sys
from pathlib import Path
from capstone import Cs,CS_ARCH_X86,CS_MODE_64,CS_GRP_RET
import mxbikes_init_child_successors_native as prior
import mxbikes_init_child_return_probe as x64
import mxbikes_main_joined_callee_native as joined

BASE=joined.BASE
EARLY=prior.TAKEN_CONTROL
NEXT=x64.NEXT_CALL
CHECK=x64.CHECK_TARGET
RET=x64.CHECK_RETURN
GLOBAL=0x3928a0
ORIGINAL=[
 ("cmp","rcx, qword ptr [rip + 0xe7a39]"),
 ("jne","0x2aae7a"),
 ("rol","rcx, 0x10"),
 ("test","cx, 0xffff"),
 ("jne","0x2aae76"),
]
AFTER=[
 ("add","rsp, 0x160"),("pop","rbx"),("ret","")
]
CONT=[
 ("lea","edx, [rsi + 1]"),("mov","ecx, 0xa008c"),
 ("call","0x130580")
]

def verify(pe):
    prior.validate_original(pe)
    source=x64.inspect(pe)
    if source["authentic_cookie_call"]["callee_rva"]!=hex(CHECK):
        raise ValueError("Security-checker original CALL moved")
    md=Cs(CS_ARCH_X86,CS_MODE_64);md.detail=True
    # Optimized original checker ends in a two-byte return instruction;
    # the conditional failure edge must remain unsupported.
    checker=list(md.disasm(pe.read_rva(CHECK,0x2aae76-CHECK),CHECK))
    checker_forms=[(i.mnemonic,i.op_str) for i in checker]
    if (len(checker)!=6 or checker_forms[:5]!=ORIGINAL or
        checker[-1].address!=0x2aae74 or
        not checker[-1].group(CS_GRP_RET) or
        sum(i.size for i in checker)!=0x2aae76-CHECK):
        raise ValueError("Original x64 optimized checker mismatch "+str(checker_forms))
    for addr,end,expected in (
         (RET,0x133cb5,AFTER),
         (x64.AFTER_CHILD_RET,0x133f08,CONT)):
        rows=list(md.disasm(pe.read_rva(addr,end-addr),addr))
        shapes=[(i.mnemonic,i.op_str) for i in rows]
        if (len(rows)!=len(expected) or shapes!=expected or
            sum(i.size for i in rows)!=end-addr):
            raise ValueError("Original x64 Win64 return identity changed "+
                             hex(addr)+": "+str(shapes))
    if (0x2aae67+0xe7a39)!=GLOBAL:
        raise ValueError("Original cookie RIP-relative address no longer matches")

def expected(pe,value,rbx,rsi,rdi):
    if (0x1 < value < 0x80000000):return None
    ref=x64.original_x64_return(pe,value,rbx=rbx,rsi=rsi,rdi=rdi)
    if (ref["status"]!="reached_next_outer_call" or
        not all(ref[k] for k in (
            "authentic_cookie_checker_called","authentic_cookie_checker_returned",
            "authentic_child_return_reached","authentic_next_outer_call_reached"))):
        raise ValueError("Original x64 authentic full checker return not reached")
    return [
        BASE+int(ref["original_guest_rip"],16),
        int(ref["original_guest_rsp"],16),
        *[int(ref["original_guest_"+r],16) for r in ("rax","rbx","rcx","rdx")],
        ref["original_zf"],ref["original_sf"],ref["original_cf"],
        int(ref["outer_return_slot"],16),int(ref["child_return_slot"],16)
    ]

def as_c(data):
    return " {"+",".join("UINT64_C("+str(v)+")" for v in data)+"}"

def extend(pe,source,cases):
    verify(pe)
    if len(cases)!=16:raise ValueError("Original parser input count changed")
    refs=[]
    for _,row,_,kind in cases:
        valid=kind=="returned" and row["rip"]==BASE+joined.AFTER_CALL
        refs.append(expected(pe,row["callee_global1"],row["rbx"],
                   row["rsi"],row["rdi"]) if valid else None)
    synth=[expected(pe,v,prior.SAVED_RBX,prior.SAVED_RSI,prior.SAVED_RDI)
           for v in prior.SYNTHETIC_CASES]
    if sum(a is not None for a in synth)!=3:
        raise ValueError("Original x64 checker variants no longer span signed branches")
    def rep(a,b):
        nonlocal source
        if source.count(a)!=1:raise ValueError("Cumulative native guest source shifted "+a[:50])
        source=source.replace(a,b)
    anchor="static int main_to_callee(mx_crt_cluster_state*s,mx_cfg_memory*m,"
    array="static const uint64_t original_cookie_returns[CASES][11]={"+",".join(
        as_c(r) if r else " {0}" for r in refs)+"};\n"
    synth_array="static const uint64_t original_cookie_synthetic[4][11]={"+",".join(
        as_c(r) if r else " {0}" for r in synth)+"};\n"
    helper=f"""
static int native_cookie_check_and_child_return(
    mx_crt_cluster_state*s,mx_cfg_memory*m){{
 if(!s||!m||s->fault||s->rip!=UINT64_C({BASE+EARLY})||
    (s->rsp&15U)!=0U||s->rsp<0x180U)return 180;
 const uint64_t frame=s->rsp;
 uint64_t cookie=0U,slot=0U,save=0U,parent_return=0U;
 if(!mx_cfg_transfer(m,UINT64_C({BASE+GLOBAL}),&cookie,8U,0)||
    !mx_cfg_transfer(m,frame-8U,&slot,8U,0)||
    !mx_cfg_transfer(m,frame+0x160U,&save,8U,0)||
    !mx_cfg_transfer(m,frame+0x168U,&parent_return,8U,0))
    return 181;
 if(parent_return!=UINT64_C({BASE+x64.AFTER_CHILD_RET}))return 182;
 /* Faithful original CMP/JNE, ROL 16, TEST CX, JNE. Any failure
  * follows an UNIMPLEMENTED original x64 security-failure branch. */
 if(s->rcx!=cookie)return 183;
 const uint64_t rotated=(cookie<<16U)|(cookie>>48U);
 if((rotated&UINT64_C(0xffff))!=0U)return 184;
 slot=UINT64_C({BASE+RET});
 if(!mx_cfg_transfer(m,frame-8U,&slot,8U,1))return 185;
 const uint64_t after_add=frame+0x160U;
 s->cf=(uint8_t)(after_add<frame);
 s->zf=(uint8_t)(after_add==0U);
 s->sf=(uint8_t)((after_add>>63U)&1U);
 s->rbx=save;
 s->rsp=frame+0x170U;
 s->rax=0U;
 s->rdx=(uint64_t)(uint32_t)(s->rsi+1U);
 s->rcx=UINT64_C(0xa008c);
 s->rip=UINT64_C({BASE+NEXT});
 s->instructions+=12U;
 return MX_NATIVE_LINK_FRONTIER_REACHED;
}}
static int verify_cookie_return(const mx_crt_cluster_state*s,
    mx_cfg_memory*m,const uint64_t*e){{
 if(s->rip!=e[0]||s->rsp!=e[1]||s->rax!=e[2]||
    s->rbx!=e[3]||s->rcx!=e[4]||s->rdx!=e[5])return 1;
 if(s->zf!=e[6]||s->sf!=e[7]||s->cf!=e[8])return 2;
 if(read_guest(m,s->rsp+0x298U,8U)!=e[9])return 3;
 if(read_guest(m,s->rsp-8U,8U)!=e[10])return 4;
 if(read_guest(m,s->rsp-0x170U-8U,8U)!=UINT64_C({BASE+RET}))return 5;
 return 0;
}}
"""
    rep(anchor,helper+array+synth_array+anchor)
    rep(" unsigned native_successor_frontiers=0U;",
        " unsigned native_successor_frontiers=0U;\n unsigned original_child_returns=0U;")
    at="      native_successor_frontiers++;"
    run=f"""
      if(s.rip==UINT64_C({BASE+EARLY})){{
         const unsigned n=s.instructions;
         if(native_cookie_check_and_child_return(&s,&mem)!=
             MX_NATIVE_LINK_FRONTIER_REACHED)return 186;
         if(s.instructions!=n+12U)return 187;
         const int v=verify_cookie_return(&s,&mem,original_cookie_returns[i]);
         if(v)return 190+v;
         original_child_returns++;
      }}
"""
    rep(at,at+"\n"+run)
    syn="    if(synthetic_mismatch)return 140+synthetic_mismatch;"
    synrun=f"""
    if(trial.rip==UINT64_C({BASE+EARLY})){{
       /* The original security failure branch is NOT translated: reject
        * a corrupt cookie without changing guest RIP, RSP or stack. */
       const uint64_t old_pc=trial.rip,old_sp=trial.rsp;
       const uint64_t old_cookie_ret=read_guest(&mem,trial.rsp-8U,8U);
       trial.rcx^=UINT64_C(1);
       if(native_cookie_check_and_child_return(&trial,&mem)!=183||
          trial.rip!=old_pc||trial.rsp!=old_sp||
          read_guest(&mem,old_sp-8U,8U)!=old_cookie_ret)
          return 234;
       trial.rcx^=UINT64_C(1);
       const unsigned n=trial.instructions;
       if(native_cookie_check_and_child_return(&trial,&mem)!=
           MX_NATIVE_LINK_FRONTIER_REACHED)return 200;
       if(trial.instructions!=n+12U)return 201;
       const int mismatch=verify_cookie_return(&trial,&mem,original_cookie_synthetic[v]);
       if(mismatch)return 205+mismatch;
    }}
"""
    rep(syn,syn+"\n"+synrun)
    gate=" if(native_successor_frontiers!=12U)return 253;"
    rep(gate,gate+"\n if(original_child_returns!="+
        str(sum(r is not None for r in refs))+"U)return 211;")
    return source

def run(executable,out,*,native_extension=None):
    from tools.pe_probe import PE
    pe=PE(executable)
    verify(pe)
    def combined_extension(pe,source,cases):
        source=extend(pe,source,cases)
        return native_extension(pe,source,cases) if native_extension is not None else source
    previous=prior.run(executable,out,native_extension=combined_extension)
    if previous["original_x64_host_and_arm64_child_successor_cases"]!=16:
        raise ValueError("Earlier native branch successor cumulative path regressed")
    report={
       "original_sha256":previous["original_sha256"],
       "original_security_cookie_checker_rva":hex(CHECK),
       "original_nested_child_returned_to_outer_rva":hex(x64.AFTER_CHILD_RET),
       "native_aarch64_cookie_return_oracle_variants":3,
       "next_untranslated_original_parent_call_rva":hex(NEXT),
       "full_original_outer_game_initializer_complete":False,
       "engine_or_graphics_running":False}
    (out/"joined-native-nested-child-return.json").write_text(
        json.dumps(report,indent=2)+"\n")
    lines=["# MX Bikes: original nested security-cookie CALL/RET executes on ARM64","",
       "- Genuine checker and Win64 nested child RET: **native executed**",
       "- Independent original x64 checker return variants: **3/3**",
       "- Next original parent CALL: **"+hex(NEXT)+"**",
       "- Security comparison not bypassed; mismatches explicitly fail closed",
       "","Untranslated child JS, outer CALL, engine and first frame still pending.",""]
    (out/"joined-native-nested-child-return.md").write_text("\n".join(lines))
    print("\n".join(lines))
    return report

if __name__=="__main__":
    if len(sys.argv)!=3:
        raise SystemExit("usage: nested_return_native.py original.exe metadata-out")
    run(Path(sys.argv[1]),Path(sys.argv[2]))
