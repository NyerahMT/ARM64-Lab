#!/usr/bin/env python3
"""Authentic four-slot _initterm table: three ordered native callback bodies.

Original callback binaries and generated C objects stay on the ephemeral
private CI runner. Original SHA-pinned table is actually traversed on host
and executed AArch64, with original callback bodies:
  0x2aafc4 : 19 instruction argument setup (direct/import test doubles)
  0x320770: six instruction local CALL + wrapper tail (test doubles)
  0x320790: two instruction tail JMP -> original eight instruction wrapper
             -> actual generated 39 instruction child, six CRT imports mocked.

Each callback boundary is independently compared against its own authentic
original x64 instruction reference. The guest data and CRT globals are shared
across the NATIVE callback sequence, with fresh Win64 test call frames.
THIS DOES NOT execute original x64 _initterm_e/_initterm, nor implement real
MSVCR90, real __getmainargs, Steam, engine or iPhone native startup.
"""
from pathlib import Path
import hashlib
import json
import subprocess
import sys
import tempfile

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/"arm64-lab"))
from tools.pe_probe import PE
from tools.crt_import_cluster_lift import lift_crt_import_cluster
from tools.import_aot_smoke import execute_arm64_elf
from mxbikes_first_callee_emu import import_slots
from mxbikes_crt_exception_callback_differential import BASE,SHA,SP,STOP
from mxbikes_crt_initializer_inventory import inventory
from mxbikes_crt_initializer_table_walk import source_tables
from mxbikes_crt_argsetup_body_differential import (
    ENTRY as ARG_ENTRY,DATA_RVA,DATA_SIZE,
    WRAPPER as WRAPPER_RVA,LOCAL_HELPER,
    calls_and_input,x64_case
)
from mxbikes_crt_second_tail_body_differential import (
    ENTRY as SECOND_ENTRY, LOCAL as SECOND_LOCAL,
    inspect as inspect_second,reference as second_reference
)
from mxbikes_crt_joined_wrapper_child_aot import (
    TAIL_CALLBACK,TAIL_ARGUMENT,verify,verify_tail,
    reference_original as third_reference
)
from mxbikes_crt_child_path_reference import (
    ENTRY as CHILD_ENTRY, END as CHILD_END,THUNKS,GLOBALS,
    cases as child_cases
)

TRACE_ID={
    "_encode_pointer":1,"_decode_pointer":2,"_onexit":3,
    "__dllonexit":4,"_lock":5,"_unlock":6,
}
CHOSEN=(0,1,2,3,8,9,10,11)
U64=(1<<64)-1

def init_values(pe,executable):
    if hashlib.sha256(pe.b).hexdigest()!=SHA:
        raise RuntimeError("Licensed original executable revision moved")
    inv=inventory(executable)
    begin,values,_,_=source_tables(inv)
    if values!=[0,BASE+ARG_ENTRY,BASE+SECOND_ENTRY,BASE+TAIL_CALLBACK]:
        raise RuntimeError("Original _initterm table callbacks changed")
    return begin,values

def u(value):
    return "UINT64_C("+str(value & U64)+")"
def array(values):
    return "{"+",".join(u(int(x)) for x in values)+"}"

def encode_cases(rows):
    encoded=[]
    for arg,second,third,case in rows:
        arglist=[
            u(arg["initial_rcx"]),array(arg["expected"]),
            u(arg["stack_hash"]),u(arg["globals_hash"]),
            str(len(arg["trace"])),
            "{"+",".join(str(v) for v in (arg["trace"]+[0]*3)[:3])+"}",
        ]
        secondlist=[
            u(second["rcx"]),u(second["rbx"]),
            array(second["expected"]),u(second["stack_hash"]),
        ]
        childregs=[
            0xbbbb0000,0xaaaa0000,case["rcx"],0,0,0,0,0,0,
            case["global1"],case["global0"]
        ]
        # The wrapper/child private differential uses these exact initialized
        # inputs, including the same synthetic Win64 nonvolatile registers.
        childlist=[
            array(childregs),
            array([third[n] for n in (
                "rax","rbx","rcx","rdx","r8","rdi","rsi","r11",
                "rsp","rip","zf","g0","g1")]),
            array(case["decode"]),array(case["encode"]),
            u(case["onexit"]),u(case["dll"]),
            u(int(case["update"])),u(case["start"]),u(case["end"]),
            str(len(third["trace"])),
            array([TRACE_ID[s] for s in third["trace"]]+
                  [0]*(10-len(third["trace"]))),
            "{"+",".join(str(byte) for byte in third["stack"])+"}",
        ]
        encoded.append("{"+",".join(arglist+secondlist+childlist)+"}")
    return ",\n".join(encoded)

C=r"""
#include <stdint.h>
#include "mx_crt_joined_wrapper.h"
#include "mx_crt_initializer_walk.h"
#include "mx_crt_process_services.h"
#define SP UINT64_C(__SP__)
#define WIN UINT64_C(__WIN__)
#define STOP_PC UINT64_C(__STOP__)
#define ARG_PC UINT64_C(__ARG__)
#define ARG_LOCAL UINT64_C(__ARG_LOCAL__)
#define SECOND_PC UINT64_C(__SECOND__)
#define SECOND_LOCAL UINT64_C(__SECOND_LOCAL__)
#define WRAPPER_PC UINT64_C(__WRAPPER__)
#define TAIL_PC UINT64_C(__TAIL__)
#define TAIL_ARG UINT64_C(__TAIL_ARG__)
#define CHILD_PC UINT64_C(__CHILD__)
#define ARG_DATA UINT64_C(__ARG_DATA__)
#define CHILD_GLOBALS UINT64_C(__CHILD_GLOBALS__)
#define TABLE_BEGIN UINT64_C(__TABLE_BEGIN__)
#define TABLE_END UINT64_C(__TABLE_END__)
#define SECOND_ARG1 UINT64_C(__SECOND_ARG1__)
#define SECOND_ARG2 UINT64_C(__SECOND_ARG2__)

typedef struct {
 uint64_t argc_rcx,argc_out[14],argc_stack_hash,argc_globals_hash;
 uint32_t argc_trace_len;
 uint8_t argc_trace[3];
 uint64_t second_rcx,second_rbx,second_out[14],second_stack_hash;
 uint64_t child_in[11],child_out[13],decoder[3],encoder[3];
 uint64_t onexit,dll,update,updated0,updated1,child_trace_len;
 uint64_t child_trace[10];
 uint8_t child_stack[256];
} fixture;
static const fixture fixtures[]={__CASES__};
static uint8_t stack_bytes[256],arg_data[8192],child_globals[16];
static uint64_t original_table[4]={__TABLE_VALUES__};
typedef struct {
 mx_cfg_memory *memory;
 const fixture *f;
 uint32_t index,active_stage,events,seen[4];
 uint8_t args_trace[3];
 uint64_t child_trace[10];
 uint32_t child_trace_len,decode_count,encode_count;
 mx_crt_cluster_state state;
} table_context;

int native_argument_callback(
 mx_crt_cluster_state*,mx_cfg_memory*,mx_crt_cluster_import_fn,
 mx_crt_cluster_direct_fn,void*);
int native_second_initializer(
 mx_crt_cluster_state*,mx_cfg_memory*,mx_crt_cluster_import_fn,
 mx_crt_cluster_direct_fn,void*);
int lifted_crt_import_cluster(
 mx_crt_cluster_state*,mx_cfg_memory*,mx_crt_cluster_import_fn,void*);

static uint64_t hash_bytes(const uint8_t*p,uint32_t n){
 uint64_t h=UINT64_C(0xcbf29ce484222325);
 for(uint32_t i=0;i<n;i++)
   h=(h^(uint64_t)p[i])*UINT64_C(0x100000001b3);
 return h;
}
static int copy64(mx_cfg_memory*m,uint64_t a,uint64_t v){
 return mx_cfg_transfer(m,a,&v,8U,1);
}
static int fresh_frame(table_context*c,uint64_t pc){
 for(uint32_t i=0;i<256U;i++)stack_bytes[i]=0U;
 if(!copy64(c->memory,SP,STOP_PC))return 0;
 c->state=(mx_crt_cluster_state){0};
 c->state.rsp=SP;c->state.rip=pc;
 return 1;
}
static int event(table_context*c,uint8_t kind){
 if(c->events>=3U)return 0;
 c->args_trace[c->events++]=kind;return 1;
}
static int injected_import(void*opaque,mx_crt_service_id svc,
                           mx_crt_cluster_state*s,mx_cfg_memory*m,
                           uint64_t stack_pointer){
 table_context*c=(table_context*)opaque;
 if(!c||!s)return 0;
 if(c->active_stage==1U){
    if(svc!=MX_CRT_SERVICE_GETMAINARGS ||
       stack_pointer!=SP-0x40U ||s->rsp!=SP-0x38U||
       !event(c,2))return 0;
    if((c->index%2U)==0U){
       /* A reusable guest CRT service supplies three bounded output writes.
        * Parsed argv/env buffers are injected by the loader; no Windows
        * command-line parsing or native CRT initialization is claimed. */
       mx_crt_process process={0};
       if(mx_crt_process_bind_args(&process,m,3U,
              ARG_DATA+0x1000U,ARG_DATA+0x1100U)!=MX_CRT_PROCESS_HANDLED)
          return 0;
       uint64_t ret=s->rax;
       if(mx_crt_process_getmainargs(&process,s->rcx,s->rdx,s->r8,
              0U,&ret)!=MX_CRT_PROCESS_HANDLED)return 0;
       s->rax=ret;
    }else {
       /* Explicit fault fixture retained for original x64 differential. */
       s->rax=UINT64_MAX;
    }
    return 1;
 }
 if(c->active_stage!=3U || stack_pointer!=SP-0x60U ||
    stack_pointer!=s->rsp-8U || c->child_trace_len>=10U)return 0;
 c->child_trace[c->child_trace_len++]=(uint64_t)svc;
 switch(svc){
   case MX_CRT_SERVICE_DECODE_POINTER:
       if(c->decode_count>=3U)return 0;
       s->rax=c->f->decoder[c->decode_count++];return 1;
   case MX_CRT_SERVICE_ENCODE_POINTER:
       if(c->encode_count>=3U)return 0;
       s->rax=c->f->encoder[c->encode_count++];return 1;
   case MX_CRT_SERVICE_ONEXIT:s->rax=c->f->onexit;return 1;
   case MX_CRT_SERVICE_DLLONEXIT:
       if(c->f->update){
           uint64_t left=c->f->updated0,right=c->f->updated1;
           if(!mx_cfg_transfer(m,s->rdx,&left,8U,1)||
              !mx_cfg_transfer(m,s->r8,&right,8U,1))return 0;
       }
       s->rax=c->f->dll;return 1;
   case MX_CRT_SERVICE_LOCK:
   case MX_CRT_SERVICE_UNLOCK:return s->rcx==8U;
   default:return 0;
 }
}
static int injected_direct(void*opaque,uint64_t target,
                           mx_crt_cluster_state*s,mx_cfg_memory*m){
 table_context*c=(table_context*)opaque;
 if(!c||s->local_depth!=1U)return MX_CRT_CLUSTER_IMPORT_UNSUPPORTED;
 if(c->active_stage==1U){
    if(s->rsp!=SP-0x40U)return MX_CRT_CLUSTER_IMPORT_UNSUPPORTED;
    if(target==WRAPPER_PC){
       if(!event(c,1))return MX_CRT_CLUSTER_INVALID;
       s->rax=(c->index%2U)==0U?0U:UINT64_C(0xffffffff);
    }else if(target==ARG_LOCAL){
       if(!event(c,3))return MX_CRT_CLUSTER_INVALID;
       s->rax=0x1200U+c->index;
    }else return MX_CRT_CLUSTER_IMPORT_UNSUPPORTED;
    uint64_t ret=mx_crt_cluster_read(s,m,s->rsp,8);
    if(s->fault)return MX_CRT_CLUSTER_MEMORY_FAULT;
    s->rip=ret;s->rsp+=8U;
    return MX_CRT_CLUSTER_RETURNED;
 }
 if(c->active_stage==2U){
    if(target==SECOND_LOCAL){
        if(s->rsp!=SP-0x30U||s->rcx!=SECOND_ARG1)
           return MX_CRT_CLUSTER_IMPORT_UNSUPPORTED;
        s->rax=0x1170U+c->index;
    }else if(target==WRAPPER_PC){
        if(s->rsp!=SP||s->rcx!=SECOND_ARG2)
           return MX_CRT_CLUSTER_IMPORT_UNSUPPORTED;
        s->rax=(c->index%2U)?0U:UINT64_C(0xffffffff);
    }else return MX_CRT_CLUSTER_IMPORT_UNSUPPORTED;
    c->events++;
    uint64_t ret=mx_crt_cluster_read(s,m,s->rsp,8);
    if(s->fault)return MX_CRT_CLUSTER_MEMORY_FAULT;
    s->rip=ret;s->rsp+=8U;
    return MX_CRT_CLUSTER_RETURNED;
 }
 return MX_CRT_CLUSTER_IMPORT_UNSUPPORTED;
}
static int validate_argument(table_context*c){
 const fixture*f=c->f;
 const mx_crt_cluster_state*s=&c->state;
 const uint64_t actual[14]={
     s->rax,s->rbx,s->rcx,s->rdx,s->r8,s->r9,
     s->r11,s->rdi,s->rsi,s->rsp,s->rip,s->zf,s->sf,s->cf
 };
 for(uint32_t i=0;i<14U;i++)
     if(actual[i]!=f->argc_out[i])return 0;
 if(c->events!=f->argc_trace_len || s->imports!=1U ||
    s->local_calls!=(c->index%2U?2U:1U))
     return 0;
 for(uint32_t i=0;i<c->events;i++)
    if(c->args_trace[i]!=f->argc_trace[i])return 0;
 if(hash_bytes(stack_bytes,256)!=f->argc_stack_hash ||
    hash_bytes(arg_data,8192)!=f->argc_globals_hash)return 0;
 return 1;
}
static int validate_second(table_context*c){
 const fixture*f=c->f;
 const mx_crt_cluster_state*s=&c->state;
 const uint64_t actual[14]={
     s->rax,s->rbx,s->rcx,s->rdx,s->r8,s->r9,
     s->r11,s->rdi,s->rsi,s->rsp,s->rip,s->zf,s->sf,s->cf
 };
 for(uint32_t i=0;i<14U;i++)
     if(actual[i]!=f->second_out[i])return 0;
 if(c->events!=2U || s->local_calls!=2U)return 0;
 if(hash_bytes(stack_bytes,256)!=f->second_stack_hash)return 0;
 return 1;
}
static int validate_third(table_context*c){
 const fixture*f=c->f;
 const mx_crt_cluster_state*s=&c->state;
 const uint64_t actual[11]={
     s->rax,s->rbx,s->rcx,s->rdx,s->r8,s->rdi,
     s->rsi,s->r11,s->rsp,s->rip,s->zf
 };
 for(uint32_t i=0;i<11U;i++)
     if(actual[i]!=f->child_out[i])return 0;
 uint64_t g0=0,g1=0;
 if(!mx_cfg_transfer(c->memory,CHILD_GLOBALS+8U,&g0,8U,0)||
    !mx_cfg_transfer(c->memory,CHILD_GLOBALS,&g1,8U,0)||
    g0!=f->child_out[11]||g1!=f->child_out[12])return 0;
 if(c->child_trace_len!=f->child_trace_len ||
    s->imports!=f->child_trace_len)return 0;
 for(uint32_t i=0;i<c->child_trace_len;i++)
    if(c->child_trace[i]!=f->child_trace[i])return 0;
 for(uint32_t i=0;i<256;i++)
    if(stack_bytes[i]!=f->child_stack[i])return 0;
 return 1;
}
static int walk(void*opaque,uint64_t target,uint32_t index,
                uint8_t checked_e,uint32_t*ignored){
 table_context*c=(table_context*)opaque;
 if(!c||!ignored||checked_e||index<1U||index>3U||
    c->seen[index]!=0U||index!=c->seen[0]+1U)return 0;
 c->active_stage=index;
 c->events=0U;c->child_trace_len=0U;
 c->decode_count=0U;c->encode_count=0U;
 if(!fresh_frame(c,target))return -1;
 int status=MX_CRT_CLUSTER_INVALID;
 if(index==1U && target==ARG_PC){
     c->state.rcx=c->f->argc_rcx;
     status=native_argument_callback(&c->state,c->memory,
                                    injected_import,injected_direct,c);
     if(status!=MX_CRT_CLUSTER_RETURNED||!validate_argument(c))return -1;
 }else if(index==2U && target==SECOND_PC){
     c->state.rcx=c->f->second_rcx;
     c->state.rbx=c->f->second_rbx;
     status=native_second_initializer(&c->state,c->memory,
                                     injected_import,injected_direct,c);
     if(status!=MX_CRT_CLUSTER_RETURNED||!validate_second(c))return -1;
 }else if(index==3U && target==TAIL_PC){
     const uint64_t *v=c->f->child_in;
     c->state.rax=v[0];c->state.rbx=v[1];c->state.rcx=v[2];
     c->state.rdx=v[3];c->state.r8=v[4];
     c->state.rdi=v[5];c->state.rsi=v[6];c->state.r11=v[7];
     c->state.zf=(uint8_t)v[8];
     status=mx_crt_tail_callback2_to_wrapper(
         &c->state,c->memory,TAIL_PC,TAIL_ARG,WRAPPER_PC,CHILD_PC,
         lifted_crt_import_cluster,injected_import,c);
     if(status!=MX_CRT_CLUSTER_RETURNED||!validate_third(c))return -1;
 }else return 0;
 c->seen[index]++;
 c->seen[0]++;
 *ignored=(uint32_t)c->state.rax;
 return 1;
}
int smoke(void){
 mx_cfg_region regions[4]={
   {WIN,stack_bytes,256},
   {ARG_DATA,arg_data,8192},
   {CHILD_GLOBALS,child_globals,16},
   {TABLE_BEGIN,(uint8_t*)original_table,32},
 };
 mx_cfg_memory guest={regions,4};
 for(uint32_t k=0;k<sizeof(fixtures)/sizeof(fixtures[0]);k++){
    for(uint32_t i=0;i<8192;i++)
       arg_data[i]=(uint8_t)((i*9U+k*13U+3U)&255U);
    /* Keep the joined native argument globals identical to x64_case(). */
    for(uint32_t i=0x5b0U;i<0x5b8U;i++)arg_data[i]=0U;
    for(uint32_t i=0;i<16;i++)child_globals[i]=0;
    const fixture*f=&fixtures[k];
    if(!copy64(&guest,CHILD_GLOBALS,f->child_in[9]) ||
       !copy64(&guest,CHILD_GLOBALS+8U,f->child_in[10]))
        return 1;
    table_context ctx={0};
    ctx.memory=&guest;ctx.f=f;ctx.index=k;
    mx_crt_init_walk result={0};
    int outcome=mx_crt_walk_initializers(&guest,TABLE_BEGIN,TABLE_END,
                                          0,walk,&ctx,&result);
    if(outcome!=MX_CRT_INIT_TABLE_COMPLETE||
       result.slots_examined!=4U||result.skipped_nulls!=1U||
       result.callbacks_invoked!=3U||ctx.seen[0]!=3U||
       ctx.seen[1]!=1U||ctx.seen[2]!=1U||ctx.seen[3]!=1U)
       return 20+k;
 }
 return 0;
}
#ifdef HOST
int main(void){return smoke();}
#endif
"""

def generate(executable,out):
    pe=PE(executable)
    table_begin,values=init_values(pe,executable)
    generated_arg,arg_meta,arg_slot,arg_code=calls_and_input(pe)
    second_body,generated_second,second_args=inspect_second(pe)
    verify_tail(pe)
    allowed,wrapperpcs=verify(pe)
    imports={rva:(dll,name) for rva,dll,name in import_slots(pe)}
    thunks={rva:pe.read_rva(rva,6) for rva in THUNKS}
    generated_child,child_meta=lift_crt_import_cluster(
        pe.read_rva(CHILD_ENTRY,CHILD_END-CHILD_ENTRY),
        CHILD_ENTRY,imports,thunks,BASE
    )
    if (arg_meta["decoded_instructions"]!=19 or
        child_meta["decoded_instructions"]!=39):
        raise RuntimeError("Original native CRT callback bodies changed")
    selected=list(child_cases())
    rows=[]
    for i,selected_idx in enumerate(CHOSEN):
        arg=x64_case(arg_code,arg_slot,i)
        second=second_reference(second_body,i,second_args)
        child_case=selected[selected_idx]
        joined=third_reference(pe,child_case,allowed,wrapperpcs,tail=True)
        rows.append((arg,second,joined,child_case))
    rendered=C
    markers={
        "__SP__":str(SP),"__WIN__":str(SP-128),
        "__STOP__":str(STOP),
        "__ARG__":str(BASE+ARG_ENTRY),
        "__ARG_LOCAL__":str(BASE+LOCAL_HELPER),
        "__SECOND__":str(BASE+SECOND_ENTRY),
        "__SECOND_LOCAL__":str(BASE+SECOND_LOCAL),
        "__WRAPPER__":str(BASE+WRAPPER_RVA),
        "__TAIL__":str(BASE+TAIL_CALLBACK),
        "__TAIL_ARG__":str(BASE+TAIL_ARGUMENT),
        "__CHILD__":str(BASE+CHILD_ENTRY),
        "__ARG_DATA__":str(BASE+DATA_RVA),
        "__CHILD_GLOBALS__":str(BASE+GLOBALS[1]),
        "__TABLE_BEGIN__":str(table_begin),
        "__TABLE_END__":str(table_begin+32),
        "__SECOND_ARG1__":str(second_args[0]),
        "__SECOND_ARG2__":str(second_args[1]),
        "__CASES__":encode_cases(rows),
        "__TABLE_VALUES__":",".join(u(v) for v in values),
    }
    for key,value in markers.items():
        if key not in rendered:
            raise RuntimeError("Original initializer native placeholder missing "+key)
        rendered=rendered.replace(key,value)
    with tempfile.TemporaryDirectory(prefix="private-mx-full-i-table-") as td:
        tmp=Path(td)
        translated=tmp/"owned-generated-init-bodies.c"
        smoke=tmp/"original-ordered-guest-table.c"
        translated.write_text(
            generated_arg+"\n"+generated_second+"\n"+generated_child)
        smoke.write_text(rendered)
        flags=["-std=c11","-O2","-Wall","-Wextra","-Werror",
               "-I"+str(ROOT/"arm64-lab"/"runtime")]
        def checked(cmd):
            result=subprocess.run(cmd,capture_output=True,text=True)
            if result.returncode:
                raise RuntimeError("Private native _initterm joined test failed "+
                    "exit="+str(result.returncode)+": "+
                    (result.stderr or result.stdout)[-3000:])
        host=tmp/"host"
        checked(["cc",*flags,"-DHOST",str(translated),str(smoke),
                 "-o",str(host)])
        checked([str(host)])
        elf=tmp/"native.elf"
        checked(["clang","--target=aarch64-unknown-linux-gnu",
                 "-fuse-ld=lld","-nostdlib","-static","-ffreestanding",
                 "-fno-builtin","-fno-stack-protector",*flags,
                 "-Wl,-e,smoke","-Wl,-z,max-page-size=4096",
                 "-Wl,--build-id=none",
                 str(translated),str(smoke),"-o",str(elf)])
        status=execute_arm64_elf(elf,instruction_budget=1900000,
                                 timeout_us=14000000)
    out.mkdir(parents=True,exist_ok=True)
    metadata={
        "original_initializer":"msvcr90.dll::_initterm",
        "authentic_pointer_slots":4,
        "nonnull_original_callbacks_executed_in_native_sequence":3,
        "native_original_callback_source_instructions":[19,6,2,8,39],
        "individual_original_x64_reference_fixtures_per_stage":len(rows),
        "original_full_x64_initterm_loop_executed":False,
        "original_getmainargs_service_executed":False,
        "native_guest_getmainargs_service_executed":True,
        "second_initializer_local_and_wrapper_body_executed":False,
        "third_initializer_native_wrapper_and_child_executed":True,
        "native_windows_crt_services_executed":False,
        "native_game_or_iphone_executed":False,
        "arm64_result":status["arm64_smoke_exit"],
    }
    (out/"crt-joined-init-native.json").write_text(
        json.dumps(metadata,indent=2)+"\n")
    summary="\n".join([
       "# Native MX Bikes _initterm table: three authentic callbacks ordered","",
       "- SHA-pinned original pointer array **four slots, three non-null**",
       "- Ordered Win64 guest callback loop: **19-instruction argument setup",
       "  → 6-instruction second tail → 2-instruction third tail",
       "  → 8-instruction wrapper → 39-instruction translated child**",
       "- All three original callback bodies execute under one AArch64",
       "  table dispatcher, sharing guest process memory and CRT globals",
       "- Independently verified original x64 references for every stage",
       "  in **"+str(len(rows))+"/"+str(len(rows))+" checked fixture combinations**",
       "- The final tail actually executes native wrapper and original child",
       "- Remaining original local callees and imported Windows CRT services",
       "  still use controlled test responses","",
       "**This is a native callback-table integration under synthetic",
       "dependency conditions, not a real _initterm Windows CRT, Steam",
       "startup, original engine execution or native iOS build.**",""
    ])
    (out/"crt-joined-init-native.md").write_text(summary)
    print(summary)

if __name__=="__main__":
    if len(sys.argv)!=3:
        raise SystemExit("usage: script.py owned-original-exe private-report-dir")
    generate(Path(sys.argv[1]),Path(sys.argv[2]))
