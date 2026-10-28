#!/usr/bin/env python3
"""Original MX Bikes two-table CRT callback dispatch and verified tail slice.

Reads SHA-pinned original _initterm_e and _initterm pointer arrays from the
privately-owned executable. Under native host C and executed AArch64:
  * Walks each authentic table from the beginning and FAILS CLOSED on the
    first callback without an independently verified native implementation.
  * Walks the single supported _initterm tail-callback slot as a bounded
    slice, executing its authentic LEA/JMP -> wrapper -> generated child chain
    and comparing all register/guest-stack/global side effects with original
    x64 Unicorn execution across 16 fixtures.

Does NOT claim the full initializer tables, imported CRT, Steam or game boot.
Never uploads executable bytes or generated native game code to public repos.
"""
from pathlib import Path
import hashlib
import json
import sys
import tempfile

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/"arm64-lab"))
from tools.pe_probe import PE
from tools.crt_import_cluster_lift import lift_crt_import_cluster
from tools.import_aot_smoke import execute_arm64_elf
from mxbikes_crt_initializer_inventory import inventory
from mxbikes_first_callee_emu import import_slots
from mxbikes_crt_child_path_reference import ENTRY,END,THUNKS,cases
from mxbikes_crt_child_aot_differential import fixture,checked
from mxbikes_crt_exception_callback_differential import (
    inspect as inspect_exception_callback,
    reference_original as reference_exception_callback,
    CALLBACK as EXCEPTION_CALLBACK,
)
from mxbikes_crt_joined_wrapper_child_aot import (
    SHA,BASE,WRAPPER,TAIL_CALLBACK,verify,verify_tail,
    reference_original,native_harness,
)

def source_tables(inv):
    tables={}
    for t in inv["tables"]:
        if t["symbol"] not in ("msvcr90.dll::_initterm",
                                "msvcr90.dll::_initterm_e"):
            raise RuntimeError("Original initializer table family unexpected")
        address=BASE+int(t["begin_rva"],16)
        values=[0 if x["null"] else BASE+int(x["target_rva"],16)
                for x in t["entries"]]
        if len(values)!=t["slots"] or len(values)*8!=(
                int(t["end_rva"],16)-int(t["begin_rva"],16)):
            raise RuntimeError("Original callback table slots are noncontiguous")
        tables[t["symbol"]]=(address,values)
    if set(tables)!={"msvcr90.dll::_initterm",
                     "msvcr90.dll::_initterm_e"}:
        raise RuntimeError("Both original initializer tables required")
    init_begin,init_values=tables["msvcr90.dll::_initterm"]
    e_begin,e_values=tables["msvcr90.dll::_initterm_e"]
    if (len(init_values)!=4 or len(e_values)!=3 or
        init_values != [0,BASE+0x2aafc4,BASE+0x320770,
                        BASE+TAIL_CALLBACK] or
        e_values != [0,BASE+0x2ab234,BASE+0x2ab714]):
        raise RuntimeError("Initializer callback table identity changed")
    return init_begin,init_values,e_begin,e_values

def exception_reference_rows(pe, source_cases):
    handler,slot,_=inspect_exception_callback(pe)
    if (handler,slot)!=(0x2ab6d0,0x3210e8):
        raise RuntimeError("Original SetUnhandledExceptionFilter callback changed")
    result=[]
    for c in source_cases:
        f=fixture(c)
        expected=reference_exception_callback(pe,handler,slot,{
            "rax":f["rax"],"rbx":f["rbx"],"rcx":f["rcx"],
            "rdi":f["rdi"],"rsi":f["rsi"],"r11":f["r11"],
            "result":c["onexit"],"zf":f["zf"],
        })
        result.append(expected)
    return handler,result

def exception_array(rows):
    fields=("rax","rbx","rcx","rdi","rsi","r11",
            "rsp","rip","zf")
    encoded=[]
    for row in rows:
        nums=",".join("UINT64_C("+str(row[k])+")" for k in fields)
        mem="{"+",".join(str(x) for x in row["stack"])+"}"
        encoded.append("{"+nums+","+mem+"}")
    return ",\n".join(encoded)

def build_harness(rows,init_begin,init_values,e_begin,e_values,
                  exception_handler,exception_rows):
    program=native_harness(rows,tail=True)
    def substitute(old,new,label):
        nonlocal program
        if old not in program:
            raise RuntimeError("Native generated callback harness changed: "+label)
        program=program.replace(old,new,1)

    substitute('#include "mx_crt_joined_wrapper.h"',
        '#include "mx_crt_joined_wrapper.h"\n'
        '#include "mx_crt_initializer_walk.h"',
        "walker header")
    substitute('#include "mx_crt_initializer_walk.h"',
               '#include "mx_crt_initializer_walk.h"\n'
               '#include "mx_crt_exception_callback.h"',
               "original six-instruction callback header")
    declarations=(
        '#define INIT_BEGIN UINT64_C('+str(init_begin)+')\n'
        '#define INIT_END UINT64_C('+str(init_begin+len(init_values)*8)+')\n'
        '#define EINIT_BEGIN UINT64_C('+str(e_begin)+')\n'
        '#define EINIT_END UINT64_C('+str(e_begin+len(e_values)*8)+')\n'
        '#define SUPPORTED_TAIL UINT64_C('+str(BASE+TAIL_CALLBACK)+')\n'
        '#define FIRST_INIT_BLOCKER UINT64_C('+str(init_values[1])+')\n'
        '#define FIRST_EINIT_BLOCKER UINT64_C('+str(e_values[1])+')\n'
        '#define EXCEPTION_PC UINT64_C('+str(BASE+EXCEPTION_CALLBACK)+')\n'
        '#define HANDLER_PC UINT64_C('+str(BASE+exception_handler)+')\n'
        'static uint64_t init_words[4]={'+",".join(str(x) for x in init_values)+'};\n'
        'static uint64_t einit_words[3]={'+",".join(str(x) for x in e_values)+'};\n'
        'typedef struct {uint64_t rax,rbx,rcx,rdi,rsi,r11,rsp,rip,zf;'
        ' uint8_t stack[256];} exception_fixture;\n'
        'static const exception_fixture exception_expect[]={'
        +exception_array(exception_rows)+'};\n'
    )
    substitute('static uint8_t stack_bytes[256],global_bytes[16];',
        'static uint8_t stack_bytes[256],global_bytes[16];\n'+declarations,
        "real original pointer arrays")
    substitute('mx_cfg_region ranges[2]={{WIN,stack_bytes,256},{BASE_G1,global_bytes,16}};',
        'mx_cfg_region ranges[4]={{WIN,stack_bytes,256},'
        '{BASE_G1,global_bytes,16},{INIT_BEGIN,(uint8_t*)init_words,32},'
        '{EINIT_BEGIN,(uint8_t*)einit_words,24}};',
        "mapped original initializer arrays")
    substitute('mx_cfg_memory mem={ranges,2};',
               'mx_cfg_memory mem={ranges,4};',
               "four-region mapped guest memory")
    dispatcher=r"""
typedef struct {
  mx_crt_cluster_state *guest;
  mx_cfg_memory *memory;
  context *imports;
  uint32_t supported_invocations;
  uint32_t unsupported_invocations;
} table_context;
static int table_dispatch(void *opaque,uint64_t target,uint32_t index,
                          uint8_t checked_e,uint32_t *retval) {
    table_context*t=(table_context*)opaque;
    if(!t||!retval)return -1;
    if(checked_e||target!=SUPPORTED_TAIL) {
        t->unsupported_invocations++;
        return 0; /* fail closed: no invented callback result */
    }
    if(index!=0U)return -1; /* supported slice only, no skipped dependencies */
    int status=mx_crt_tail_callback2_to_wrapper(
        t->guest,t->memory,ENTRY,
        UINT64_C(0x1403207b0),UINT64_C(0x1402ab7e4),CHILD,
        lifted_crt_import_cluster,hook,t->imports);
    if(status!=MX_CRT_CLUSTER_RETURNED)return -1;
    *retval=(uint32_t)t->guest->rax;
    t->supported_invocations++;
    return 1;
}
"""
    # Replace hardcoded argument and wrapper addresses with verified constants.
    dispatcher=dispatcher.replace('UINT64_C(0x1403207b0)',
                                  'UINT64_C('+str(BASE+0x3207b0)+')')
    dispatcher=dispatcher.replace('UINT64_C(0x1402ab7e4)',
                                  'UINT64_C('+str(BASE+WRAPPER)+')')
    substitute('static int copy64(mx_cfg_memory*m',
               dispatcher+'\nstatic int copy64(mx_cfg_memory*m',
               "original target dispatch callback")
    exception_dispatcher=r"""
typedef struct {
 mx_crt_state *state;
 mx_cfg_memory *memory;
 uint32_t calls;
} exception_context;
static int filter_hook(void *opaque,uint64_t new_filter,uint64_t *previous) {
    exception_context*e=(exception_context*)opaque;
    if(!e||!previous||new_filter!=HANDLER_PC)return 0;
    e->calls++;
    *previous=UINT64_C(0x1234abcde0);
    return 1;
}
static int exception_dispatch(void *opaque,uint64_t target,
                              uint32_t index,uint8_t checked_e,
                              uint32_t *result) {
    exception_context*e=(exception_context*)opaque;
    if(!e||!result)return -1;
    if(target!=EXCEPTION_PC||!checked_e)return 0;
    if(index!=0U)return -1;
    int outcome=mx_crt_exception_callback6(
        e->state,e->memory,EXCEPTION_PC,HANDLER_PC,filter_hook,e);
    if(outcome!=MX_CRT_RETURNED)return -1;
    *result=(uint32_t)e->state->rax;
    return 1;
}
"""
    substitute('static int copy64(mx_cfg_memory*m',
               exception_dispatcher+'\nstatic int copy64(mx_cfg_memory*m',
               "exception callback dispatch in original second table")
    substitution_start='    if(mx_crt_tail_callback2_to_wrapper(&s,&mem,ENTRY,'
    start=program.find(substitution_start)
    end_text='MX_CRT_CLUSTER_RETURNED)return 40+k;'
    end=program.find(end_text,start)
    if start<0 or end<0:
        raise RuntimeError("Expected native direct tail invocation was not found")
    end+=len(end_text)
    # First attempt the real full tables and prove the earliest unresolved
    # callbacks are NOT assumed successful; then explicitly test only the
    # independently verified original tail callback in its genuine slot.
    table_steps=r"""
    table_context tc={&s,&mem,&ctx,0,0};
    mx_crt_init_walk first={0};
    int full_e=mx_crt_walk_initializers(&mem,EINIT_BEGIN,EINIT_END,
                                       1,table_dispatch,&tc,&first);
    if(full_e!=MX_CRT_INIT_TABLE_UNSUPPORTED ||
       first.skipped_nulls!=1U || first.callbacks_invoked!=0U ||
       first.failed_slot_address!=EINIT_BEGIN+8U ||
       first.failed_function_address!=FIRST_EINIT_BLOCKER ||
       tc.unsupported_invocations!=1U)return 32+k;
    mx_crt_init_walk second={0};
    int full_init=mx_crt_walk_initializers(&mem,INIT_BEGIN,INIT_END,
                                          0,table_dispatch,&tc,&second);
    if(full_init!=MX_CRT_INIT_TABLE_UNSUPPORTED ||
       second.skipped_nulls!=1U || second.callbacks_invoked!=0U ||
       second.failed_slot_address!=INIT_BEGIN+8U ||
       second.failed_function_address!=FIRST_INIT_BLOCKER ||
       tc.unsupported_invocations!=2U ||
       tc.supported_invocations!=0U)return 36+k;
    /* Independently verified original _initterm_e slot 2 executes its
     * six-instruction exception-filter callback. The earlier unsupported
     * callback remains blocked in the full-table attempt above. */
    mx_crt_state exc={0};
    exc.rax=f->in[0];exc.rbx=f->in[1];exc.rcx=f->in[2];
    exc.rdi=f->in[5];exc.rsi=f->in[6];exc.r11=f->in[7];
    exc.zf=(uint8_t)f->in[8];exc.rip=EXCEPTION_PC;exc.rsp=SP;
    exception_context ec={&exc,&mem,0U};
    mx_crt_init_walk scoped_exception={0};
    int e_status=mx_crt_walk_initializers(
        &mem,EINIT_END-8U,EINIT_END,1,
        exception_dispatch,&ec,&scoped_exception);
    if(e_status!=MX_CRT_INIT_TABLE_COMPLETE ||
       scoped_exception.callbacks_invoked!=1U||
       scoped_exception.slots_examined!=1U||
       scoped_exception.callback_error_status!=0U||
       ec.calls!=1U)return 38+k;
    const exception_fixture *expect=&exception_expect[k];
    const uint64_t actual_e[]={
        exc.rax,exc.rbx,exc.rcx,exc.rdi,exc.rsi,exc.r11,
        exc.rsp,exc.rip,(uint64_t)exc.zf
    };
    const uint64_t expected_e[]={
        expect->rax,expect->rbx,expect->rcx,expect->rdi,expect->rsi,
        expect->r11,expect->rsp,expect->rip,expect->zf
    };
    for(unsigned e=0;e<9U;e++){
        if(actual_e[e]!=expected_e[e])return 39+k;
    }
    for(unsigned e=0;e<256U;e++){
        if(stack_bytes[e]!=expect->stack[e])return 42+k;
    }
    /* The table slices are independent fixtures. Reset guest stack before
     * entering the separately verified original _initterm tail callback. */
    for(unsigned e=0;e<256U;e++)stack_bytes[e]=0;
    if(!copy64(&mem,SP,STOP))return 44+k;
    mx_crt_init_walk supported={0};
    int scoped=mx_crt_walk_initializers(&mem,INIT_END-8U,INIT_END,
                                       0,table_dispatch,&tc,&supported);
    if(scoped!=MX_CRT_INIT_TABLE_COMPLETE ||
       supported.callbacks_invoked!=1U ||
       supported.slots_examined!=1U ||
       supported.skipped_nulls!=0U ||
       tc.supported_invocations!=1U ||
       tc.unsupported_invocations!=2U)return 40+k;
"""
    program=program[:start]+table_steps+program[end:]
    if 'mx_crt_walk_initializers' not in program:
        raise RuntimeError("Original table walker never wired to native harness")
    return program

def run(executable,out):
    pe=PE(executable)
    if hashlib.sha256(pe.b).hexdigest()!=SHA:
        raise RuntimeError("Private purchased original EXE revision changed")
    inv=inventory(executable)
    init_begin,init_values,e_begin,e_values=source_tables(inv)
    allowed,wrapper_pcs=verify(pe)
    verify_tail(pe)
    imports={rva:(dll,name) for rva,dll,name in import_slots(pe)}
    thunks={rva:pe.read_rva(rva,6) for rva in THUNKS}
    generated,meta=lift_crt_import_cluster(
        pe.read_rva(ENTRY,END-ENTRY),ENTRY,imports,thunks,BASE)
    if meta["decoded_instructions"]!=39 or meta["import_calls"]!=10:
        raise RuntimeError("Expected full translated child is missing")
    rows=[]
    union=set()
    for c in cases():
        ref=reference_original(pe,c,allowed,wrapper_pcs,tail=True)
        union.update(ref["visited_child"])
        rows.append((fixture(c),ref))
    if len(rows)!=16 or len(union)!=39:
        raise RuntimeError("Authentic tail callback branch coverage changed")
    exception_handler,exception_rows=exception_reference_rows(pe,list(cases()))
    if len(exception_rows)!=len(rows):
        raise RuntimeError("Exception x64 fixture count not aligned")
    native=build_harness(rows,init_begin,init_values,e_begin,e_values,
                         exception_handler,exception_rows)
    with tempfile.TemporaryDirectory(prefix="private-init-arrays-native-") as temp:
        work=Path(temp)
        source=work/"generated-crt-child.c"
        smoke=work/"private-init-table-bridge.c"
        source.write_text(generated)
        smoke.write_text(native)
        common=["-std=c11","-O2","-Wall","-Wextra","-Werror",
                "-I"+str(ROOT/"arm64-lab"/"runtime")]
        host=work/"native-host"
        checked(["cc",*common,"-DHOST",str(source),str(smoke),
                 "-o",str(host)])
        checked([str(host)])
        elf=work/"aarch64.elf"
        checked(["clang","--target=aarch64-unknown-linux-gnu",
                 "-fuse-ld=lld","-nostdlib","-static","-ffreestanding",
                 "-fno-builtin","-fno-stack-protector",*common,
                 "-Wl,-e,smoke","-Wl,-z,max-page-size=4096",
                 "-Wl,--build-id=none",str(source),str(smoke),
                 "-o",str(elf)])
        result=execute_arm64_elf(elf,instruction_budget=1600000,
                                 timeout_us=12000000)
    out.mkdir(parents=True,exist_ok=True)
    report={
        "original_real_initializer_tables":2,
        "original_total_slots":inv["total_pointer_slots"],
        "original_nonnull_callbacks":inv["non_null_initializer_callbacks"],
        "full_initterm_e_walk_result":"blocked at first unsupported callback (slot 1)",
        "full_initterm_walk_result":"blocked at first unsupported callback (slot 1)",
        "supported_scoped_initterm_e_slot":2,
        "exception_filter_original_callback_rva":hex(EXCEPTION_CALLBACK),
        "exception_filter_native_x64_AArch64_matched":len(exception_rows),
        "supported_scoped_initterm_slot":3,
        "supported_scoped_callback_original_rva":hex(TAIL_CALLBACK),
        "supported_scoped_callback_native_C_AArch64_fixtures":len(rows),
        "native_x64_original_children_compared":True,
        "real_callback_results_guessed":False,
        "full_initializer_tables_executed":False,
        "remaining_nonnull_callbacks_not_integrated":3,
        "arm64_elf_exit":result["arm64_smoke_exit"],
        "engine_or_ios_booted":False,
    }
    (out/"crt-real-tables-dispatch.json").write_text(
        json.dumps(report,indent=2)+"\n")
    lines=[
        "# MX Bikes actual CRT initializer tables — bounded ARM64 dispatch","",
        "- Authentic pointer arrays: **2 tables / 7 slots / 5 non-null callbacks**",
        "- Full _initterm_e traversal stops at unresolved callback:",
        "  **slot 1, RVA 0x2AB234** (no fake return)",
        "- Full _initterm traversal stops at unresolved callback:",
        "  **slot 1, RVA 0x2AAFC4** (no fake return)",
        "- Explicitly scoped _initterm_e slot 2 executes its original",
        "  six-instruction exception-filter callback on host C and executed",
        "  AArch64; **16/16 original x64 fixtures matched**",
        "- Explicitly scoped _initterm slot 3 runs its original",
        "  **callback → wrapper → translated 39-instruction child** on host C",
        "  and executed AArch64; **16/16 original x64 fixtures matched**",
        "- Synthetic CRT import responses still required inside the child","",
        "**This is a partially integrated real initializer-table dispatcher.",
        "Both FULL original tables correctly fail closed; no unsupported",
        "callback was skipped, and native CRT/game/Steam/iOS boot is not achieved.**",""
    ]
    summary="\n".join(lines)
    (out/"crt-real-tables-dispatch.md").write_text(summary)
    print(summary)

if __name__=="__main__":
    if len(sys.argv)!=3:
        raise SystemExit("usage: script.py original-owned-exe report-dir")
    run(Path(sys.argv[1]),Path(sys.argv[2]))
