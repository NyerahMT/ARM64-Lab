#!/usr/bin/env python3
"""Execute the complete authentic _initterm_e callback array on native ARM64.

The SHA-verified original PE contributes the actual three pointer-array
slots (one NULL, 52-instruction app initializer, six-instruction exception
callback). The native ARM64 table walker invokes BOTH original callback
implementations, in correct slot order, within one guest-memory context.
Their original x64 reference states are established independently, and
each boundary is compared with those authentic original instruction runs.

Critical scope: all external CRT/Kernel32 APIs and the two app local callees
are injected controlled test doubles. This is a joined table *under those
test conditions*, NOT an actual MSVCR90, native process boot, or iOS game.
Generated original-code derivatives remain in ephemeral private CI.
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
from tools.import_aot_smoke import execute_arm64_elf
from tools.guest_leaf_lift import lift_guest_leaf_to_c
from tools.crt_empty_table_lift import lift_empty_crt_table
from mxbikes_crt_appsetup_body_differential import (
    source_input, mapped_original_image, reference as app_reference,
    render_c, ENTRY as APP_ENTRY, LOCAL_A, LOCAL_B, BASE, SHA, SP, STOP
)
from mxbikes_crt_exception_callback_differential import (
    inspect as inspect_exception, reference_original as exception_reference,
    CALLBACK as EXCEPTION_ENTRY
)
from mxbikes_crt_initializer_inventory import inventory
from mxbikes_crt_initializer_table_walk import source_tables

HANDLER=0x2ab6d0

def make_exception_rows(pe,app_rows):
    handler,iat_slot,_=inspect_exception(pe)
    if handler!=HANDLER:
        raise RuntimeError("Original exception-handler target changed")
    out=[]
    for index,app in enumerate(app_rows):
        regs=app["expected"]
        # Native table walker carries the completed app callback's register
        # values into its next callback, then establishes a fresh Win64
        # callback stack frame. Original x64 reference uses the same inputs.
        seed={
            "rax":regs[0],"rbx":regs[1],"rcx":regs[2],
            "rdi":regs[7],"rsi":regs[8],"r11":regs[6],
            "zf":regs[11],
            "result":0x1234abcde0+index,
        }
        expected=exception_reference(pe,handler,iat_slot,seed)
        out.append((seed,expected))
    return out

def generate_joined_harness(existing,table_begin,table_values,exception_rows):
    if table_values!=[0,BASE+APP_ENTRY,BASE+EXCEPTION_ENTRY]:
        raise RuntimeError("Expected authentic original _initterm_e pointer table")
    s=existing
    def replace(old,new):
        nonlocal s
        if old not in s:
            raise RuntimeError("Previously validated appsetup harness changed: "+repr(old[:80]))
        s=s.replace(old,new,1)
    replace('#include "mx_crt_cluster_guest.h"',
            '#include "mx_crt_cluster_guest.h"\n'
            '#include "mx_crt_initializer_walk.h"\n'
            '#include "mx_crt_exception_callback.h"')
    replace('#define LOCAL_A ', 
            '#define EINIT_BEGIN UINT64_C('+str(table_begin)+')\n'
            '#define EINIT_END UINT64_C('+str(table_begin+24)+')\n'
            '#define EXCEPTION_PC UINT64_C('+str(BASE+EXCEPTION_ENTRY)+')\n'
            '#define HANDLER_PC UINT64_C('+str(BASE+HANDLER)+')\n'
            '#define LOCAL_A ')
    header=s[:s.index('int smoke(void) {')]
    # The original standalone harness prints its decoded forms on failure.
    # The joined harness reports only bounded state/slot diagnostics and
    # must not retain an unused private static disassembly array (-Werror).
    import re
    header=re.sub(r'#ifdef HOST\nstatic const char \*original_forms\[\]=\{.*?\};\n#endif\n',
                  '',header,flags=re.DOTALL)
    # Existing validated app native C runtime, memory-page fixtures,
    # images and service adapters are retained intact. Only the final
    # test entry point is replaced by a real ordered three-slot walk.
    fields=("rax","rbx","rcx","rdi","rsi","r11","zf")
    outputs=("rax","rbx","rcx","rdi","rsi","r11","rsp","rip","zf")
    encoded=[]
    for seed,expect in exception_rows:
        begin=",".join("UINT64_C("+str(seed[n])+")" for n in fields)
        finish=",".join("UINT64_C("+str(expect[n])+")" for n in outputs)
        digest=0xcbf29ce484222325
        for byte in expect["stack"]:
            digest=((digest^byte)*0x100000001b3)&((1<<64)-1)
        encoded.append("{ {"+begin+"},{"+finish+"},UINT64_C("+str(digest)+") }")
    rows=",\n".join(encoded)
    evalues=",".join("UINT64_C("+str(value)+")" for value in table_values)
    glue=r"""
typedef struct {
    uint64_t initial[7],final[9],stack_hash;
} exception_fixture;
static const exception_fixture exception_expect[]={__EXCEPTION_ROWS__};
static uint64_t original_einit_words[3]={__EINIT_VALUES__};
typedef struct {
    mx_cfg_memory *memory;
    mx_crt_cluster_state *app;
    context *imports;
    const fixture *reference;
    const exception_fixture *exception;
    mx_crt_state exception_state;
    uint32_t index;
    uint32_t app_seen,exception_seen,handler_calls;
} walk_context;
static int synthetic_filter(void *opaque,uint64_t handler,uint64_t *previous){
    walk_context*c=(walk_context*)opaque;
    if(!c||!previous||handler!=HANDLER_PC)return 0;
    c->handler_calls++;
    *previous=UINT64_C(0x1234abcde0)+c->index;
    return 1;
}
static int validate_app(walk_context*c){
    const fixture*f=c->reference;
    mx_crt_cluster_state*s=c->app;
    const uint64_t actual[14]={
        s->rax,s->rbx,s->rcx,s->rdx,s->r8,s->r9,
        s->r11,s->rdi,s->rsi,s->rsp,s->rip,s->zf,s->sf,s->cf
    };
    for(uint32_t i=0;i<14U;i++)
        if(actual[i]!=f->registers[i])return 0;
    if(c->imports->n!=f->count || s->visited!=f->visited ||
       stack_digest()!=f->stack_hash ||
       guest_image_digest()!=f->hash)return 0;
    for(uint32_t i=0;i<f->count;i++)
        if(c->imports->trace[i]!=f->calls[i])return 0;
    uint64_t external_hash=UINT64_C(0xcbf29ce484222325);
    for(uint32_t i=0;i<16U;i++)
        external_hash=fnv_extend(external_hash,external_bytes[i]);
    if(external_hash!=f->external_hash)return 0;
    return 1;
}
static int dispatch_actual_einit(void*opaque,uint64_t target,
                                 uint32_t slot,uint8_t checked_e,
                                 uint32_t *status){
    walk_context*c=(walk_context*)opaque;
    if(!c||!status||!checked_e||slot==0U||slot>2U)return 0;
    if(slot==1U && target==ENTRY){
        if(c->app_seen || c->exception_seen)return -1;
        if(native_app_initializer(c->app,c->memory,imported,local,c->imports)
           !=MX_CRT_CLUSTER_RETURNED)return -1;
        if(!validate_app(c))return -1;
        c->app_seen++;
        *status=(uint32_t)c->app->rax;
        return 1;
    }
    if(slot==2U && target==EXCEPTION_PC){
        if(c->app_seen!=1U||c->exception_seen!=0U)return -1;
        /* This is the next Win64 callback invocation, with an independently
         * initialized return slot. The writable image and CRT globals are
         * NOT reset: appsetup's native effects persist between callbacks.
         */
        for(uint32_t i=0;i<256U;i++)stack_bytes[i]=0U;
        const uint64_t ret=STOP;
        if(!mx_cfg_transfer(c->memory,SP,(void*)&ret,8U,1))return -1;
        const exception_fixture*f=c->exception;
        mx_crt_state *s=&c->exception_state;
        *s=(mx_crt_state){0};
        s->rax=c->app->rax;s->rbx=c->app->rbx;s->rcx=c->app->rcx;
        s->rdi=c->app->rdi;s->rsi=c->app->rsi;s->r11=c->app->r11;
        s->zf=c->app->zf;s->rsp=SP;s->rip=EXCEPTION_PC;
        const uint64_t inputs[7]={
            s->rax,s->rbx,s->rcx,s->rdi,s->rsi,s->r11,s->zf
        };
        for(uint32_t i=0;i<7U;i++)
            if(inputs[i]!=f->initial[i])return -1;
        if(mx_crt_exception_callback6(s,c->memory,EXCEPTION_PC,HANDLER_PC,
                                      synthetic_filter,c)!=MX_CRT_RETURNED)
            return -1;
        const uint64_t actual[9]={
            s->rax,s->rbx,s->rcx,s->rdi,s->rsi,s->r11,
            s->rsp,s->rip,s->zf
        };
        for(uint32_t i=0;i<9U;i++)
            if(actual[i]!=f->final[i])return -1;
        if(stack_digest()!=f->stack_hash)return -1;
        c->exception_seen++;
        *status=(uint32_t)s->rax;
        return 1;
    }
    /* No invented success for missing callbacks or unexpected tables. */
    return 0;
}
int smoke(void){
    mx_cfg_region regions[PAGE_COUNT+3U];
    regions[0]=(mx_cfg_region){EINIT_BEGIN,
                             (uint8_t*)original_einit_words,24U};
    for(uint32_t p=0;p<PAGE_COUNT;p++)
        regions[p+1U]=(mx_cfg_region){
            BASE+page_rvas[p],image_pages[p],PAGE_SIZE
        };
    regions[PAGE_COUNT+1U]=(mx_cfg_region){WIN,stack_bytes,256U};
    regions[PAGE_COUNT+2U]=(mx_cfg_region){
        EXTERNAL_GLOBAL,external_bytes,4096U
    };
    mx_cfg_memory mem={regions,PAGE_COUNT+3U};
    if(mem.count>16U)return 1;
    uint32_t complete_count=0U,short_circuit_count=0U;
    for(uint32_t k=0;k<sizeof(cases)/sizeof(cases[0]);k++){
        const fixture*f=&cases[k];
        for(uint32_t i=0;i<256;i++)stack_bytes[i]=0U;
        for(uint32_t i=0;i<16;i++)external_bytes[i]=0U;
        for(uint32_t i=0;i<sizeof(image_seeds)/sizeof(image_seeds[0]);i++)
            for(uint32_t j=0;j<8;j++)
                *guest_ptr(image_seeds[i].rva+j)=image_seeds[i].value[j];
        for(uint32_t i=0;i<4096;i++)image_pages[0][i]=base_header[i];
        if(k==1U)image_pages[0][0]=0U;
        else if(k==2U)image_pages[0][HEADER_OFFSET]=0U;
        else if(k==3U)image_pages[0][HEADER_OFFSET+24U]=0U;
        static const uint32_t iat_rvas[4]={__IAT_RVAS__};
        for(uint32_t i=0;i<4;i++){
            uint64_t stub=UINT64_C(0x600000000)+16U*i;
            for(uint32_t j=0;j<8;j++)
                *guest_ptr(iat_rvas[i]+j)=
                    (uint8_t)((stub>>(8U*j))&255U);
        }
        uint64_t writable=EXTERNAL_GLOBAL;
        for(uint32_t i=0;i<8;i++){
            *guest_ptr(DATA_SLOT_RVA+i)=
                (uint8_t)((writable>>(8U*i))&255U);
            *guest_ptr(MODE_SLOT_RVA+i)=
                (uint8_t)(((writable+8U)>>(8U*i))&255U);
        }
        uint64_t ret=STOP;
        if(!mx_cfg_transfer(&mem,SP,&ret,8U,1))return 2;
        mx_crt_cluster_state app={0};
        app.rcx=f->rcx;app.rsp=SP;app.rip=ENTRY;
        context imported_ctx={k,0,{0,0,0,0,0,0}};
        walk_context ctx={
            &mem,&app,&imported_ctx,f,&exception_expect[k],
            {0},k,0,0,0
        };
        mx_crt_init_walk walk={0};
        int result=mx_crt_walk_initializers(
            &mem,EINIT_BEGIN,EINIT_END,1,dispatch_actual_einit,&ctx,&walk);
        uint32_t expected_status=(uint32_t)f->registers[0];
        if(expected_status!=0U){
            if(result!=MX_CRT_INIT_TABLE_EARLY_ERROR||
               walk.callbacks_invoked!=1U||
               walk.callback_error_status!=expected_status||
               walk.failed_slot_address!=EINIT_BEGIN+8U||
               ctx.app_seen!=1U||ctx.exception_seen!=0U||
               ctx.handler_calls!=0U)return 10+k;
            short_circuit_count++;
        } else {
            if(result!=MX_CRT_INIT_TABLE_COMPLETE||
               walk.callbacks_invoked!=2U||
               walk.slots_examined!=3U||walk.skipped_nulls!=1U||
               ctx.app_seen!=1U||ctx.exception_seen!=1U||
               ctx.handler_calls!=1U)return 30+k;
            complete_count++;
        }
    }
    /* A test that only observes short-circuits does not establish a complete
     * ordered table execution and must not be reported as that milestone.
     */
    if(complete_count==0U ||
       complete_count+short_circuit_count !=
         sizeof(cases)/sizeof(cases[0]))return 70;
    return 0;
}
#ifdef HOST
int main(void){return smoke();}
#endif
"""
    glue=glue.replace("__EXCEPTION_ROWS__",rows)
    glue=glue.replace("__EINIT_VALUES__",evalues)
    # re-use the already-validated IAT list rendered by appsetup
    from re import search
    found=search(r'static const uint32_t iat_rvas\[4\]=\{([^}]+)\}',existing)
    if not found:
        raise RuntimeError("Could not locate original appsetup IAT slot list")
    glue=glue.replace("__IAT_RVAS__",found.group(1))
    if "__IAT_RVAS__" in glue or "__EXCEPTION_ROWS__" in glue:
        raise RuntimeError("Joined _initterm_e smoke template unresolved")
    return header+glue

def checked(args):
    proc=subprocess.run(args,capture_output=True,text=True)
    if proc.returncode:
        raise RuntimeError("Original joined _initterm_e native differential "+
                           "failed (exit "+str(proc.returncode)+"): "+
                           (proc.stderr or proc.stdout)[-3500:])

def run(exe,out):
    pe=PE(exe)
    if hashlib.sha256(pe.b).hexdigest()!=SHA:
        raise RuntimeError("Authentic owned executable SHA mismatch")
    inv=inventory(exe)
    _,_,e_begin,e_values=source_tables(inv)
    generated,meta,code,slots,targets,header,nt_offset=source_input(pe)
    # Include the very same original callable leaf as the standalone
    # 52-instruction parent test; joined _initterm_e must link its body too.
    leaf_c=lift_guest_leaf_to_c(
        pe.read_rva(LOCAL_B,3),BASE+LOCAL_B,
        function_name="native_app_zero_leaf")
    empty_c,empty_info=lift_empty_crt_table(
        pe.read_rva(LOCAL_A,0x38),LOCAL_A,BASE,
        function_name="native_app_empty_table")
    if (empty_info["decoded_instructions"]!=17 or
        not empty_info["original_callback_range_is_empty"]):
        raise RuntimeError("Original CRT initializer array must stay empty")
    original_image=mapped_original_image(pe)
    rows=[app_reference(pe,code,slots,targets,header,nt_offset,
                        i,original_image) for i in range(8)]
    exception_rows=make_exception_rows(pe,rows)
    standalone=render_c(rows,header,nt_offset,targets,slots,
                        original_image,code)
    harness=generate_joined_harness(
        standalone,e_begin,e_values,exception_rows)
    with tempfile.TemporaryDirectory(prefix="private-mx-joined-einit-") as td:
        tmp=Path(td)
        app=tmp/"original-app-callback.c"
        leaf=tmp/"original-app-local-leaf.c"
        empty=tmp/"original-app-empty-table.c"
        smoke=tmp/"original-e-table.c"
        app.write_text(generated)
        leaf.write_text(leaf_c)
        empty.write_text(empty_c)
        smoke.write_text(harness)
        flags=["-std=c11","-O2","-Wall","-Wextra","-Werror",
               "-I"+str(ROOT/"arm64-lab"/"runtime")]
        host=tmp/"host"
        checked(["cc",*flags,"-DHOST",str(app),str(leaf),str(empty),str(smoke),"-o",str(host)])
        checked([str(host)])
        arm=tmp/"arm64.elf"
        checked(["clang","--target=aarch64-unknown-linux-gnu",
                 "-fuse-ld=lld","-nostdlib","-static",
                 "-ffreestanding","-fno-builtin","-fno-stack-protector",
                 *flags,"-Wl,-e,smoke","-Wl,-z,max-page-size=4096",
                 "-Wl,--build-id=none",str(app),str(leaf),str(empty),str(smoke),"-o",str(arm)])
        status=execute_arm64_elf(
            arm,instruction_budget=1900000,timeout_us=14000000)
    out.mkdir(parents=True,exist_ok=True)
    metadata={
        "original_initterm_e_slots":3,
        "original_initterm_e_nonnull_callbacks":2,
        "real_original_callback_bodies_executed_sequentially_in_same_native_guest":True,
        "first_original_body_rva":hex(APP_ENTRY),
        "first_original_body_instructions":52,
        "second_original_body_rva":hex(EXCEPTION_ENTRY),
        "second_original_body_instructions":6,
        "independent_original_x64_reference_cases_per_callback":len(rows),
        "full_original_x64_initterm_e_table_sequence_executed":False,
        "native_initterm_e_table_dispatch_complete_on_test_fixtures":True,
        "real_msvcr90_or_kernel32_services_executed":False,
        "native_original_local_zero_leaf_executed":True,
        "all_original_local_app_callees_executed":True,
        "original_native_empty_initializer_walker":hex(LOCAL_A),
        "original_empty_table_indirect_calls":0,
        "original_native_local_zero_leaf":hex(LOCAL_B),
        "remaining_local_app_callee_controlled":False,
        "native_engine_or_iPhone_game_executed":False,
        "arm64_smoke_exit":status["arm64_smoke_exit"],
    }
    (out/"crt-joined-einit-native.json").write_text(
        json.dumps(metadata,indent=2)+"\n")
    summary="\n".join([
        "# Native MX Bikes _initterm_e table: two authentic callbacks joined","",
        "- Full SHA-verified original _initterm_e table: **3 slots, 2 non-null**",
        "- Ordered native guest-memory walk: **NULL → app setup → exception filter**",
        "- Original app setup body: **52 real x64 instructions** generated",
        "  into native ARM64; **8/8 independent original x64 reference fixtures**",
        "- Original exception filter callback: **six real x64 instructions**",
        "  modeled by previously verified native adapter;",
        "  **8/8 independent original x64 reference fixtures**",
        "- Both run in the **same guest memory context**; original appsetup",
        "  image/CRT-global effects survive into the exception callback",
        "- Full native table dispatch checks callback order and return status;",
        "  early error results must stop before the second callback","",
        "- App initializer zero-return local child at "+hex(LOCAL_B)+
          " executes translated original x64 code with matching stack/flags",
        "- Original 17-instruction empty CRT walker also executes as native",
        "  child, without manufacturing success for unknown indirect calls",
        "- Imported CRT/Kernel32 services remain test doubles, not real",
        "  Windows runtime implementations","",
        "**This is NOT the real x64 _initterm_e",
        "runtime loop and does not establish actual Windows CRT startup,",
        "engine execution, Steam, rendering or iOS gameplay.**",""
    ])
    (out/"crt-joined-einit-native.md").write_text(summary)
    print(summary)

if __name__=="__main__":
    if len(sys.argv)!=3:
        raise SystemExit("usage: script.py private-owned-exe report-dir")
    run(Path(sys.argv[1]),Path(sys.argv[2]))
