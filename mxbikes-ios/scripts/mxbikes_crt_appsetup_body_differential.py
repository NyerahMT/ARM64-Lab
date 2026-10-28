#!/usr/bin/env python3
"""Bounded full 52-instruction original CRT app-setup body x64/C/ARM64 test.

The SHA-pinned original PE code and header are read only inside private CI.
The verified three-byte zero-return original local callee is separately
translated and linked into its parent native guest-state CALL path.
A native C function is generated from the original function in an ephemeral
runner and cross-checked with original x64 instructions under Unicorn. Input
fixtures include valid/invalid PE headers and controlled injected local calls
and MSVCR90 APIs. Those injected dependencies are NOT production services.
No original bytes, generated C or ARM64 objects are uploaded.
"""
from pathlib import Path
import hashlib
import json
import struct
import subprocess
import sys
import tempfile

from capstone import Cs, CS_ARCH_X86, CS_MODE_64
from capstone.x86 import X86_OP_MEM
from unicorn import Uc, UC_ARCH_X86, UC_MODE_64, UC_HOOK_CODE, UC_HOOK_MEM_INVALID, UcError
from unicorn.x86_const import (
    UC_X86_REG_RAX,UC_X86_REG_RBX,UC_X86_REG_RCX,UC_X86_REG_RDX,
    UC_X86_REG_R8,UC_X86_REG_R9,UC_X86_REG_R11,UC_X86_REG_RDI,
    UC_X86_REG_RSI,UC_X86_REG_RSP,UC_X86_REG_RIP,UC_X86_REG_EFLAGS,
)
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/"arm64-lab"))
from tools.pe_probe import PE
from tools.pe_call_clusters import unwind_functions
from tools.crt_import_cluster_lift import lift_crt_import_cluster
from tools.guest_leaf_lift import lift_guest_leaf_to_c
from tools.crt_empty_table_lift import lift_empty_crt_table
from tools.import_aot_smoke import execute_arm64_elf
from mxbikes_first_callee_emu import import_slots
from mxbikes_crt_exception_callback_differential import BASE,SHA,SP,STACK,STOP

ENTRY=0x2ab234
LOCAL_A=0x2ab7fc
LOCAL_B=0x2ab950
STUB=0x600000000
EXTERNAL_GLOBAL=0x600010000
DATA_POINTER_SLOT=0x321500
MODE_POINTER_SLOT=0x3214f8
IMAGE_SIZE=0x1000000
HEADER_LEN=4096
MASK=(1<<64)-1
API_NAMES=(
    "__set_app_type","_encode_pointer",
    "__setusermatherr","_configthreadlocale",
)
LOCAL_RVAS=(LOCAL_A,LOCAL_B)
FNV_BASIS=0xcbf29ce484222325
FNV_PRIME=0x100000001b3
REGS=(
    ("rax",UC_X86_REG_RAX),("rbx",UC_X86_REG_RBX),
    ("rcx",UC_X86_REG_RCX),("rdx",UC_X86_REG_RDX),
    ("r8",UC_X86_REG_R8),("r9",UC_X86_REG_R9),
    ("r11",UC_X86_REG_R11),("rdi",UC_X86_REG_RDI),
    ("rsi",UC_X86_REG_RSI),("rsp",UC_X86_REG_RSP),
    ("rip",UC_X86_REG_RIP),
)

def fnv(data):
    h=FNV_BASIS
    for byte in data:
        h=((h^byte)*FNV_PRIME)&MASK
    return h

def source_input(pe):
    if hashlib.sha256(pe.b).hexdigest()!=SHA:
        raise RuntimeError("Original privately owned executable SHA mismatch")
    end=unwind_functions(pe).get(ENTRY)
    if end is None or not 100<=end-ENTRY<=768:
        raise RuntimeError("Original CRT app initializer unwind span changed")
    code=pe.read_rva(ENTRY,end-ENTRY)
    decoder=Cs(CS_ARCH_X86,CS_MODE_64)
    decoder.detail=True
    forms=list(decoder.disasm(code,ENTRY))
    if (len(forms)!=52 or sum(x.size for x in forms)!=len(code) or
        forms[-1].mnemonic!="ret"):
        raise RuntimeError("Original 52-instruction bound is no longer valid")
    imports={}
    for rva,dll,name in import_slots(pe):
        if dll.lower()=="msvcr90.dll" and name in API_NAMES:
            imports[rva]=(dll,name)
    if set(name for _,name in imports.values())!=set(API_NAMES):
        raise RuntimeError("Unexpected MSVCR90 setup API set")
    slots={name:rva for rva,(_,name) in imports.items()}
    imported_all={rva:(dll,name) for rva,dll,name in import_slots(pe)}
    expected_globals={
        DATA_POINTER_SLOT:"_fmode",
        MODE_POINTER_SLOT:"_commode",
    }
    for pointer_slot,symbol in expected_globals.items():
        identity=imported_all.get(pointer_slot)
        if (identity is None or identity[0].lower()!="msvcr90.dll"
                or identity[1]!=symbol):
            raise RuntimeError("Original MSVCR90 data-import identity changed: "+
                               hex(pointer_slot)+" "+repr(identity))
    translated,meta=lift_crt_import_cluster(
        code,ENTRY,
        {rva:(dll,name) for rva,dll,name in import_slots(pe)},
        {},BASE,local_targets=set(LOCAL_RVAS),
        function_name="native_app_initializer"
    )
    if (meta["decoded_instructions"]!=52 or
        meta["local_call_sites"]!=2 or meta["import_calls"]!=4):
        raise RuntimeError("Original app setup call graph changed")
    targets=set()
    for ins in forms:
        # LEA computes a guest address but does not touch memory. Including
        # its target in our *data* comparison accidentally compared bytes of
        # synthetic local RET stubs against the untouched native code image.
        if ins.mnemonic=="lea":
            continue
        for op in ins.operands:
            if op.type==X86_OP_MEM and ins.reg_name(op.mem.base)=="rip":
                rva=ins.address+ins.size+op.mem.disp
                if not 0<=rva<IMAGE_SIZE-8:
                    raise RuntimeError("Original callback RIP target RVA "+
                                       hex(rva)+
                                       " is outside bounded modeled image")
                targets.add(rva)
    header=pe.b[:HEADER_LEN]
    if len(header)!=HEADER_LEN or header[:2]!=b"MZ":
        raise RuntimeError("Original PE header unavailable")
    nt_offset=int.from_bytes(header[0x3c:0x40],"little")
    if not 0x40<=nt_offset<HEADER_LEN-64:
        raise RuntimeError("Original NT header offset unsupported")
    if header[nt_offset:nt_offset+4]!=b"PE\x00\x00":
        raise RuntimeError("Original PE NT header signature not found")
    return translated,meta,code,slots,tuple(sorted(targets)),header,nt_offset

def mapped_original_image(pe):
    """Construct original PE section memory at its verified preferred base.

    Keep initialized .rdata/.data and zero-filled virtual tails. In the
    previous test only headers/code/import thunks were present, which left
    required original global pointers as artificial zeroes.
    """
    image=bytearray(IMAGE_SIZE)
    if pe.u32(pe.opt+56)<IMAGE_SIZE//2:
        raise RuntimeError("Unexpectedly tiny original PE image")
    image[:HEADER_LEN]=pe.b[:HEADER_LEN]
    for name,vsize,rva,rawsize,rawptr,flags in pe.sections:
        if (rva<0 or rva+max(vsize,rawsize)>0x10000000 or
            rawptr+rawsize>len(pe.b)):
            raise RuntimeError("Malformed section exceeds PE input bounds")
        # The full PE includes unrelated large engine/asset sections. For
        # this bounded CRT proof, load the *initialized intersection* of
        # each section and 16MB of guest image; no image data is invented.
        if rva>=IMAGE_SIZE:
            continue
        copied=min(rawsize,IMAGE_SIZE-rva)
        if copied:
            image[rva:rva+copied]=pe.b[rawptr:rawptr+copied]
    return image

def case_header(header,index,nt_offset):
    sample=bytearray(header)
    if index==1:
        sample[0]=0
    elif index==2:
        sample[nt_offset]=0
    elif index==3:
        sample[nt_offset+24]=0
    return bytes(sample)

def api_response(machine,name,index):
    # Every external import is an injected deterministic test double.
    if name=="__set_app_type":
        return
    if name=="_encode_pointer":
        ptr=machine.reg_read(UC_X86_REG_RCX)
        machine.reg_write(UC_X86_REG_RAX,
                          (ptr^0x5a5aa5a5d00dbeef)&MASK)
    elif name=="__setusermatherr":
        machine.reg_write(UC_X86_REG_RAX,0)
    elif name=="_configthreadlocale":
        machine.reg_write(UC_X86_REG_RAX,1+index%2)
    else:
        raise RuntimeError("Unsupported synthetic CRT API")

def reference(pe,code,slots,targets,header,nt_offset,index,original_image):
    machine=Uc(UC_ARCH_X86,UC_MODE_64)
    machine.mem_map(BASE,IMAGE_SIZE)
    machine.mem_map(STACK,0x10000)
    machine.mem_map(STUB,4096)
    machine.mem_map(EXTERNAL_GLOBAL,4096)
    machine.mem_write(BASE,bytes(original_image))
    machine.mem_write(BASE,case_header(header,index,nt_offset))
    machine.mem_write(BASE+ENTRY,code)
    machine.mem_write(BASE+DATA_POINTER_SLOT,
                      struct.pack('<Q',EXTERNAL_GLOBAL))
    machine.mem_write(BASE+MODE_POINTER_SLOT,
                      struct.pack('<Q',EXTERNAL_GLOBAL+8))
    local_codes={BASE+LOCAL_A:1,BASE+LOCAL_B:2}
    # Execute both complete original callees on x64. LOCAL_A walks an
    # empty table; LOCAL_B is the independently verified XOR/RET leaf.
    machine.mem_write(BASE+LOCAL_A,pe.read_rva(LOCAL_A,0x38))
    machine.mem_write(BASE+LOCAL_B,pe.read_rva(LOCAL_B,3))
    slot_codes={}
    for offset,name in enumerate(API_NAMES):
        slot=slots[name]
        stub=STUB+offset*16
        machine.mem_write(BASE+slot,struct.pack("<Q",stub))
        machine.mem_write(stub,b"\xc3")
        slot_codes[stub]=(3+offset,name)
    machine.mem_write(SP,struct.pack("<Q",STOP))
    original_rcx=0x101000+index*19
    machine.reg_write(UC_X86_REG_RCX,original_rcx)
    machine.reg_write(UC_X86_REG_RSP,SP)
    machine.reg_write(UC_X86_REG_RIP,BASE+ENTRY)
    calls=[]
    recent=[]
    forms=tuple(Cs(CS_ARCH_X86,CS_MODE_64).disasm(code,ENTRY))
    ins_lookup={BASE+x.address:(x.mnemonic+" "+x.op_str)
                for x in forms}
    index_by_pc={BASE+x.address:i for i,x in enumerate(forms)}
    visited=0
    def hook(emu,pc,size,opaque):
        nonlocal visited
        if pc in index_by_pc:
            visited |= 1<<index_by_pc[pc]
        if pc in ins_lookup:
            recent.append((hex(pc-BASE),ins_lookup[pc]))
            if len(recent)>8:
                recent.pop(0)
        if pc in local_codes:
            if emu.reg_read(UC_X86_REG_RSP)!=SP-0x30:
                raise RuntimeError("Original local app-init Win64 stack moved")
            kind=local_codes[pc]
            calls.append(kind)
            # No fake RAX/flags. Both local function bodies execute.
        elif pc in slot_codes:
            if emu.reg_read(UC_X86_REG_RSP)!=SP-0x30:
                raise RuntimeError("Original external app-init Win64 stack moved")
            kind,name=slot_codes[pc]
            calls.append(kind)
            api_response(emu,name,index)
    machine.hook_add(UC_HOOK_CODE,hook)
    unmapped=[]
    def fault_probe(emu,access,address,size,value,opaque):
        unmapped.append({
            "fixture":index,
            "pc_rva":hex(emu.reg_read(UC_X86_REG_RIP)-BASE),
            "guest_address":hex(address),
            "access_kind":access,
            "access_width":size,
            "rsp_offset":emu.reg_read(UC_X86_REG_RSP)-SP,
            "rax":hex(emu.reg_read(UC_X86_REG_RAX)),
            "rcx":hex(emu.reg_read(UC_X86_REG_RCX)),
            "rdx":hex(emu.reg_read(UC_X86_REG_RDX)),
            "last_original_instructions":list(recent),
            "controlled_call_events":list(calls),
        })
        return False
    machine.hook_add(UC_HOOK_MEM_INVALID,fault_probe)
    try:
        machine.emu_start(BASE+ENTRY,STOP,timeout=3000000,count=250)
    except UcError as exc:
        if unmapped:
            raise RuntimeError(
                "Bounded original x64 app-init unmapped guest dependency: "+
                json.dumps(unmapped[-1],sort_keys=True)) from exc
        raise
    if machine.reg_read(UC_X86_REG_RIP)!=STOP or (
            machine.reg_read(UC_X86_REG_RSP)!=SP+8):
        raise RuntimeError("Original app-init callback did not return")
    if len(calls)>6:
        raise RuntimeError("Original app-init callback made unexpected calls")
    flags=machine.reg_read(UC_X86_REG_EFLAGS)
    regs=[machine.reg_read(reg) for _,reg in REGS]+[
        int(bool(flags&64)),int(bool(flags&128)),int(bool(flags&1))]
    observed=b"".join(bytes(machine.mem_read(BASE+rva,8)) for rva in targets)
    return {
        "initial_rcx":original_rcx,
        "index":index,
        "visited":visited,
        "expected":regs,
        "trace":calls,
        "observed_hash":fnv(observed),
        "observed_bytes":[list(machine.mem_read(BASE+rva,8))
                          for rva in targets],
        "stack_hash":fnv(bytes(machine.mem_read(SP-128,256))),
        "external_hash":fnv(bytes(machine.mem_read(EXTERNAL_GLOBAL,16))),
    }

C=r"""
#include <stdint.h>
#ifdef HOST
#include <stdio.h>
#endif
#include "mx_crt_cluster_guest.h"
#define BASE UINT64_C(__BASE__)
#define ENTRY UINT64_C(__ENTRY__)
#define SP UINT64_C(__SP__)
#define WIN UINT64_C(__WIN__)
#define STOP UINT64_C(__STOP__)
#define HEADER_OFFSET __HEADER_OFFSET__
#define IMAGE_SIZE 0x1000000U
#define PAGE_COUNT __PAGE_COUNT__
#define PAGE_SIZE 4096U
#define LOCAL_A UINT64_C(__LOCAL_A__)
#define LOCAL_B UINT64_C(__LOCAL_B__)
#define EXTERNAL_GLOBAL UINT64_C(__EXTERNAL_GLOBAL__)
#define DATA_SLOT_RVA __DATA_SLOT_RVA__
#define MODE_SLOT_RVA __MODE_SLOT_RVA__
#define OBSERVED_COUNT __OBSERVED_COUNT__
typedef struct {
 uint64_t rcx,registers[14],hash,stack_hash,external_hash,visited;
 uint32_t count;
 uint8_t calls[6];
 uint8_t expected_bytes[OBSERVED_COUNT][8];
} fixture;
static const fixture cases[]={__CASES__};
static const uint8_t base_header[4096]={__HEADER_BYTES__};
static const uint32_t observed_rvas[]={__OBSERVED_RVAS__};
#ifdef HOST
static const char *original_forms[]={__ORIGINAL_FORMS__};
#endif
typedef struct {uint32_t rva;uint8_t value[8];} image_seed;
static const image_seed image_seeds[]={__IMAGE_SEEDS__};
static const uint32_t page_rvas[PAGE_COUNT]={__PAGE_RVAS__};
static uint8_t image_pages[PAGE_COUNT][PAGE_SIZE],stack_bytes[256],external_bytes[4096];
static uint8_t *guest_ptr(uint32_t rva){
    for(uint32_t p=0;p<PAGE_COUNT;p++){
        uint32_t start=page_rvas[p];
        if(rva>=start && rva-start<PAGE_SIZE)
            return &image_pages[p][rva-start];
    }
    return (uint8_t*)0;
}
typedef struct {uint32_t case_index,n;uint8_t trace[6];} context;
static uint64_t fnv_extend(uint64_t h,uint8_t byte){
 return (h^(uint64_t)byte)*UINT64_C(0x100000001b3);
}
static uint64_t guest_image_digest(void) {
 uint64_t h=UINT64_C(0xcbf29ce484222325);
 for(uint32_t i=0;i<sizeof(observed_rvas)/sizeof(observed_rvas[0]);i++){
   const uint8_t*p=guest_ptr(observed_rvas[i]);
   for(uint32_t j=0;j<8;j++)h=fnv_extend(h,p[j]);
 }
 return h;
}
static uint64_t stack_digest(void){
 uint64_t h=UINT64_C(0xcbf29ce484222325);
 for(uint32_t i=0;i<256;i++)h=fnv_extend(h,stack_bytes[i]);
 return h;
}
static int record(context*c,uint8_t id){
 if(c->n>=6U)return 0;
 c->trace[c->n++]=id;return 1;
}
static int imported(void*opaque,mx_crt_service_id svc,
                    mx_crt_cluster_state*s,mx_cfg_memory*m,
                    uint64_t guest_rsp){
 (void)m;
 context*c=(context*)opaque;
 if(!c||guest_rsp!=SP-0x30U||s->rsp!=SP-0x28U)return 0;
 if(svc==MX_CRT_SERVICE_SET_APP_TYPE){
    return record(c,3);
 }else if(svc==MX_CRT_SERVICE_ENCODE_POINTER){
    if(!record(c,4))return 0;
    s->rax=s->rcx^UINT64_C(0x5a5aa5a5d00dbeef);
    return 1;
 }else if(svc==MX_CRT_SERVICE_SET_USERMATHERR){
    if(!record(c,5))return 0;
    s->rax=0;return 1;
 }else if(svc==MX_CRT_SERVICE_CONFIGTHREADLOCALE){
    if(!record(c,6))return 0;
    s->rax=1+(c->case_index%2U);return 1;
 }
 return 0;
}
int native_app_zero_leaf(mx_crt_cluster_state*,mx_cfg_memory*);
int native_app_empty_table(mx_crt_cluster_state*,mx_cfg_memory*);
static int local(void*opaque,uint64_t target,
                 mx_crt_cluster_state*s,mx_cfg_memory*m){
 context*c=(context*)opaque;
 if(!c||s->local_depth!=1U||s->rsp!=SP-0x30U)
   return MX_CRT_CLUSTER_IMPORT_UNSUPPORTED;
 uint8_t kind=0;
 if(target==LOCAL_A)kind=1;
 if(target==LOCAL_B)kind=2;
 if(!kind||!record(c,kind))return MX_CRT_CLUSTER_IMPORT_UNSUPPORTED;
 if(kind==2U)return native_app_zero_leaf(s,m);
 if(kind==1U)return native_app_empty_table(s,m);
 uint64_t ret=mx_crt_cluster_read(s,m,s->rsp,8);
 if(s->fault)return MX_CRT_CLUSTER_MEMORY_FAULT;
 s->rsp+=8U;s->rip=ret;
 return MX_CRT_CLUSTER_RETURNED;
}
int native_app_initializer(mx_crt_cluster_state*s,mx_cfg_memory*m,
                           mx_crt_cluster_import_fn imported,
                           mx_crt_cluster_direct_fn direct,void*ctx);
int smoke(void) {
 mx_cfg_region regions[PAGE_COUNT+2];
 for(uint32_t p=0;p<PAGE_COUNT;p++)
    regions[p]=(mx_cfg_region){BASE+page_rvas[p],image_pages[p],PAGE_SIZE};
 regions[PAGE_COUNT]=(mx_cfg_region){WIN,stack_bytes,256};
 regions[PAGE_COUNT+1]=(mx_cfg_region){EXTERNAL_GLOBAL,external_bytes,4096};
 mx_cfg_memory mem={regions,PAGE_COUNT+2};
 for(uint32_t k=0;k<sizeof(cases)/sizeof(cases[0]);k++){
    const fixture*f=&cases[k];
    for(uint32_t i=0;i<256;i++)stack_bytes[i]=0;
    for(uint32_t i=0;i<16;i++)external_bytes[i]=0;
    for(uint32_t i=0;i<sizeof(image_seeds)/sizeof(image_seeds[0]);i++)
       for(uint32_t j=0;j<8;j++)
          *guest_ptr(image_seeds[i].rva+j)=image_seeds[i].value[j];
    for(uint32_t i=0;i<4096;i++)image_pages[0][i]=base_header[i];
    if(k==1U)image_pages[0][0]=0U;
    else if(k==2U)image_pages[0][HEADER_OFFSET]=0U;
    else if(k==3U)image_pages[0][HEADER_OFFSET+24U]=0U;
    /* Initialized PE globals were restored from image_seeds above.
     * Do NOT zero them: original CRT branch conditions can depend on
     * nonzero linker-initialized data, including the PE/CRT setup flags.
     * BSS already begins zero-initialized in this native guest image.
     */
    /* Put the same synthetic thunk pointers into the original IAT slots. */
    static const uint32_t iat_rvas[4]={__IAT_RVAS__};
    for(uint32_t i=0;i<4;i++){
        uint64_t stub=UINT64_C(0x600000000)+16U*i;
        for(uint32_t j=0;j<8;j++)
            *guest_ptr(iat_rvas[i]+j)=(uint8_t)((stub>>(8U*j))&255U);
    }
    uint64_t writable=EXTERNAL_GLOBAL;
    for(uint32_t i=0;i<8;i++) {
        *guest_ptr(DATA_SLOT_RVA+i)=(uint8_t)((writable>>(8U*i))&255U);
        *guest_ptr(MODE_SLOT_RVA+i)=(uint8_t)(((writable+8U)>>(8U*i))&255U);
    }
    uint64_t return_pc=STOP;
    if(!mx_cfg_transfer(&mem,SP,&return_pc,8,1))return 1;
    mx_crt_cluster_state state={0};
    state.rcx=f->rcx;state.rsp=SP;state.rip=ENTRY;
    context ctx={k,0,{0,0,0,0,0,0}};
    if(native_app_initializer(&state,&mem,imported,local,&ctx)!=
       MX_CRT_CLUSTER_RETURNED)return 10+k;
    uint64_t actual[14]={
       state.rax,state.rbx,state.rcx,state.rdx,state.r8,state.r9,
       state.r11,state.rdi,state.rsi,state.rsp,state.rip,
       state.zf,state.sf,state.cf
    };
    for(uint32_t j=0;j<14;j++){
        if(actual[j]!=f->registers[j]){
#ifdef HOST
            fprintf(stderr,
                "Original CRT appsetup first mismatch: fixture=%u register=%u actual=0x%llx expected=0x%llx native_calls=%u expected_calls=%u\\n",
                (unsigned)k,(unsigned)j,(unsigned long long)actual[j],
                (unsigned long long)f->registers[j],
                (unsigned)ctx.n,(unsigned)f->count);
            fprintf(stderr,"native events:");
            for(uint32_t d=0;d<ctx.n;d++)
                fprintf(stderr," %u",(unsigned)ctx.trace[d]);
            fprintf(stderr,"; original events:");
            for(uint32_t d=0;d<f->count;d++)
                fprintf(stderr," %u",(unsigned)f->calls[d]);
            fprintf(stderr,"; image MZ=0x%x PE=0x%x magic=0x%x; mode_1=0x%llx mode_2=0x%llx\\n",
                (unsigned)image_pages[0][0],
                (unsigned)image_pages[0][HEADER_OFFSET],
                (unsigned)image_pages[0][HEADER_OFFSET+24U],
                (unsigned long long)state.rcx,
                (unsigned long long)state.rdx);
            fprintf(stderr,"visited actual=0x%llx expected=0x%llx difference=0x%llx\\n",
                (unsigned long long)state.visited,
                (unsigned long long)f->visited,
                (unsigned long long)(state.visited^f->visited));
            uint64_t changed=state.visited^f->visited;
            for(uint32_t d=0;d<52U;d++){
                if(changed&(UINT64_C(1)<<d)){
                    uint32_t lo=d>3U?d-3U:0U;
                    for(uint32_t p=lo;p<=d;p++)
                        fprintf(stderr,"  branch-diff context[%u]: %s\\n",
                                (unsigned)p,original_forms[p]);
                    break;
                }
            }
#endif
            return 40+k;
        }
    }
    if(ctx.n!=f->count)return 70+k;
    for(uint32_t j=0;j<f->count;j++)
       if(ctx.trace[j]!=f->calls[j])return 75+k;
    if(stack_digest()!=f->stack_hash)return 90+k;
    if(guest_image_digest()!=f->hash){
#ifdef HOST
        for(uint32_t i=0;i<OBSERVED_COUNT;i++){
            uint32_t rva=observed_rvas[i];
            for(uint32_t b=0;b<8;b++){
                if(*guest_ptr(rva+b)!=f->expected_bytes[i][b]){
                    fprintf(stderr,
                        "Original CRT appsetup first image byte mismatch: fixture=%u rva=0x%x actual=0x%x expected=0x%x\\n",
                        (unsigned)k,(unsigned)(rva+b),
                        (unsigned)*guest_ptr(rva+b),
                        (unsigned)f->expected_bytes[i][b]);
                    goto image_mismatch_found;
                }
            }
        }
image_mismatch_found:;
#endif
        return 110+k;
    }
    uint64_t external_hash=UINT64_C(0xcbf29ce484222325);
    for(uint32_t i=0;i<16;i++)
       external_hash=fnv_extend(external_hash,external_bytes[i]);
    if(external_hash!=f->external_hash)return 130+k;
 }
 return 0;
}
#ifdef HOST
int main(void){return smoke();}
#endif
"""

def render_c(rows,header,offset,targets,slots,original_image,code):
    values=[]
    for case in rows:
        registers=",".join("UINT64_C("+str(x)+")" for x in case["expected"])
        calls=",".join(str(x) for x in (case["trace"]+[0]*6)[:6])
        images=",".join(
            "{"+",".join(str(x) for x in row)+"}"
            for row in case["observed_bytes"])
        values.append("{UINT64_C("+str(case["initial_rcx"])+"),{"+
                      registers+"},UINT64_C("+str(case["observed_hash"])+
                      "),UINT64_C("+str(case["stack_hash"])+"),"+
                      "UINT64_C("+str(case["external_hash"])+"),"+
                      "UINT64_C("+str(case["visited"])+"),"+
                      str(len(case["trace"]))+",{"+calls+"},{"+
                      images+"}}")
    page_rvas=sorted(
        {0,DATA_POINTER_SLOT&~4095,MODE_POINTER_SLOT&~4095} |
        {rva&~4095 for rva in targets} |
        {rva&~4095 for rva in slots.values()})
    if (not page_rvas or page_rvas[0]!=0 or
        len(page_rvas)>64 or
        any(rva+4096>IMAGE_SIZE for rva in page_rvas) or
        any(rva&4095>4088 for rva in
            [DATA_POINTER_SLOT,MODE_POINTER_SLOT,*targets,*slots.values()])):
        raise RuntimeError("Original CRT initializer sparse guest page map unsafe")
    prepared=C
    replacements={
        "__BASE__":str(BASE),
        "__PAGE_COUNT__":str(len(page_rvas)),
        "__PAGE_RVAS__":",".join(str(rva) for rva in page_rvas),
        "__ENTRY__":str(BASE+ENTRY),
        "__SP__":str(SP),
        "__WIN__":str(SP-128),
        "__STOP__":str(STOP),
        "__HEADER_OFFSET__":str(offset),
        "__LOCAL_A__":str(BASE+LOCAL_A),
        "__LOCAL_B__":str(BASE+LOCAL_B),
        "__EXTERNAL_GLOBAL__":str(EXTERNAL_GLOBAL),
        "__DATA_SLOT_RVA__":str(DATA_POINTER_SLOT),
        "__OBSERVED_COUNT__":str(len(targets)),
        "__MODE_SLOT_RVA__":str(MODE_POINTER_SLOT),
        "__IMAGE_SEEDS__":",\n".join(
            "{"+str(rva)+",{"+",".join(str(x) for x in original_image[rva:rva+8])+"}}"
            for rva in targets),
        "__CASES__":",\n".join(values),
        "__HEADER_BYTES__":",".join(str(b) for b in header),
        "__OBSERVED_RVAS__":",".join(str(x) for x in targets),
        "__IAT_RVAS__":",".join(str(slots[name]) for name in API_NAMES),
        "__ORIGINAL_FORMS__":",".join(
            json.dumps(hex(ins.address)+" "+ins.mnemonic+" "+ins.op_str)
            for ins in Cs(CS_ARCH_X86,CS_MODE_64).disasm(code,ENTRY)),
    }
    for key,value in replacements.items():
        if key not in prepared:
            raise RuntimeError("Missing generated fixture placeholder "+key)
        prepared=prepared.replace(key,value)
    return prepared

def run(executable,out):
    pe=PE(executable)
    generated,meta,code,slots,targets,header,offset=source_input(pe)
    original_image=mapped_original_image(pe)
    # The original native leaf is identified at a preverified call target
    # and individually bounded to a fully recognized whole function.
    native_leaf=lift_guest_leaf_to_c(
        pe.read_rva(LOCAL_B,3),BASE+LOCAL_B,
        function_name="native_app_zero_leaf")
    native_empty,empty_meta=lift_empty_crt_table(
        pe.read_rva(LOCAL_A,0x38),LOCAL_A,BASE,
        function_name="native_app_empty_table")
    if (empty_meta["decoded_instructions"]!=17 or
        not empty_meta["original_callback_range_is_empty"]):
        raise RuntimeError("Original callback table no longer empty")
    rows=[reference(pe,code,slots,targets,header,offset,i,original_image)
          for i in range(8)]
    native_leaf_cases=sum(2 in x["trace"] for x in rows)
    if native_leaf_cases==0:
        raise RuntimeError("No original app-initializer fixture reaches local zero leaf")
    if sum(len(x["trace"])>0 for x in rows)==0:
        raise RuntimeError("Original setup success path never reached CRT services")
    harness=render_c(rows,header,offset,targets,slots,original_image,code)
    with tempfile.TemporaryDirectory(prefix="original-app-setup-arm64-") as td:
        work=Path(td)
        source=work/"generated-native-app-body.c"
        leaf=work/"generated-original-local-leaf.c"
        empty=work/"generated-original-empty-table.c"
        smoke=work/"private-native-fixtures.c"
        source.write_text(generated)
        leaf.write_text(native_leaf)
        empty.write_text(native_empty)
        smoke.write_text(harness)
        flags=["-std=c11","-O2","-Wall","-Wextra","-Werror",
               "-I"+str(ROOT/"arm64-lab"/"runtime")]
        def checked(cmd):
            completed=subprocess.run(cmd,capture_output=True,text=True)
            if completed.returncode:
                raise RuntimeError("Private native app body failed; exit="+
                                   str(completed.returncode)+": "+
                                   (completed.stderr or completed.stdout)[-2500:])
        host=work/"host"
        checked(["cc",*flags,"-DHOST",str(source),str(leaf),str(empty),str(smoke),"-o",str(host)])
        checked([str(host)])
        elf=work/"arm64.elf"
        checked(["clang","--target=aarch64-unknown-linux-gnu",
                 "-fuse-ld=lld","-nostdlib","-static","-ffreestanding",
                 "-fno-builtin","-fno-stack-protector",*flags,
                 "-Wl,-e,smoke","-Wl,-z,max-page-size=4096",
                 "-Wl,--build-id=none",str(source),str(leaf),str(empty),str(smoke),"-o",str(elf)])
        result=execute_arm64_elf(
            elf,instruction_budget=1900000,timeout_us=12000000)
    out.mkdir(parents=True,exist_ok=True)
    metadata={
        "original_callback_rva":hex(ENTRY),
        "original_instructions":52,
        "original_x64_vs_native_C_vs_executed_ARM64_fixtures":len(rows),
        "early_header_failure_cases":3,
        "original_import_names":list(API_NAMES),
        "local_direct_calls":2,
        "controlled_imported_writable_crt_globals":["_fmode","_commode"],
        "native_original_local_zero_leaf_executed":True,
        "all_original_local_callees_executed":True,
        "original_empty_initializer_walker_rva":hex(LOCAL_A),
        "original_empty_initializer_walker_instructions":empty_meta["decoded_instructions"],
        "original_empty_table_callback_count":0,
        "native_original_local_zero_leaf_rva":hex(LOCAL_B),
        "original_local_zero_leaf_executed_in_fixtures":native_leaf_cases,
        "remaining_controlled_local_callee_rva":None,
        "actual_msvcr90_services_executed":False,
        "full_initializer_table_executed":False,
        "game_engine_or_ios_executed":False,
        "arm64_test_status":result["arm64_smoke_exit"],
    }
    (out/"crt-original-appsetup-body-arm64.json").write_text(
        json.dumps(metadata,indent=2)+"\n")
    markdown="\n".join([
        "# Authentic 52-instruction CRT app initializer: x64/C/AArch64","",
        "- Original callback RVA: **"+hex(ENTRY)+"**",
        "- Authentic x64 versus generated host C versus executed AArch64:",
        "  **"+str(len(rows))+"/"+str(len(rows))+" fixtures matched**",
        "- PE header validation plus injected Windows CRT setup dependencies",
        "- Guest registers, flags, 256-byte stack window, observed RIP",
        "  guest-memory locations and imported/direct call order compared",
        "- Actual original zero-return local callee at "+hex(LOCAL_B)+
          " executed in **"+str(native_leaf_cases)+"/8** fixtures",
        "- Guest RAX/ZF/SF/CF and nested return stack verified against",
        "  independently executed original x64 child instructions",
        "- Original 17-instruction empty CRT table walker also executed",
        "  as actual linked native callee (zero callbacks)",
        "- No original local child is stubbed in this isolated parent;",
        "  imported Windows CRT services remain explicitly modeled",
        "- ARM64 smoke result: **"+str(result["arm64_smoke_exit"])+"**","",
        "**The original 52-instruction callback body is tested in isolation.",
        "This is NOT full CRT initialization, engine startup, graphics,",
        "Steam integration or an iPhone launch.**",""
    ])
    (out/"crt-original-appsetup-body-arm64.md").write_text(markdown)
    print(markdown)

if __name__=="__main__":
    if len(sys.argv)!=3:
        raise SystemExit("usage: script.py owned-original.exe report-dir")
    run(Path(sys.argv[1]),Path(sys.argv[2]))
