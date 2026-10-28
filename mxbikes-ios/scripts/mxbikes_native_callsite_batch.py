#!/usr/bin/env python3
"""Batch execute authentic original x64 CALL sites against verified native leaves.

Original executable code and generated C/ELF stay in the private CI runner.
This verifies exact CALL-edge ABI/return semantics, NOT full caller functions.
Only independently verified native leaves may be targets; unresolved callers
remain unresolved until a separate full-body differential passes.
"""
from __future__ import annotations
from collections import Counter, defaultdict
import argparse
import hashlib
import json
from pathlib import Path
import struct
import subprocess
import tempfile

from capstone import Cs, CS_ARCH_X86, CS_MODE_64, CS_GRP_CALL
from capstone.x86 import X86_OP_IMM, X86_OP_MEM, X86_OP_REG
from unicorn import Uc, UC_ARCH_X86, UC_MODE_64, UC_HOOK_MEM_WRITE
from unicorn.x86_const import UC_X86_REG_EFLAGS, UC_X86_REG_RIP, UC_X86_REG_RSP, UC_X86_REG_RBP
from mxbikes_verified_leaf_autolink import (
    ROOT, BASE, STACK, PARENT_SP, FIXTURES, GP, FIELDS, EXE_SHA,
    discover, generate_source, x64_reference, execute_arm64_elf
)
from mxbikes_joined_direct_batch import safe_callee
from mxbikes_callsite_prefix import (select_prefix_chain, emit_native_prefix,
    FRAME_ANCHOR_FROM_RSP, MAX_FRAME_READ_END, decode_frame_pointer_load_prefix)
from mxbikes_native_link_plan import build as build_link_plan

MAX_ORIGINAL_SITES=96
MAX_INTERVAL_BYTES=8192
GUEST_HEAP=0x720000000
GUEST_HEAP_PAGE_SPACING=4096
GUEST_HEAP_SEED_WINDOW=512
GUEST_HEAP_BASE_OFFSET=256


def describe_preceding_operand_family(ins):
    """Aggregate only structural operand classes; do not export original code."""
    if ins is None:
        return "start_of_interval"
    if ins.mnemonic!="mov":
        return ins.mnemonic
    ops=[]
    for part in ins.operands:
        if part.type==X86_OP_REG:
            ops.append("reg")
        elif part.type==X86_OP_IMM:
            ops.append("imm")
        elif part.type==X86_OP_MEM:
            base=ins.reg_name(part.mem.base) if part.mem.base else "none"
            # Base classes are structural groups, not guest address values.
            if base in ("rsp","rbp","rip"):
                family=base
            elif base in ("rbx","rdi","rsi","rax","rcx","rdx","r8","r9","r10","r11","r12","r13","r14","r15"):
                family="guest_base"
            else:
                family="other"
            indexed="_indexed" if part.mem.index else ""
            ops.append("mem_"+family+indexed)
        else:
            ops.append("other")
    if len(ops)!=2:
        return "mov:other_operands"
    return "mov:"+ops[0]+"<-"+ops[1]



def characterize_frame_predecessor(ins):
    """Privacy-safe structural reason a predecessor RBP access was excluded."""
    if ins is None or len(ins.operands)!=2:
        return None
    dst,src=ins.operands
    if src.type!=X86_OP_MEM or ins.reg_name(src.mem.base)!="rbp":
        return None
    if ins.mnemonic!="mov":
        return "rbp:non_mov"
    if dst.type!=X86_OP_REG:
        return "rbp:nonregister_destination"
    if src.mem.index:
        return "rbp:indexed_address"
    width=dst.size
    if width not in (4,8) or width!=src.size:
        return "rbp:unsupported_width"
    offset=FRAME_ANCHOR_FROM_RSP+int(src.mem.disp)
    if offset<0:
        return "rbp:before_fixture_window"
    if offset+width>MAX_FRAME_READ_END:
        return "rbp:after_fixture_window"
    if decode_frame_pointer_load_prefix(ins) is None:
        return "rbp:unsupported_encoding"
    return "rbp:bounded_fixture_eligible"



def discover_original_call_sites(pe,mapping,eligible,*,limit=MAX_ORIGINAL_SITES):
    if (mapping.get("input_sha256")!=EXE_SHA or
        mapping.get("original_file_verified") is not True):
        raise ValueError("Unpinned original-game caller/callee graph")
    if not 0<=limit<=MAX_ORIGINAL_SITES:
        raise ValueError("Unsafe original callsite limit")
    if not limit:
        return []
    by_child={x["rva"]:x for x in eligible if safe_callee(x)}
    graph={int(a,16):{int(b,16) for b in dest}
           for a,dest in mapping["direct_call_graph"].items()}
    potential={a for a,dests in graph.items() if dests & by_child.keys()}
    selected=[]
    decoder=Cs(CS_ARCH_X86,CS_MODE_64)
    decoder.detail=True
    for row in mapping.get("interval_map",[]):
        rva=int(row["rva"],16)
        size=row.get("bytes",0)
        if (rva not in potential or row.get("status")!="decoded_linear" or
            not isinstance(size,int) or not 1<=size<=MAX_INTERVAL_BYTES):
            continue
        blob=pe.read_rva(rva,size)
        insns=list(decoder.disasm(blob,rva))
        if not insns or sum(x.size for x in insns)!=size:
            raise RuntimeError("Original decoded interval changed between stages")
        for ix,ins in enumerate(insns):
            if (ins.group(CS_GRP_CALL) and len(ins.operands)==1 and
                ins.operands[0].type==X86_OP_IMM and
                ins.size==5 and blob[ins.address-rva]==0xe8):
                target=int(ins.operands[0].imm)
                if target not in by_child or target not in graph[rva]:
                    continue
                actual_target=ins.address+5+int.from_bytes(
                    blob[ins.address-rva+1:ins.address-rva+5],
                    "little",signed=True)
                if target!=actual_target:
                    raise RuntimeError("Original x64 direct call operand decode disagreement")
                prefixes=select_prefix_chain(insns,ix)
                # A pointer loaded earlier in the original caller may have
                # been assigned by an untranslated instruction. Begin the
                # verified fixture at the last bounded guest pointer read.
                heap_positions=[j for j,op in enumerate(prefixes)
                                if op["kind"] in ("guest_heap_load",
                                                  "guest_heap_indexed_load",
                                                  "guest_heap_store")]
                if heap_positions:
                    prefixes=prefixes[heap_positions[-1]:]
                # An operand used as both a guest pointer and an index would
                # need a different fixture model. Retain CALL-only validation.
                bases={op["src"] for op in prefixes if op["kind"] in (
                       "guest_heap_load","guest_heap_indexed_load",
                       "guest_heap_store")}
                indices={op["index"] for op in prefixes
                         if op["kind"]=="guest_heap_indexed_load"}
                if bases & indices:
                    prefixes=[]
                selected.append({
                    "parent_rva":rva, "callsite_rva":ins.address,
                    "entry_rva":prefixes[0]["address"] if prefixes else ins.address,
                    "original_prefix_bytes":b"".join(
                        bytes(i.bytes) for i in insns[ix-len(prefixes):ix]),
                    "prefix":prefixes[-1] if prefixes else None,
                    "prefixes":prefixes,
                    "preceding_mnemonic":insns[ix-1].mnemonic if ix else "start_of_interval",
                    "preceding_operand_family":describe_preceding_operand_family(insns[ix-1] if ix else None),
                    "preceding_frame_class":characterize_frame_predecessor(insns[ix-1] if ix else None),
                    "continuation_rva":ins.address+5,
                    "target_rva":target,
                    "original_call_bytes":bytes(blob[ins.address-rva:ins.address-rva+5]),
                    "verified_callee":by_child[target],
                    "parent_function_native_complete":False,
                })
    # Group by parent first to amortize original callsite discovery. These
    # links are dynamic ABI tests, not full parent CFG translation.
    selected.sort(key=lambda r:(r["parent_rva"],r["callsite_rva"],r["target_rva"]))
    return selected[:limit]


def original_reference(site,case):
    callee=site["verified_callee"]
    x64=Uc(UC_ARCH_X86,UC_MODE_64)
    addr=site["callsite_rva"]
    entry=site["entry_rva"]
    pages=set()
    for at,length in ((entry,5+len(site["original_prefix_bytes"])),
                      (callee["rva"],len(callee["body"]))):
        pages.update(range(at&~4095, ((at+length-1)&~4095)+1,4096))
    for page in sorted(pages):
        x64.mem_map(BASE+page,4096)
    x64.mem_map(STACK,65536)
    heap_bases={op["src"] for op in site.get("prefixes",[])
                if op["kind"] in ("guest_heap_load","guest_heap_indexed_load",
                                  "guest_heap_store")}
    heap_indexes={op["index"] for op in site.get("prefixes",[])
                  if op["kind"]=="guest_heap_indexed_load"}
    if heap_bases & heap_indexes:
        raise RuntimeError("Unmodeled overlapping guest-pointer and index register")
    if heap_bases:
        x64.mem_map(GUEST_HEAP,65536)
        for index in range(len(GP)):
            x64.mem_write(GUEST_HEAP+index*GUEST_HEAP_PAGE_SPACING,
                bytes((k*13+31+index)&255 for k in range(GUEST_HEAP_SEED_WINDOW)))
    # Seed original Win64 shadow/stack argument bytes identically to the
    # native guest-memory fixture. Never dereference process-host pointers.
    x64.mem_write(PARENT_SP,bytes((k*17+9)&255 for k in range(MAX_FRAME_READ_END)))
    if site["original_prefix_bytes"]:
        x64.mem_write(BASE+entry,site["original_prefix_bytes"])
    x64.mem_write(BASE+addr,site["original_call_bytes"])
    x64.mem_write(BASE+callee["rva"],callee["body"])
    seed={}
    for idx,(name,reg) in enumerate(GP):
        value=(0x1122448899AABBCC+idx*0x10f01001+case*0x13131313)&((1<<64)-1)
        if case in (0,1,2,3):
            names={0:("rcx",),1:("rax",),2:("rdx",),3:("rax","rcx","rdx")}[case]
            if name in names:value=0
        if case==4 and idx<4:value=(1<<64)-1
        if name in heap_bases:
            value=GUEST_HEAP+idx*GUEST_HEAP_PAGE_SPACING+GUEST_HEAP_BASE_OFFSET
        elif name in heap_indexes:
            value=case%5
        seed[name]=value
        x64.reg_write(reg,value)
    flags=0x202|([0,1,0x40,0x80,0xc1,0x41][case%6])
    writes=[]
    if any(op["kind"]=="guest_heap_store" for op in site.get("prefixes",[])):
        def recorded_write(_emu, _access, address, size, _value, _context):
            if GUEST_HEAP<=address and address+size<=GUEST_HEAP+65536:
                writes.append((address,size))
        x64.hook_add(UC_HOOK_MEM_WRITE,recorded_write)
    # Frame-pointer CALL slices are bounded fixture-level proofs: RBP is
    # deterministic and points inside the initialized guest stack window.
    # The caller's actual prologue is not translated or assumed correct.
    if any(op["kind"]=="frame_pointer_load" for op in site.get("prefixes",[])):
        x64.reg_write(UC_X86_REG_RBP,PARENT_SP+FRAME_ANCHOR_FROM_RSP)
    x64.reg_write(UC_X86_REG_EFLAGS,flags)
    x64.reg_write(UC_X86_REG_RSP,PARENT_SP)
    x64.reg_write(UC_X86_REG_RIP,BASE+entry)
    x64.emu_start(BASE+entry,BASE+site["continuation_rva"],
                  timeout=1000000,count=64)
    raw_flags=x64.reg_read(UC_X86_REG_EFLAGS)
    expected={name:x64.reg_read(reg) for name,reg in GP}
    expected.update(rsp=x64.reg_read(UC_X86_REG_RSP),
                    rip=x64.reg_read(UC_X86_REG_RIP),
                    cf=int(bool(raw_flags&1)),
                    zf=int(bool(raw_flags&0x40)),
                    sf=int(bool(raw_flags&0x80)))
    actual_slot=struct.unpack("<Q",bytes(x64.mem_read(PARENT_SP-8,8)))[0]
    if (expected["rip"]!=BASE+site["continuation_rva"] or
        expected["rsp"]!=PARENT_SP or
        actual_slot!=BASE+site["continuation_rva"]):
        raise RuntimeError("Original complete direct-CALL->callee return not verified")
    if any(op["kind"]=="guest_heap_store" for op in site.get("prefixes",[])):
        if len(writes)!=1 or writes[0][1] not in (4,8):
            raise RuntimeError("Original guest-store side effect not uniquely traced")
        address,size=writes[0]
        expected["_store_addr"]=address
        expected["_store_size"]=size
        expected["_store_value"]=int.from_bytes(
            bytes(x64.mem_read(address,size)),"little")
    return seed,flags,expected


def callsite_native_source(candidates,leaves,edges):
    references={c["rva"]:[x64_reference(c,j) for j in range(FIXTURES)]
                for c in leaves}
    source=generate_source(leaves,references)
    source=source.replace("int smoke(void){","int baseline_leaf_smoke(void){")
    wrapper="#ifdef HOST\nint main(void){return smoke();}\n#endif"
    if source.count(wrapper)!=1:
        raise RuntimeError("Original leaf smoke template no longer matches")
    source=source.replace(wrapper,"")
    init=[]
    for site_index,site in enumerate(candidates):
        for case in range(FIXTURES):
            seed,flags,result=original_reference(site,case)
            input_regs=",".join(f"UINT64_C({seed[name]})" for name,_ in GP)
            expected=",".join(f"UINT64_C({result[name]})" for name in FIELDS)
            init.append("{"+str(site_index)+",UINT64_C("+str(site["callsite_rva"])+"),"
                        +"UINT64_C("+str(site["target_rva"])+"),"
                        +"UINT64_C("+str(site["continuation_rva"])+"),"
                        +"{"+input_regs+"},"+str(flags)+",{"+expected+"},"
                        +"UINT64_C("+str(result.get("_store_addr",0))+"),"
                        +"UINT64_C("+str(result.get("_store_value",0))+"),"
                        +str(result.get("_store_size",0))+"}")
    prefixes="\n".join(
        f"case {i}U: "+
        " ".join(emit_native_prefix(part) for part in site.get("prefixes",[]))+
        " break;" for i,site in enumerate(candidates))
    source+=r'''
#define GUEST_HEAP UINT64_C(0x720000000)
static uint8_t guest_heap_bytes[65536];
typedef struct {
 uint32_t site_index;
 uint64_t callsite,target,continuation;
 uint64_t regs[9];
 uint32_t flags;
 uint64_t expected[14];
 uint64_t expected_store_address,expected_store_value;
 uint32_t expected_store_bytes;
} original_edge_fixture;
#define EDGES __EDGE_COUNT__
static const original_edge_fixture edge_cases[EDGES]={
__EDGES__
};
int smoke(void){
 if(baseline_leaf_smoke()!=0)return 1;
 mx_cfg_region regions[2]={
   {STACK,stack_bytes,65536U},{GUEST_HEAP,guest_heap_bytes,65536U}
 };
 mx_cfg_memory memory={regions,2U};
 mx_native_link_registry registry={0};
 registry.entries=link_entries;registry.count=COUNT;registry.max_depth=8U;
 if(mx_native_link_seal(&registry)!=MX_NATIVE_LINK_OK)return 2;
 for(unsigned i=0;i<EDGES;i++){
   /* Every original Unicorn fixture starts with the same fresh guest pages. */
   for(unsigned n=0;n<9U;n++)
     for(unsigned k=0;k<512U;k++)
       guest_heap_bytes[n*4096U+k]=(uint8_t)((k*13U+31U+n)&255U);
   const original_edge_fixture *fc=&edge_cases[i];
   mx_crt_cluster_state s={0};
   for(unsigned k=0;k<128U;k++)stack_bytes[(PARENT_SP-64U-STACK)+k]=0;
   for(unsigned k=0;k<1024U;k++)stack_bytes[(PARENT_SP-STACK)+k]=(uint8_t)((k*17U+9U)&255U);
   s.rax=fc->regs[0];s.rbx=fc->regs[1];s.rcx=fc->regs[2];
   s.rdx=fc->regs[3];s.r8=fc->regs[4];s.r9=fc->regs[5];
   s.rdi=fc->regs[6];s.rsi=fc->regs[7];s.r11=fc->regs[8];
   s.cf=(fc->flags&1U)!=0U;s.zf=(fc->flags&64U)!=0U;
   s.sf=(fc->flags&128U)!=0U;
   s.rsp=PARENT_SP;s.rip=BASE+fc->callsite;
   switch(fc->site_index){
__NATIVE_PREFIXES__
     default:return 7;
   }
   if(mx_native_link_call(&registry,&s,&memory,BASE+fc->target,
                          BASE+fc->continuation)!=MX_NATIVE_LINK_OK)return 3;
   const uint64_t observed[14]={s.rax,s.rbx,s.rcx,s.rdx,s.r8,s.r9,
                                 s.rdi,s.rsi,s.r11,s.rsp,s.rip,s.cf,s.zf,s.sf};
   for(unsigned k=0;k<14U;k++)if(observed[k]!=fc->expected[k])return 4;
   if(fc->expected_store_bytes){
     uint64_t actual_store=0U;
     if(fc->expected_store_bytes!=4U && fc->expected_store_bytes!=8U)return 9;
     if(!mx_cfg_transfer(&memory,fc->expected_store_address,
                         &actual_store,fc->expected_store_bytes,0))return 10;
     if(actual_store!=fc->expected_store_value)return 11;
   }
   uint64_t slot=0U;
   if(!mx_cfg_transfer(&memory,PARENT_SP-8U,&slot,8U,0) ||
      slot!=BASE+fc->continuation)return 5;
 }
 if(registry.calls_completed!=EDGES||registry.unresolved_calls||
    registry.active_depth)return 6;
 return 0;
}
#ifdef HOST
int main(void){return smoke();}
#endif
'''
    return (source.replace("__EDGE_COUNT__",str(len(init)))
            .replace("__EDGES__",",\n".join(init))
            .replace("__NATIVE_PREFIXES__",prefixes))


def run(original,map_path,verified_path,output,*,waves_path=None):
    from tools.pe_probe import PE
    pe=PE(original)
    if hashlib.sha256(pe.b).hexdigest()!=EXE_SHA:
        raise RuntimeError("Owned MX Bikes executable revision changed")
    mapping=json.loads(map_path.read_text())
    verified=json.loads(verified_path.read_text())
    waves=json.loads(waves_path.read_text()) if waves_path else None
    _,found,_,_=discover(original,mapping,waves)
    audited={int(x["original_rva"],16) for x in verified
             if x.get("full_function_behavior_verified") is True and
                x.get("win64_guest_call_abi_verified") is True and
                x.get("code_presence")=="ephemeral_ci_elf_only"}
    candidate_leaves=[x for x in found if x["rva"] in audited and safe_callee(x)]
    sites=discover_original_call_sites(pe,mapping,candidate_leaves)
    if sites:
        used={s["target_rva"] for s in sites}
        native_leaves=[x for x in candidate_leaves if x["rva"] in used]
        source=callsite_native_source(sites,native_leaves,sites)
        with tempfile.TemporaryDirectory(prefix="mxb-original-callsite-") as td:
            root=Path(td)
            code=root/"private-original-callsite.c"
            code.write_text(source)
            flags=["-O2","-std=c11","-Wall","-Wextra","-Werror",
                   "-I",str(ROOT/"arm64-lab"/"runtime")]
            host=root/"host"
            out=subprocess.run(["cc",*flags,"-DHOST",str(code),"-o",str(host)],
                               capture_output=True,text=True)
            if out.returncode:
                raise RuntimeError("Original callsite host compile failed: "+out.stderr[-2500:])
            out=subprocess.run([str(host)],capture_output=True,text=True)
            if out.returncode:
                raise RuntimeError("Original original-x64 vs native callsite mismatch")
            arm=root/"native-aarch64.elf"
            out=subprocess.run(["clang","--target=aarch64-unknown-linux-gnu",
                "-fuse-ld=lld","-nostdlib","-static","-ffreestanding",
                "-fno-stack-protector","-fno-builtin",*flags,
                "-Wl,-e,smoke","-Wl,-z,max-page-size=4096",
                "-Wl,--build-id=none",str(code),"-o",str(arm)],
                capture_output=True,text=True)
            if out.returncode:
                raise RuntimeError("Original callsite ARM64 compile failed: "+out.stderr[-2500:])
            result=execute_arm64_elf(arm,instruction_budget=4000000,
                                     timeout_us=15000000)
            if result["arm64_smoke_exit"]!=0:
                raise RuntimeError("Original CALL site vs ARM64 dispatcher mismatch")
    result={
        "schema":1,"original_sha256":EXE_SHA,
        "verified_original_direct_call_sites":len(sites),
        "preceding_opcode_family_counts":dict(Counter(site["preceding_mnemonic"] for site in sites)),
        "preceding_operand_family_counts":dict(Counter(site["preceding_operand_family"] for site in sites)),
        "original_rbp_predecessor_reasons":dict(Counter(site["preceding_frame_class"] for site in sites if site["preceding_frame_class"])),
        "verified_register_setup_plus_call_sites":sum(bool(site["prefixes"]) for site in sites),
        "verified_multi_setup_plus_call_sites":sum(len(site["prefixes"])>1 for site in sites),
        "original_register_setup_instructions_executed":sum(
            len(site["prefixes"]) for site in sites),
        "verified_stack_argument_load_plus_call_sites":sum(any(x["kind"]=="stack_argument_load" for x in site["prefixes"]) for site in sites),
        "verified_frame_pointer_load_plus_call_sites":sum(any(x["kind"]=="frame_pointer_load" for x in site["prefixes"]) for site in sites),
        "verified_guest_heap_load_plus_call_sites":sum(any(x["kind"]=="guest_heap_load" for x in site["prefixes"]) for site in sites),
        "verified_guest_indexed_load_plus_call_sites":sum(any(x["kind"]=="guest_heap_indexed_load" for x in site["prefixes"]) for site in sites),
        "verified_guest_store_plus_call_sites":sum(any(x["kind"]=="guest_heap_store" for x in site["prefixes"]) for site in sites),
        "register_setup_plus_call_x64_host_arm64_fixtures":FIXTURES*sum(bool(site["prefixes"]) for site in sites),
        "original_x64_host_aarch64_edge_fixtures":len(sites)*FIXTURES,
        "unique_original_parent_intervals":len({s["parent_rva"] for s in sites}),
        "unique_verified_native_callee_targets":len({s["target_rva"] for s in sites}),
        "parent_full_functions_native_verified_by_this_gate":0,
        "native_code_artifact_persisted":False,
        "game_engine_booted":False,
        "limitations":"Authentic bounded CALL+callee+RET x64 reference; no full parent prologue/epilogue or engine execution."
    }
    output.mkdir(parents=True,exist_ok=True)
    (output/"verified-original-callsite-edges.json").write_text(
        json.dumps(result,indent=2)+"\n")
    summary="\n".join(["# MX Bikes bounded authentic CALL-edge native differential","",
       "- Original x64 direct CALL sites verified: **"+str(len(sites))+"**",
       "- Original register setup + CALL slices verified: **"+str(result["verified_register_setup_plus_call_sites"])+"**",
       "- Multi-instruction setup + CALL slices verified: **"+str(result["verified_multi_setup_plus_call_sites"])+"**",
       "- Total original argument setup instructions executed: **"+str(result["original_register_setup_instructions_executed"])+"**",
       "- Verified stack-argument-load + CALL slices: **"+str(result["verified_stack_argument_load_plus_call_sites"])+"**",
       "- Verified fixture-bounded frame-pointer-load + CALL slices: **"+str(result["verified_frame_pointer_load_plus_call_sites"])+"**",
       "- Verified bounded guest-pointer-load + CALL slices: **"+str(result["verified_guest_heap_load_plus_call_sites"])+"**",
       "- Verified bounded indexed guest-pointer-load + CALL slices: **"+str(result["verified_guest_indexed_load_plus_call_sites"])+"**",
       "- Verified bounded guest-pointer-store + CALL slices: **"+str(result["verified_guest_store_plus_call_sites"])+"**",
       "- x64/host/AArch64 differential edge fixtures: **"+str(len(sites)*FIXTURES)+"**",
       "- Original parent intervals represented: **"+str(result["unique_original_parent_intervals"])+"**",
       "- Independently verified native callee targets reused: **"+
         str(result["unique_verified_native_callee_targets"])+"**","",
       "## Original callsite predecessor operand families",""]+
       ["- "+kind+": "+str(count) for kind,count in
        sorted(result["preceding_operand_family_counts"].items(),key=lambda x:(-x[1],x[0]))]+["",
       "## Original RBP-relative predecessor eligibility",""]+
       ["- "+kind+": "+str(count) for kind,count in
        sorted(result["original_rbp_predecessor_reasons"].items())]+["",
       "**No parent function is declared translated or added to native dispatch by this step.**",""])
    (output/"verified-original-callsite-edges.md").write_text(summary)
    print(summary)
    return result


if __name__=="__main__":
    p=argparse.ArgumentParser()
    p.add_argument("owned_original",type=Path)
    p.add_argument("same_run_original_map",type=Path)
    p.add_argument("verified_leaf_manifest",type=Path)
    p.add_argument("metadata_output",type=Path)
    p.add_argument("--waves",type=Path)
    args=p.parse_args()
    run(args.owned_original,args.same_run_original_map,
        args.verified_leaf_manifest,args.metadata_output,waves_path=args.waves)
