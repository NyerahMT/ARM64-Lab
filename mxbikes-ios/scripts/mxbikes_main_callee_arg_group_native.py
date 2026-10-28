#!/usr/bin/env python3
"""Original joined Win64 CALL through both parser argument-write blocks on AArch64.

Branch A, quote: LEA RDX,[RCX+1]; CMP BYTE [RCX+1],R9B; JE.
Branch B, nonquote: MOVSXD RAX,R10D; INC R10D; MOV [R11+RAX*8],RCX;
MOV [RIP+disp],R10D; TEST R9D,R9D; JE.
Exactly SHA-checked original PE instruction identities, original x64 full
registers/flags and both BEFORE/AFTER argument-table slot bytes are compared
to host-compiled C and executable AArch64. No complete game boot is inferred.
"""
from pathlib import Path
import hashlib,json,subprocess,sys,tempfile
import mxbikes_main_callee_branch_pair_native as pair
import mxbikes_main_callee_branch_pair_map as mapblocks
import mxbikes_main_callee_quote_jne_native as quote
import mxbikes_main_callee_followup_native as followup
import mxbikes_main_callee_third_jle_native as third
import mxbikes_main_callee_second_jge_native as second
import mxbikes_main_joined_callee_native as joined
from mxbikes_main_callee_native_branch import INPUT as CASES
from mxbikes_whole_game_map import INPUT_SHA as SHA

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/"arm64-lab"))
from tools.pe_probe import PE
from tools.import_aot_smoke import execute_arm64_elf

QUOTED=0x13618a
UNQUOTED=0x1361b9
QUOTE_CMP_JE=0x136192
STORE_JE=0x1361cd
QUOTE_FALL=0x136194
STORE_TAKEN=0x1361d5
QUOTED_CASES=frozenset((3,7))


def verify_original_blocks(pe,layout):
    a=mapblocks.first_control(pe,QUOTED)
    b=mapblocks.first_control(pe,UNQUOTED)
    if ([(v["mnemonic"],v["op_str"]) for v in a["instruction_forms"]]!=[
            ("lea","rdx, [rcx + 1]"),
            ("cmp","byte ptr [rcx + 1], r9b")] or
        a["control_rva"]!=hex(QUOTE_CMP_JE) or
        a["control_kind"]!="je" or
        a["control_direct_target_rva"]!=hex(UNQUOTED) or
        a["control_next_rva"]!=hex(QUOTE_FALL) or
        [(v["mnemonic"],v["op_str"]) for v in b["instruction_forms"]]!=[
            ("movsxd","rax, r10d"),("inc","r10d"),
            ("mov","qword ptr [r11 + rax*8], rcx"),
            ("mov","dword ptr [rip + 0xd14c26], r10d"),
            ("test","r9d, r9d")] or
        b["control_rva"]!=hex(STORE_JE) or
        b["control_kind"]!="je" or
        b["control_direct_target_rva"]!=hex(STORE_TAKEN)):
        raise ValueError("Original quoted/unquoted argument-write opcode block changed")
    first_global=layout["callee_global0"]
    flag_global=layout["callee_global1"]
    if not (first_global==joined.BASE+0xe4ae20 and
            flag_global==joined.BASE+0xe4adf0 and
            first_global+8 & ~4095 == first_global & ~4095):
        raise ValueError("Original argument-array/flag-global layout changed")
    return a,b


def extend_native_argument_blocks(source,table_before,table_after,steps):
    if any(len(x)!=len(CASES) for x in (table_before,table_after,steps)):
        raise ValueError("Original native guest fixture/table count mismatch")
    prior=(f" s->rip=s->zf?UINT64_C({joined.BASE+quote.FALLTHROUGH}):\n"
           f"              UINT64_C({joined.BASE+quote.NOT_QUOTE});\n"
           " s->instructions+=3U;\n return MX_NATIVE_LINK_FRONTIER_REACHED;")
    after=(f" s->rip=s->zf?UINT64_C({joined.BASE+quote.FALLTHROUGH}):\n"
           f"              UINT64_C({joined.BASE+quote.NOT_QUOTE});\n"
           " s->instructions+=3U;\n return native_arg_quotepair(s,m);")
    if source.count(prior)!=1:
        raise ValueError("Proven first-quote-JNE native callback not found")
    helper=f"""
static int native_arg_store(mx_crt_cluster_state*s,mx_cfg_memory*m){{
 if(!s||!m||s->fault||s->rip!=UINT64_C({joined.BASE+UNQUOTED}) ||
    s->r9!=0U||current_branch.r10!=1U||
    s->r11!=CALLEE_G0||CALLEE_G1!=UINT64_C({joined.BASE+0xe4adf0}))
    return MX_GAME_PREFIX_BAD_STATE;
 /* Original MOVSXD RAX,R10D; INC R10D; store live RCX in argv table. */
 const uint32_t idx=(uint32_t)current_branch.r10;
 s->rax=(uint64_t)(int64_t)(int32_t)idx;
 current_branch.r10=(uint32_t)(idx+1U);
 uint64_t slot=s->r11+((uint64_t)idx*8U);
 uint64_t argument=s->rcx;
 uint32_t count=(uint32_t)current_branch.r10;
 if(!mx_cfg_transfer(m,slot,&argument,8U,1)||
    !mx_cfg_transfer(m,CALLEE_G1,&count,4U,1))
    return MX_GAME_PREFIX_UNMAPPED;
 /* Original TEST R9D,R9D + JE 0x1361d5, R9D known zero. */
 s->cf=0U;s->zf=1U;s->sf=0U;
 s->rip=UINT64_C({joined.BASE+STORE_TAKEN});
 s->instructions+=6U;
 return MX_NATIVE_LINK_FRONTIER_REACHED;
}}
static int native_arg_quotepair(mx_crt_cluster_state*s,mx_cfg_memory*m){{
 if(!s||!m||s->fault)return MX_GAME_PREFIX_BAD_STATE;
 if(s->rip==UINT64_C({joined.BASE+QUOTED})){{
    if(s->r9!=0U||s->rcx==UINT64_MAX)return MX_GAME_PREFIX_BAD_STATE;
    /* Original LEA RDX,[RCX+1]; CMP BYTE [RCX+1],R9B; JE. */
    uint64_t addr=s->rcx+1U;
    uint8_t next=0U;
    if(!mx_cfg_transfer(m,addr,&next,1U,0))
        return MX_GAME_PREFIX_UNMAPPED;
    s->rdx=addr;
    const uint8_t diff=(uint8_t)(next-(uint8_t)s->r9);
    s->cf=(uint8_t)(next<(uint8_t)s->r9);
    s->zf=(uint8_t)(diff==0U);
    s->sf=(uint8_t)(diff>>7U);
    s->rip=s->zf?UINT64_C({joined.BASE+UNQUOTED}):
                 UINT64_C({joined.BASE+QUOTE_FALL});
    s->instructions+=3U;
    if(!s->zf)return MX_NATIVE_LINK_FRONTIER_REACHED;
 }}
 return native_arg_store(s,m);
}}
"""
    anchor="static int native_quote_branch(mx_crt_cluster_state*s,mx_cfg_memory*m){"
    if source.count(anchor)!=1:
        raise ValueError("Joined original quote-JNE stage no longer callable")
    source=source.replace(anchor,helper+anchor)
    source=source.replace(prior,after)
    call=(f"r,s,m,CALLEE,AFTER_CALL,UINT64_C({joined.BASE+quote.NOT_QUOTE}),"
          f"UINT64_C({joined.BASE+quote.FALLTHROUGH}));")
    repl=(f"r,s,m,CALLEE,AFTER_CALL,UINT64_C({joined.BASE+QUOTE_FALL}),"
          f"UINT64_C({joined.BASE+STORE_TAKEN}));")
    if source.count(call)!=1:
        raise ValueError("Authentic Win64 guest CALL frontier changed")
    source=source.replace(call,repl)
    extra=(
       "static const uint64_t expected_arg_slot_before[CASES]={"+
       ",".join(f"UINT64_C({x})" for x in table_before)+"};\n"+
       "static const uint64_t expected_arg_slot_after[CASES]={"+
       ",".join(f"UINT64_C({x})" for x in table_after)+"};\n"
    )
    read="static uint64_t read_guest(mx_cfg_memory*m,uint64_t addr,unsigned size){"
    if source.count(read)!=1:raise ValueError("Guest pointer verification unavailable")
    source=source.replace(read,extra+read)
    init="   mx_crt_cluster_state s={0};"
    if source.count(init)!=1:raise ValueError("Original guest initialization changed")
    source=source.replace(init,
        """   uint64_t initial_arg_slot=expected_arg_slot_before[i];
   if(!mx_cfg_transfer(&mem,CALLEE_G0+8U,&initial_arg_slot,8U,1))return 33;
"""+init)
    verify="   if(read_guest(&mem,ARG0,8U)!=f->arg0 ||"
    if source.count(verify)!=1:raise ValueError("Original guest global checks missing")
    source=source.replace(verify,
        """   if(read_guest(&mem,CALLEE_G0+8U,8U)!=expected_arg_slot_after[i])
     return 34+(int)i;
"""+verify)
    return source


def run(original,out):
    pe=PE(original)
    if hashlib.sha256(pe.b).hexdigest()!=SHA:
        raise ValueError("Original owned PE revision differs from SHA pin")
    second.verify_second_branch(pe)
    third.verify_third_branch(pe)
    pair.verified_pair(pe)
    followup.verify_original_followup(pe)
    quote.original_branch(pe)
    joined.verify_main(original)
    layout,_,_=joined.inspect_original(pe)
    verify_original_blocks(pe,layout)
    records=[pair.reference(pe,layout,i,arg_group=True)
             for i in range(len(CASES))]
    outcomes={}
    for _,v,_,_ in records:
        loc=hex(v["rip"]-joined.BASE)
        outcomes[loc]=outcomes.get(loc,0)+1
        if loc not in (hex(joined.AFTER_CALL),hex(QUOTE_FALL),hex(STORE_TAKEN)):
            raise RuntimeError("Original x64 argument-write branch escaped strict frontier")
    if not outcomes.get(hex(QUOTE_FALL)) or not outcomes.get(hex(STORE_TAKEN)):
        raise RuntimeError("Both authentic quote and argument-write controls not executed")
    refs=[(before,state) for before,state,_,_ in records]
    statuses=[status for _,_,_,status in records]
    steps=[steps for _,_,steps,_ in records]
    second_bytes=[0 if i==7 else pair.next_byte(i) for i in range(len(CASES))]
    src,_=joined.generate(layout,refs)
    src=third.extend_third_jle(second.extend_joined_source(
        src,second.verify_second_branch(pe)))
    src=pair.extend_native_pair(src,second_bytes,statuses,steps)
    src=followup.extend_joined_native_followup(src)
    src=quote.extend_quote_native(src)
    src=extend_native_argument_blocks(src,
          [v["argument_slot_before"] for _,v,_,_ in records],
          [v["argument_slot_after"] for _,v,_,_ in records],steps)
    with tempfile.TemporaryDirectory(prefix="mxb-original-argument-writes-") as td:
        root=Path(td);file=root/"original-guest-argv-table-arm64.c"
        file.write_text(src)
        opts=["-O2","-std=c11","-Wall","-Wextra","-Werror",
              "-I",str(ROOT/"arm64-lab"/"runtime")]
        host=root/"host"
        p=subprocess.run(["cc",*opts,"-DHOST",str(file),"-o",str(host)],
                         capture_output=True,text=True)
        if p.returncode:
            raise RuntimeError("Original Win64 argv-block host compile: "+p.stderr[-3000:])
        p=subprocess.run([str(host)],capture_output=True,text=True)
        if p.returncode:
            raise RuntimeError("Authentic original x64 argv guest + host mismatch: "+str(p.returncode))
        arm=root/"original-argv-write-arm64.elf"
        p=subprocess.run(["clang","--target=aarch64-unknown-linux-gnu",
              "-fuse-ld=lld","-nostdlib","-static","-ffreestanding",
              "-fno-builtin","-fno-stack-protector",*opts,
              "-Wl,-e,smoke","-Wl,-z,max-page-size=4096",
              "-Wl,--build-id=none",str(file),"-o",str(arm)],
              capture_output=True,text=True)
        if p.returncode:
            raise RuntimeError("Native ARM64 argv-block compile: "+p.stderr[-3000:])
        res=execute_arm64_elf(arm,instruction_budget=2300000,timeout_us=15000000)
        if res["arm64_smoke_exit"]!=0:
            raise RuntimeError("Original x64/native AArch64 argument-table mismatch: "+
                               str(res["arm64_smoke_exit"]))
    out.mkdir(parents=True,exist_ok=True)
    report={
        "original_sha256":SHA,
        "native_arm64_executed_original_argument_table_write":True,
        "original_x64_host_arm64_guest_differential_cases":len(CASES),
        "original_argument_table_after_compared_cases":len(CASES),
        "original_quote_case_indices":[3,7],
        "real_guest_execution_end_rvas":outcomes,
        "original_callee_full_all_paths":False,
        "game_engine_or_ios_booted":False,
        "machine_code_or_original_pe_exported":False
    }
    (out/"joined-argument-write-native.json").write_text(json.dumps(report,indent=2)+"\n")
    lines=["# MX Bikes original x64 joined argv table native AArch64 write","",
         "- Original x64 vs compiled host vs executed AArch64 cases: **16/16**",
         "- Compared original argument table BEFORE and AFTER native write: **16/16**",
         "- Both quoted and nonquoted input paths executed: **YES**","",
         "## Executed game-callee remaining frontiers"]
    lines.extend("- "+k+": **"+str(v)+" cases**" for k,v in sorted(outcomes.items()))
    lines+=["","Whole game main / original callee / menu / IPA running: **NO**",""]
    (out/"joined-argument-write-native.md").write_text("\n".join(lines))
    print("\n".join(lines))
    return report


if __name__=="__main__":
    if len(sys.argv)!=3:
        raise SystemExit("usage: argument_native.py owned-original.exe metadata-dir")
    run(Path(sys.argv[1]),Path(sys.argv[2]))
