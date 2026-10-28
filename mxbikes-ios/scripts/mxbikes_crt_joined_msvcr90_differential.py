#!/usr/bin/env python3
"""Verify one continuous 49-instruction original MX Bikes CRT control region.

The privately owned original x64 runs through both imported CALL sites with
deterministic synthetic GetStartupInfoA and Sleep handlers. Translated C/AArch64
uses five strict block lifts, then compares guest register/flag/global/stack
effects and retry paths. This is NOT live Windows or full startup.
"""
import hashlib,json,struct,subprocess,sys,tempfile
from pathlib import Path
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
from capstone.x86 import X86_OP_MEM, X86_OP_IMM
from unicorn import Uc,UC_ARCH_X86,UC_MODE_64,UC_HOOK_CODE,UC_HOOK_MEM_INVALID
from unicorn.x86_const import (
    UC_X86_REG_RIP,UC_X86_REG_RSP,UC_X86_REG_RAX,UC_X86_REG_RBX,
    UC_X86_REG_R8,UC_X86_REG_R9,
    UC_X86_REG_RDI,UC_X86_REG_RSI,UC_X86_REG_RCX,UC_X86_REG_RDX,UC_X86_REG_EFLAGS,
    UC_X86_REG_GS_BASE
)

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/"arm64-lab"))
from tools.pe_probe import PE
from tools.crt_entry_prefix_lift import lift_crt_entry_prefix
from tools.crt_gs_lock_lift import lift_crt_gs_lock_prefix
from tools.crt_retry_lift import lift_crt_retry
from tools.crt_init_state_lift import lift_crt_init_state
from tools.crt_common_release_lift import lift_crt_common_release
from tools.crt_post_import import after_initterm_e,after_initterm
from mxbikes_crt_import_thunk_differential import decode_calls
from tools.import_aot_smoke import execute_arm64_elf
from mxbikes_first_callee_emu import import_slots
from mxbikes_crt_initializer_inventory import inventory
from mxbikes_crt_initializer_table_walk import source_tables
from mxbikes_crt_second_tail_body_differential import (
    inspect as inspect_second_initializer, LOCAL as SECOND_LOCAL_RVA,
    WRAPPER as SECOND_WRAPPER_RVA
)
from mxbikes_crt_argsetup_body_differential import (
    calls_and_input as inspect_argument_initializer,
    WRAPPER as ARG_WRAPPER_RVA, DATA_RVA as ARG_DATA_RVA,
    DATA_SIZE as ARG_DATA_SIZE
)
from mxbikes_crt_appsetup_body_differential import (
    source_input as inspect_app_initializer,
    mapped_original_image, reference as app_reference,
    DATA_POINTER_SLOT, MODE_POINTER_SLOT, EXTERNAL_GLOBAL,
    LOCAL_A as APP_LOCAL_A_RVA, LOCAL_B as APP_LOCAL_B_RVA,
    API_NAMES as APP_API_NAMES
)
from tools.crt_import_cluster_lift import lift_crt_import_cluster
from mxbikes_main_joined_callee_native import inspect_original as inspect_main_prefix
from mxbikes_main_filename_native import (
    verify_next_import as verify_module_api,
    PATH as MODELED_GAME_PATH,
)
from mxbikes_filename_helper_native import verify_helper as verify_game_path_helper
from mxbikes_msvcr90_strcpy_native import original_thunk as verify_game_strcpy
from mxbikes_post_strcpy_native import verify_source as verify_post_strcpy
from mxbikes_after_strcpy_branch_native import (
    verify_branch as verify_game_first_branch,
    original_branch as original_filename_branch,
)
from mxbikes_filename_separator_native import validate_original as verify_game_separator
from mxbikes_filename_normal_loop_native import validate_source as verify_game_slash_loop
from mxbikes_main_after_filename_map import block as inspect_next_main_block
from mxbikes_crt_joined_wrapper_child_aot import (
    verify as verify_tail_wrapper, verify_tail as verify_tail_callback,
    reference_original as tail_reference, TAIL_ARGUMENT
)
from mxbikes_crt_child_path_reference import (
    ENTRY as TAIL_CHILD_RVA, END as TAIL_CHILD_END,
    SLOTS as TAIL_CHILD_IAT, THUNKS as TAIL_CHILD_THUNKS,
    GLOBALS as TAIL_CHILD_GLOBALS, cases as tail_cases
)

SHA="4ae7de3854b4d0a18271679fb57a1f2fdf0b21804417b85dd82055078ea123b6"
BASE=0x140000000
ENTRY=0x2ab02c
GET_INFO_CALL=0x2ab043
AFTER_INFO=0x2ab049
CAS_RETRY=0x2ab059
LOCK_BRANCH=0x2ab064
DONE=0x2ab07f
FINAL=0x2ab0d3
RELEASE_END=0x2ab108
RELEASE_CALL=0x2ab0ec
AFTER_E=0x2ab0bb
POST_E_END=0x2ab0c9
AFTER_VOID=0x2ab0f1
ERROR_STOP=0x2ab221
CALL_BUSY=0x2ab08d
CALL_INIT=0x2ab0b6
MAIN_CALL=0x2ab186
MAIN_TARGET=0x136710
STATE=BASE+0xe4ada0
ALT=BASE+0x3d803c
GLOBAL=BASE+0xe4ada8
GS=0x720000000
STACK=0x700000000
SP=STACK+0xff08
WIN=SP-256
STUB_INFO=0x600000000
STUB_SLEEP=STUB_INFO+0x20
STUB_E=STUB_INFO+0x40
STUB_VOID=STUB_INFO+0x60
FIELDS=("rax","rbx","rcx","rdi","rsi","rsp","rip","zf","global","sleep_return","suffix_bits","suffix_steps","sleep_calls","rdx","state_after","alt_after","state_bits","state_steps","release_bits","release_steps","crt_e_calls","crt_void_calls")

def scenarios():
    for i in range(54):
        mode=i%3
        thread=0x112233440000+i*0x319
        other=0x778800110000+i*101
        yield {
            "mode":mode, "thread":thread,
            "init_status":0 if (i//9)%2==0 else (1,2,255)[i%3],
            "state":(0,1,2)[(i//3)%3], "alt":(i*0x123)&0xffffffff,
            "rdx":0x889977665544+i*31,
            "global_initial":0 if mode==0 else (thread if mode==1 else other),
            "rax":0x123456000000+i*971,
            "rbx":0x554400001100+i*881,
            "rsi":0x667788110000+i*311,
            "rdi":0x889900001100+i*71,
            "rcx":0x111122223333+i*127
        }

def reference(original:bytes,info_slot:int,sleep_slot:int,original_instr,scenario,specs):
    x=Uc(UC_ARCH_X86,UC_MODE_64)
    pages={(BASE+ENTRY)&~0xfff,(BASE+info_slot)&~0xfff,
           (BASE+sleep_slot)&~0xfff,GLOBAL&~0xfff,ALT&~0xfff,
           *((BASE+v["iat_rva"])&~0xfff for v in specs)}
    for pg in pages:x.mem_map(pg,0x1000)
    x.mem_map(GS,0x1000)
    x.mem_map(STUB_INFO,0x1000)
    x.mem_map(STACK,0x20000)
    x.mem_write(BASE+ENTRY,original)
    x.mem_write(BASE+info_slot,struct.pack("<Q",STUB_INFO))
    x.mem_write(BASE+sleep_slot,struct.pack("<Q",STUB_SLEEP))
    x.mem_write(STUB_INFO,b"\xc3")
    x.mem_write(STUB_SLEEP,b"\xc3")
    x.mem_write(STUB_E,bytes([0xc3]))
    x.mem_write(STUB_VOID,bytes([0xc3]))
    for spec,stub in zip(specs,(STUB_E,STUB_VOID)):
        x.mem_write(BASE+spec["thunk_rva"],spec["original_thunk"])
        x.mem_write(BASE+spec["iat_rva"],struct.pack("<Q",stub))
    x.mem_write(GS+0x30,struct.pack("<Q",GS))
    x.mem_write(GS+8,struct.pack("<Q",scenario["thread"]))
    x.mem_write(GLOBAL,struct.pack("<Q",scenario["global_initial"]))
    x.mem_write(STATE,struct.pack("<I",scenario["state"]))
    x.mem_write(ALT,struct.pack("<I",scenario["alt"]))
    x.reg_write(UC_X86_REG_GS_BASE,GS)
    for name,reg in (("rax",UC_X86_REG_RAX),("rbx",UC_X86_REG_RBX),
                     ("rcx",UC_X86_REG_RCX),("rsi",UC_X86_REG_RSI),
                     ("rdi",UC_X86_REG_RDI),("rdx",UC_X86_REG_RDX)):
        x.reg_write(reg,scenario[name])
    x.reg_write(UC_X86_REG_RIP,BASE+ENTRY)
    x.reg_write(UC_X86_REG_RSP,SP)
    x.reg_write(UC_X86_REG_EFLAGS,0x202)
    suffix_code=[ins for ins in original_instr if CAS_RETRY<=ins.address<DONE]
    state_code=[ins for ins in original_instr if DONE<=ins.address<FINAL]
    state_bits={BASE+ins.address:j for j,ins in enumerate(state_code)}
    release_code=[ins for ins in original_instr if FINAL<=ins.address<RELEASE_END]
    release_bits={BASE+ins.address:j for j,ins in enumerate(release_code)}
    suffix={BASE+ins.address:j for j,ins in enumerate(suffix_code)}
    expected={BASE+ins.address for ins in original_instr}
    counts={"info":0,"sleep":0,"suffix_bits":0,"suffix_steps":0,
            "state_bits":0,"state_steps":0,"release_bits":0,"release_steps":0,
            "in_retry_branch":False,"crt_e_calls":0,"crt_void_calls":0}
    def hook(emu,pc,size,user):
        if pc==STUB_INFO:
            counts["info"]+=1
            if counts["info"]!=1:return
            if emu.reg_read(UC_X86_REG_RSP)%16!=8:
                raise RuntimeError("Original GetStartupInfoA callee stack alignment mismatch")
            address=emu.reg_read(UC_X86_REG_RCX)
            data=struct.pack("<I",104)+bytes(100)
            if address<WIN or address+104>WIN+512:
                raise RuntimeError("Original startup info memory escaped bounded stack")
            emu.mem_write(address,data)
            return
        if pc==STUB_SLEEP:
            counts["sleep"]+=1
            if scenario["mode"]!=2 or counts["sleep"]!=1:
                raise RuntimeError("Unexpected original Sleep callback path")
            if emu.reg_read(UC_X86_REG_RCX)!=1000:
                raise RuntimeError("Original CRT did not pass Sleep(1000)")
            emu.mem_write(GLOBAL,struct.pack("<Q",0))
            return
        if pc==STUB_E:
            counts["crt_e_calls"]+=1
            if counts["crt_e_calls"]!=1 or emu.reg_read(UC_X86_REG_RSP)%16!=8:
                raise RuntimeError("Original _initterm_e thunk ABI mismatch")
            emu.reg_write(UC_X86_REG_RAX,scenario["init_status"])
            return
        if pc==STUB_VOID:
            counts["crt_void_calls"]+=1
            if counts["crt_void_calls"]!=1 or emu.reg_read(UC_X86_REG_RSP)%16!=8:
                raise RuntimeError("Original _initterm thunk ABI mismatch")
            return
        if pc in (BASE+specs[0]["thunk_rva"],BASE+specs[1]["thunk_rva"]):
            return
        if pc not in expected or pc==BASE+CALL_BUSY:
            raise RuntimeError("Original x64 escaped bounded startup or attempted unverified direct call")
        # Initial XOR/CAS is owned by the preceding GS block. Only
        # instrument instructions starting at the first branch, then any
        # backward retries, just as the native joined harness resets its
        # counters when that block returns.
        if pc==BASE+LOCK_BRANCH:
            counts["in_retry_branch"]=True
        if counts["in_retry_branch"] and pc in suffix:
            counts["suffix_bits"]|=1<<suffix[pc]
            counts["suffix_steps"]+=1
        if pc in state_bits and pc!=BASE+CALL_INIT and not (BASE+AFTER_E<=pc<BASE+POST_E_END):
            counts["state_bits"]|=1<<state_bits[pc]
            counts["state_steps"]+=1
        if pc in release_bits:
            counts["release_bits"]|=1<<release_bits[pc]
            counts["release_steps"]+=1
    x.hook_add(UC_HOOK_CODE,hook)
    stop=(CALL_BUSY if scenario["state"]==1 else
          ERROR_STOP if scenario["state"]==0 and scenario["init_status"] else
          RELEASE_END)
    x.emu_start(BASE+ENTRY,BASE+stop,timeout=3_000_000,count=180)
    if counts["info"]!=1 or counts["sleep"]!=(1 if scenario["mode"]==2 else 0):
        raise RuntimeError("Original startup import calls did not match the intended scenario")
    out={}
    for name,reg in (("rax",UC_X86_REG_RAX),("rbx",UC_X86_REG_RBX),
                     ("rcx",UC_X86_REG_RCX),("rdi",UC_X86_REG_RDI),
                     ("rsi",UC_X86_REG_RSI),("rdx",UC_X86_REG_RDX),("rsp",UC_X86_REG_RSP),
                     ("rip",UC_X86_REG_RIP)):
        out[name]=x.reg_read(reg)
    out["zf"]=int(bool(x.reg_read(UC_X86_REG_EFLAGS)&64))
    out["global"]=struct.unpack("<Q",x.mem_read(GLOBAL,8))[0]
    out["state_after"]=struct.unpack("<I",x.mem_read(STATE,4))[0]
    out["alt_after"]=struct.unpack("<I",x.mem_read(ALT,4))[0]
    out["sleep_return"]=struct.unpack("<Q",x.mem_read(SP-0xb0,8))[0]
    out["suffix_bits"]=counts["suffix_bits"]
    out["suffix_steps"]=counts["suffix_steps"]
    out["sleep_calls"]=counts["sleep"]
    out["state_bits"]=counts["state_bits"]
    out["state_steps"]=counts["state_steps"]
    out["release_bits"]=counts["release_bits"]
    out["release_steps"]=counts["release_steps"]
    out["crt_e_calls"]=counts["crt_e_calls"]
    out["crt_void_calls"]=counts["crt_void_calls"]
    out["stack"]=bytes(x.mem_read(WIN,512))
    release=(scenario["state"]==2 or (scenario["state"]==0 and not scenario["init_status"]))
    owner_expected=0 if release and scenario["mode"]!=1 else scenario["thread"]
    if (out["rip"]!=BASE+stop or out["rsp"]!=SP-0xa8 or
            out["global"]!=owner_expected):
        raise RuntimeError("Original 49-instruction CRT outcome failed bounded reference checks")
    return out

NATIVE=r"""
#include <stdint.h>
#ifdef HOST
#include <stdio.h>
#endif
#include "mx_crt_primitives.h"
#include "mx_crt_init_imports.h"
#include "mx_crt_startup_bridge.h"
#include "mx_crt_exception_callback.h"
#include "mx_crt_cluster_guest.h"
#include "mx_crt_process_services.h"
#include "mx_crt_joined_wrapper.h"
#include "mx_crt_main_handoff.h"
#include "mx_crt_to_main_prefix.h"
#include "mx_native_guest_linker.h"
#include "mx_game_main_callee_prefix.h"
#include "mx_game_module_filename.h"
#include "mx_game_path_helper_prefix.h"
#include "mx_game_crt_strcpy.h"
#include "mx_game_path_after_strcpy.h"
#include "mx_game_path_after_strcpy_branch.h"
#include "mx_game_path_separator_branch.h"
#include "mx_game_path_slash_loop.h"
#include "mx_game_filename_loop_iteration.h"
#include "mx_game_filename_scan.h"
#include "mx_game_filename_separator_finish.h"
#include "mx_game_filename_helper_return.h"
#include "mx_game_virtual_current_directory.h"
#define BASE UINT64_C(0x140000000)
#define ENTRY UINT64_C(ENTRY_VA)
#define GS UINT64_C(GS_VA)
#define SP UINT64_C(SP_VA)
#define WIN UINT64_C(WIN_VA)
#define GLOBAL UINT64_C(GLOBAL_VA)
#define STATE UINT64_C(STATE_VA)
#define ALT UINT64_C(ALT_VA)
#define AFTER_INFO UINT64_C(AFTER_INFO_VA)
#define BRANCH UINT64_C(BRANCH_VA)
#define RELEASE UINT64_C(RELEASE_VA)
#define INITIALIZER_CALL UINT64_C(INIT_CALL_VA)
#define VOID_INITIALIZER_CALL UINT64_C(VOID_CALL_VA)
#define E_BEGIN UINT64_C(E_BEGIN_VA)
#define I_BEGIN UINT64_C(I_BEGIN_VA)
#define APP_CALLBACK UINT64_C(APP_CALLBACK_VA)
#define EXCEPTION_CALLBACK UINT64_C(EXCEPTION_CALLBACK_VA)
#define EXCEPTION_HANDLER UINT64_C(EXCEPTION_HANDLER_VA)
#define ARG_CALLBACK UINT64_C(ARG_CALLBACK_VA)
#define SECOND_CALLBACK UINT64_C(SECOND_CALLBACK_VA)
#define TAIL_CALLBACK UINT64_C(TAIL_CALLBACK_VA)
#define SECOND_LOCAL UINT64_C(SECOND_LOCAL_VA)
#define SECOND_WRAPPER UINT64_C(SECOND_WRAPPER_VA)
#define SECOND_FIRST_ARG UINT64_C(SECOND_FIRST_ARG_VA)
#define SECOND_TAIL_ARG UINT64_C(SECOND_TAIL_ARG_VA)
#define CALLBACK_STACK_BEGIN UINT64_C(0x71000fe80)
#define CALLBACK_SP UINT64_C(0x71000ff08)
#define ARG_WRAPPER UINT64_C(ARG_WRAPPER_VA)
#define ARG_DATA UINT64_C(ARG_DATA_VA)
#define ARG_DATA_SIZE 8192U
#define PE_PAGE_COUNT PE_PAGE_COUNT_V
#define PE_PAGE_SIZE 4096U
#define APP_LOCAL_A UINT64_C(APP_LOCAL_A_VA)
#define APP_LOCAL_B UINT64_C(APP_LOCAL_B_VA)
#define APP_EXTERNAL UINT64_C(APP_EXTERNAL_VA)
#define APP_DATA_SLOT UINT64_C(APP_DATA_SLOT_VA)
#define APP_MODE_SLOT UINT64_C(APP_MODE_SLOT_VA)
#define APP_EXPECTED_RAX UINT64_C(APP_EXPECTED_RAX_V)
#define APP_EXPECTED_VISITED UINT64_C(APP_EXPECTED_VISITED_V)
#define APP_EXPECTED_CALLS APP_EXPECTED_CALLS_V
#define TAIL_ARG UINT64_C(TAIL_ARG_VA)
#define TAIL_WRAPPER UINT64_C(TAIL_WRAPPER_VA)
#define TAIL_CHILD UINT64_C(TAIL_CHILD_VA)
#define TAIL_G0 UINT64_C(TAIL_G0_VA)
#define TAIL_G1 UINT64_C(TAIL_G1_VA)
#define TAIL_INIT_G0 UINT64_C(TAIL_INIT_G0_V)
#define TAIL_INIT_G1 UINT64_C(TAIL_INIT_G1_V)
#define TAIL_EXPECT_RAX UINT64_C(TAIL_EXPECT_RAX_V)
#define POST_RELEASE_PC UINT64_C(POST_RELEASE_PC_V)
#define MAIN_CALL_PC UINT64_C(MAIN_CALL_PC_V)
#define CMDLINE_IAT UINT64_C(CMDLINE_IAT_V)
#define ONEXIT_GUARD UINT64_C(ONEXIT_GUARD_V)
#define MAIN_ENTRY_PC UINT64_C(MAIN_ENTRY_PC_V)
#define MAIN_FIRST_CALL UINT64_C(MAIN_FIRST_CALL_V)
#define MAIN_COOKIE UINT64_C(MAIN_COOKIE_V)
#define MAIN_ARG0 UINT64_C(MAIN_ARG0_V)
#define MAIN_ARG1 UINT64_C(MAIN_ARG1_V)
#define MAIN_SHOW UINT64_C(MAIN_SHOW_V)
#define MAIN_COOKIE_INIT UINT64_C(MAIN_COOKIE_INIT_V)
#define GAME_CALLEE UINT64_C(GAME_CALLEE_V)
#define GAME_CALLEE_CONST UINT64_C(GAME_CALLEE_CONST_V)
#define GAME_CALLEE_G0 UINT64_C(GAME_CALLEE_G0_V)
#define GAME_CALLEE_G1 UINT64_C(GAME_CALLEE_G1_V)
#define GAME_CALLEE_TAKEN UINT64_C(GAME_CALLEE_TAKEN_V)
#define GAME_CALLEE_FALL UINT64_C(GAME_CALLEE_FALL_V)
#define GAME_CALLEE_RET UINT64_C(GAME_CALLEE_RET_V)
#define GAME_FILENAME_CALL UINT64_C(GAME_FILENAME_CALL_V)
#define GAME_FILENAME_AFTER UINT64_C(GAME_FILENAME_AFTER_V)
#define MODELED_FILENAME_LENGTH MODELED_FILENAME_LENGTH_V
#define GAME_HELPER UINT64_C(GAME_HELPER_V)
#define GAME_HELPER_CALL UINT64_C(GAME_HELPER_CALL_V)
#define GAME_HELPER_RETURN UINT64_C(GAME_HELPER_RETURN_V)
#define GAME_HELPER_TRANSFER UINT64_C(GAME_HELPER_TRANSFER_V)
#define GAME_HELPER_DEST UINT64_C(GAME_HELPER_DEST_V)
#define GAME_STRCPY_THUNK UINT64_C(GAME_STRCPY_THUNK_V)
#define GAME_STRCPY_RETURN UINT64_C(GAME_STRCPY_RETURN_V)
#define GAME_STRCPY_DEST UINT64_C(GAME_STRCPY_DEST_V)
#define GAME_POST_STRCPY_JUMP (BASE+UINT64_C(0x15b7cf))
#define GAME_NONZERO_START (BASE+UINT64_C(0x15b7db))
#define GAME_FIRST_LOOP (BASE+UINT64_C(0x15b7c1))
#define GAME_SEPARATOR_FOUND (BASE+UINT64_C(0x15b7f5))
#define GAME_CWD_PREPARE (BASE+UINT64_C(0x136769))
#define GAME_CWD_CALL (BASE+UINT64_C(0x13676c))
#define GAME_CWD_AFTER (BASE+UINT64_C(0x136772))
#define GAME_NEXT_CALL (BASE+UINT64_C(0x13677f))
#define GAME_NEXT_ARG_GLOBAL (BASE+UINT64_C(0xe4adf0))
#define GAME_NEXT_RDX_ADDRESS (BASE+UINT64_C(0xe4ae20))
#define MAIN_RETURN_PC (MAIN_CALL_PC+5U)
#define EXTRA_MAIN_STACK_BEGIN (WIN-UINT64_C(2048))
#define CMDLINE_VAR (APP_EXTERNAL+UINT64_C(0x100))
#define CMDLINE_TEXT (APP_EXTERNAL+UINT64_C(0x180))
typedef struct {
    uint64_t mode,thread,global_initial,rax,rbx,rcx,rsi,rdi,state,alt,rdx,init_status;
    uint64_t e_rax,e_rbx,e_rcx,e_rdi,e_rsi,e_rsp,e_rip,e_zf,e_global;
    uint64_t e_sleep_return,e_suffix_bits,e_suffix_steps,e_sleep_calls;
    uint64_t e_rdx,e_state_after,e_alt_after,e_state_bits,e_state_steps;
    uint64_t e_release_bits,e_release_steps;
    uint64_t e_crt_e_calls,e_crt_void_calls;
    uint64_t main_out[11];
    uint8_t expected_stack[512];
} fixture;
static const fixture cases[]={
__CASES__
};
static uint8_t stack_bytes[512],teb[256],callback_stack[256];
static uint8_t extra_main_stack[2048];
static const uint8_t modeled_filename[]={67,58,92,77,88,66,105,107,101,115,92,109,120,98,105,107,101,115,46,101,120,101,0};
static const mx_game_main_callee_layout original_game_callee={
    GAME_CALLEE,GAME_CALLEE_CONST,GAME_CALLEE_G0,GAME_CALLEE_G1,
    GAME_CALLEE_TAKEN,GAME_CALLEE_FALL
};
static int joined_game_main_first_child(
    mx_crt_cluster_state *state,mx_cfg_memory *memory,void *opaque){
    (void)opaque;
    mx_game_main_callee_out out={0};
    if(mx_game_main_callee_branch(state,memory,
        &original_game_callee,&out)!=MX_GAME_PREFIX_BRANCH_REACHED ||
       !out.branch_taken || out.input_first_byte!=0U ||
       out.r10!=1U || out.executed_original_instructions!=7U)
        return MX_NATIVE_LINK_BAD_FRONTIER;
    return mx_game_main_callee_finish_empty(
        state,memory,&original_game_callee);
}
static const mx_game_path_helper_layout original_path_helper={
    GAME_HELPER,GAME_HELPER_TRANSFER,GAME_HELPER_DEST,0x38U
};
static int joined_game_path_helper(
    mx_crt_cluster_state *state,mx_cfg_memory *memory,void *opaque){
    (void)opaque;
    int status=mx_game_path_helper_first_block(
        state,memory,&original_path_helper);
    return status==MX_GAME_PATH_HELPER_FRONTIER?
        MX_NATIVE_LINK_FRONTIER_REACHED:status;
}
static const mx_game_path_after_strcpy_layout original_post_strcpy={
    GAME_STRCPY_RETURN,GAME_STRCPY_DEST,GAME_POST_STRCPY_JUMP
};
static const mx_game_path_after_strcpy_branch_layout original_branch={
    GAME_POST_STRCPY_JUMP,BASE+UINT64_C(0x15b801),GAME_NONZERO_START
};
static const mx_game_path_separator_layout original_separators={
    GAME_NONZERO_START,BASE+UINT64_C(0x15b801),
    GAME_SEPARATOR_FOUND,BASE+UINT64_C(0x15b7e8),
    BASE+UINT64_C(0x15b81b),BASE+UINT64_C(0x15b809)
};
static const mx_game_slash_loop_layout original_slash_loop={
    BASE+UINT64_C(0x15b7e8),GAME_SEPARATOR_FOUND,GAME_FIRST_LOOP
};
static const mx_game_filename_iteration_layout original_iteration={
    GAME_FIRST_LOOP,BASE+UINT64_C(0x15b801),GAME_NONZERO_START
};
static const mx_game_filename_finish_layout original_directory_finish={
    BASE+UINT64_C(0x15b809),GAME_STRCPY_DEST,
    BASE+UINT64_C(0x15b862),260U
};
static const mx_game_filename_scan_layout original_entire_filename_scan={
    {GAME_FIRST_LOOP,BASE+UINT64_C(0x15b801),GAME_NONZERO_START},
    {GAME_NONZERO_START,BASE+UINT64_C(0x15b801),
     GAME_SEPARATOR_FOUND,BASE+UINT64_C(0x15b7e8),
     BASE+UINT64_C(0x15b81b),BASE+UINT64_C(0x15b809)},
    {BASE+UINT64_C(0x15b7e8),GAME_SEPARATOR_FOUND,GAME_FIRST_LOOP},
    GAME_SEPARATOR_FOUND,GAME_FIRST_LOOP,
    BASE+UINT64_C(0x15b809),BASE+UINT64_C(0x15b81b),260U
};
static int authorized_virtual_game_directory(
    void *opaque,const uint8_t *name,uint32_t nbytes){
    if(!opaque||*(const uint32_t*)opaque!=1U||nbytes!=11U)
        return -1;
    static const uint8_t allowed[]={
        67,58,92,77,88,66,105,107,101,115,92
    };
    for(uint32_t i=0;i<11U;i++)
        if(name[i]!=allowed[i])return -1;
    return 1;
}
static const mx_native_link_entry verified_game_children[]={
    {GAME_CALLEE,joined_game_main_first_child,0},
    {GAME_HELPER,joined_game_path_helper,0}
};
static uint8_t app_external_data[4096];
static uint8_t pe_pages[PE_PAGE_COUNT][PE_PAGE_SIZE];
static const uint32_t pe_page_rvas[PE_PAGE_COUNT]={PE_PAGE_RVAS};
static const uint8_t original_pe_header[4096]={APP_HEADER_DATA};
typedef struct {uint32_t address;uint8_t bytes[8];} app_seed;
static const app_seed app_seeds[]={APP_SEED_ROWS};
static const uint32_t app_iat_rvas[4]={APP_IAT_RVAS};
static const uint32_t child_iat_rvas[6]={TAIL_IAT_RVAS};
static const uint64_t e_init_words[3]={E_VALUES};
static const uint64_t i_init_words[4]={I_VALUES};
static uint8_t *pe_address(uint32_t rva){
    for(uint32_t k=0;k<PE_PAGE_COUNT;k++){
        if(rva>=pe_page_rvas[k] && rva-pe_page_rvas[k]<PE_PAGE_SIZE)
            return &pe_pages[k][rva-pe_page_rvas[k]];
    }
    return (uint8_t*)0;
}
static int pe_seed_byte(uint32_t rva,uint8_t value){
    uint8_t *ptr=pe_address(rva);
    if(!ptr)return 0;
    *ptr=value;return 1;
}
static int pe_seed64(uint32_t rva,uint64_t value){
    for(uint32_t j=0;j<8U;j++)
        if(!pe_seed_byte(rva+j,(uint8_t)(value>>(8U*j))))return 0;
    return 1;
}
typedef struct {mx_cfg_memory *memory;uint32_t slept;int release;} sleep_ctx;
int lifted_crt_entry_prefix(mx_crt_state *,mx_cfg_memory *);
int lifted_crt_gs_lock_prefix(mx_crt_state *,mx_cfg_memory *,uint64_t,int);
int lifted_crt_lock_retry(mx_crt_state *,mx_cfg_memory *,int (*)(void*,uint32_t),void*,int);
int lifted_crt_init_state(mx_crt_state *,mx_cfg_memory *,uint64_t *);
int lifted_crt_common_release(mx_crt_state *,mx_cfg_memory *,uint64_t *,int);
int crt_after_initterm_e(mx_crt_state*);
int crt_after_initterm(mx_crt_state*,mx_cfg_memory*,int);
/* The imported CRT routine now traverses the original pointer arrays.
 * Four body responses are still controlled dependency fixtures. The genuine
 * six-instruction exception callback executes natively in the same guest
 * address space, with a distinct Win64 callback stack.
 */
typedef struct {
    mx_cfg_memory *guest;
    uint32_t first_status,e_callbacks,plain_callbacks,filter_calls,second_calls;
    uint32_t argument_calls,argument_imports,argument_local_calls;
    uint32_t app_calls,app_imports,app_direct_calls;
    uint32_t tail_calls,tail_imports;
} startup_callback_context;
static int filter_response(void *opaque,uint64_t filter,uint64_t *previous){
    startup_callback_context *ctx=(startup_callback_context*)opaque;
    if(!ctx||!previous||filter!=EXCEPTION_HANDLER)return 0;
    ctx->filter_calls++;
    *previous=UINT64_C(0xabc000e0);
    return 1;
}
int native_second_initializer(
    mx_crt_cluster_state *,mx_cfg_memory *,
    mx_crt_cluster_import_fn,mx_crt_cluster_direct_fn,void *);
int native_argument_callback(
    mx_crt_cluster_state *,mx_cfg_memory *,
    mx_crt_cluster_import_fn,mx_crt_cluster_direct_fn,void *);
int native_app_initializer(
    mx_crt_cluster_state *,mx_cfg_memory *,
    mx_crt_cluster_import_fn,mx_crt_cluster_direct_fn,void *);
int lifted_crt_import_cluster(
    mx_crt_cluster_state *,mx_cfg_memory *,
    mx_crt_cluster_import_fn,void *);
static int tail_import(void*opaque,mx_crt_service_id service,
                       mx_crt_cluster_state*s,mx_cfg_memory*m,
                       uint64_t sp){
    startup_callback_context *ctx=(startup_callback_context*)opaque;
    if(!ctx||!s||!m||sp!=CALLBACK_SP-0x60U||
       s->rsp!=CALLBACK_SP-0x58U)return 0;
    if(ctx->tail_imports==0U && service==MX_CRT_SERVICE_DECODE_POINTER){
        s->rax=UINT64_MAX;
    }else if(ctx->tail_imports==1U && service==MX_CRT_SERVICE_ONEXIT){
        s->rax=0U;
    }else return 0;
    ctx->tail_imports++;
    return 1;
}
static int app_import(void*opaque,mx_crt_service_id svc,
                      mx_crt_cluster_state*s,mx_cfg_memory*m,
                      uint64_t sp){
    startup_callback_context *ctx=(startup_callback_context*)opaque;
    if(!ctx||!s||!m||sp!=CALLBACK_SP-0x30U||
       s->rsp!=CALLBACK_SP-0x28U)return 0;
    if(svc==MX_CRT_SERVICE_SET_APP_TYPE){
        ctx->app_imports++;return 1;
    }
    if(svc==MX_CRT_SERVICE_ENCODE_POINTER){
        s->rax=s->rcx^UINT64_C(0x5a5aa5a5d00dbeef);
        ctx->app_imports++;return 1;
    }
    if(svc==MX_CRT_SERVICE_SET_USERMATHERR){
        s->rax=0U;ctx->app_imports++;return 1;
    }
    if(svc==MX_CRT_SERVICE_CONFIGTHREADLOCALE){
        s->rax=1U;ctx->app_imports++;return 1;
    }
    return 0;
}
static int app_direct(void*opaque,uint64_t target,
                      mx_crt_cluster_state*s,mx_cfg_memory*m){
    startup_callback_context *ctx=(startup_callback_context*)opaque;
    if(!ctx||!s||!m||s->local_depth!=1U||
       s->rsp!=CALLBACK_SP-0x30U)return MX_CRT_CLUSTER_IMPORT_UNSUPPORTED;
    uint64_t which=target==APP_LOCAL_A?1U:target==APP_LOCAL_B?2U:0U;
    if(!which)return MX_CRT_CLUSTER_IMPORT_UNSUPPORTED;
    s->rax=0x1000U+which;
    uint64_t ret=mx_crt_cluster_read(s,m,s->rsp,8U);
    if(s->fault)return MX_CRT_CLUSTER_MEMORY_FAULT;
    s->rsp+=8U;s->rip=ret;
    ctx->app_direct_calls++;
    return MX_CRT_CLUSTER_RETURNED;
}

static int argument_import(void*opaque,mx_crt_service_id svc,
                            mx_crt_cluster_state*s,mx_cfg_memory*m,
                            uint64_t stack_pointer){
    startup_callback_context*ctx=(startup_callback_context*)opaque;
    if(!ctx||!s||!m||svc!=MX_CRT_SERVICE_GETMAINARGS ||
       stack_pointer!=CALLBACK_SP-0x40U ||
       s->rsp!=CALLBACK_SP-0x38U)return 0;
    mx_crt_process process={0};
    if(mx_crt_process_bind_args(&process,m,3U,
          ARG_DATA+0x1000U,ARG_DATA+0x1100U)!=MX_CRT_PROCESS_HANDLED)
        return 0;
    uint64_t output=s->rax;
    uint64_t argc_addr=s->rcx,argv_addr=s->rdx,env_addr=s->r8;
    if(mx_crt_process_getmainargs(&process,argc_addr,argv_addr,env_addr,
          0U,&output)!=MX_CRT_PROCESS_HANDLED)return 0;
    uint32_t argc=0U;
    uint64_t argv=0U,env=0U;
    if(!mx_cfg_transfer(m,argc_addr,&argc,4U,0) ||
       !mx_cfg_transfer(m,argv_addr,&argv,8U,0) ||
       !mx_cfg_transfer(m,env_addr,&env,8U,0) ||
       argc!=3U || argv!=ARG_DATA+0x1000U ||
       env!=ARG_DATA+0x1100U || output!=0U)return 0;
    s->rax=output;
    ctx->argument_imports++;
    return 1;
}
static int argument_direct(void*opaque,uint64_t target,
                            mx_crt_cluster_state*s,mx_cfg_memory*m){
    startup_callback_context*ctx=(startup_callback_context*)opaque;
    if(!ctx||!s||!m||s->local_depth!=1U ||
       s->rsp!=CALLBACK_SP-0x40U ||
       target!=ARG_WRAPPER)return MX_CRT_CLUSTER_IMPORT_UNSUPPORTED;
    /* Only the direct callee's verified success result is injected.
     * The original 19-instruction caller executes as native code. */
    s->rax=0U;
    uint64_t ret=mx_crt_cluster_read(s,m,s->rsp,8U);
    if(s->fault)return MX_CRT_CLUSTER_MEMORY_FAULT;
    s->rsp+=8U;s->rip=ret;
    ctx->argument_local_calls++;
    return MX_CRT_CLUSTER_RETURNED;
}
static int second_unused_import(void*opaque,mx_crt_service_id svc,
                                mx_crt_cluster_state*s,mx_cfg_memory*m,
                                uint64_t stack_pointer){
    (void)opaque;(void)svc;(void)s;(void)m;(void)stack_pointer;
    return 0;
}
static int second_direct(void*opaque,uint64_t target,
                         mx_crt_cluster_state*s,mx_cfg_memory*m){
    startup_callback_context *ctx=(startup_callback_context*)opaque;
    if(!ctx||!s||!m||s->local_depth!=1U)
        return MX_CRT_CLUSTER_IMPORT_UNSUPPORTED;
    if(target==SECOND_LOCAL && s->rsp==CALLBACK_SP-0x30U &&
       s->rcx==SECOND_FIRST_ARG){
        s->rax=UINT64_C(0x1170);
    }else if(target==SECOND_WRAPPER && s->rsp==CALLBACK_SP &&
             s->rcx==SECOND_TAIL_ARG){
        /* Remaining original wrapper body is not joined here. */
        s->rax=UINT64_C(0xffffffff);
    }else return MX_CRT_CLUSTER_IMPORT_UNSUPPORTED;
    uint64_t next=mx_crt_cluster_read(s,m,s->rsp,8U);
    if(s->fault)return MX_CRT_CLUSTER_MEMORY_FAULT;
    s->rsp+=8U;s->rip=next;
    return MX_CRT_CLUSTER_RETURNED;
}
static int startup_callback(void *opaque,uint64_t pc,
                            uint32_t slot,uint8_t checked,uint32_t *result){
    startup_callback_context *ctx=(startup_callback_context*)opaque;
    if(!ctx||!result)return 0;
    if(checked){
        if(slot==1U && pc==APP_CALLBACK){
            /* Original x64 error fixtures deliberately inject nonzero
             * status. Valid PE startup executes the original 52-instruction
             * native callback on the shared guest-memory image. */
            if(ctx->first_status!=0U){
                ctx->e_callbacks++;
                *result=ctx->first_status;
                return 1;
            }
            const uint64_t ret=UINT64_C(0x140000123);
            if(!mx_cfg_transfer(ctx->guest,CALLBACK_SP,(void*)&ret,8U,1))
                return -1;
            mx_crt_cluster_state child={0};
            child.rip=APP_CALLBACK;child.rsp=CALLBACK_SP;
            child.rcx=UINT64_C(0x101000);
            if(native_app_initializer(&child,ctx->guest,
                 app_import,app_direct,ctx)!=MX_CRT_CLUSTER_RETURNED ||
               child.rip!=ret || child.rsp!=CALLBACK_SP+8U ||
               child.rax!=APP_EXPECTED_RAX ||
               child.visited!=APP_EXPECTED_VISITED ||
               ctx->app_imports+ctx->app_direct_calls!=APP_EXPECTED_CALLS)
                return -1;
            ctx->app_calls++;
            ctx->e_callbacks++;
            *result=(uint32_t)child.rax;
            return 1;
        }
        if(slot==2U && pc==EXCEPTION_CALLBACK){
            const uint64_t ret=UINT64_C(0x140000123);
            if(!mx_cfg_transfer(ctx->guest,CALLBACK_SP,(void*)&ret,8U,1))
                return -1;
            mx_crt_state child={0};
            child.rsp=CALLBACK_SP;child.rip=EXCEPTION_CALLBACK;
            if(mx_crt_exception_callback6(&child,ctx->guest,
                  EXCEPTION_CALLBACK,EXCEPTION_HANDLER,filter_response,ctx)
               !=MX_CRT_RETURNED || child.rax || child.rip!=ret)
                return -1;
            ctx->e_callbacks++;
            *result=0U;
            return 1;
        }
        return 0;
    }
    if(slot==1U && pc==ARG_CALLBACK){
        const uint64_t ret=UINT64_C(0x140000123);
        if(!mx_cfg_transfer(ctx->guest,CALLBACK_SP,(void*)&ret,8U,1))
            return -1;
        mx_crt_cluster_state child={0};
        child.rip=ARG_CALLBACK;child.rsp=CALLBACK_SP;
        child.rcx=UINT64_C(0x140010000);
        if(native_argument_callback(&child,ctx->guest,argument_import,
              argument_direct,ctx)!=MX_CRT_CLUSTER_RETURNED ||
           child.rip!=ret || child.rsp!=CALLBACK_SP+8U ||
           child.rax!=0U ||
           child.local_calls!=1U || child.imports!=1U ||
           ctx->argument_imports!=1U ||ctx->argument_local_calls!=1U)
            return -1;
        ctx->argument_calls++;
        ctx->plain_callbacks++;
        *result=0U;
        return 1;
    }
    if(slot==2U && pc==SECOND_CALLBACK){
        const uint64_t ret=UINT64_C(0x140000123);
        if(!mx_cfg_transfer(ctx->guest,CALLBACK_SP,(void*)&ret,8U,1))
            return -1;
        mx_crt_cluster_state child={0};
        child.rip=SECOND_CALLBACK;child.rsp=CALLBACK_SP;
        if(native_second_initializer(&child,ctx->guest,
             second_unused_import,second_direct,ctx)!=MX_CRT_CLUSTER_RETURNED ||
           child.rip!=ret || child.rsp!=CALLBACK_SP+8U ||
           child.local_calls!=2U)return -1;
        ctx->second_calls++;
        ctx->plain_callbacks++;
        *result=0U;
        return 1;
    }
    if(slot==3U && pc==TAIL_CALLBACK){
        const uint64_t ret=UINT64_C(0x140000123);
        if(!mx_cfg_transfer(ctx->guest,CALLBACK_SP,(void*)&ret,8U,1))
            return -1;
        /* The earlier app initializer legitimately modified these globals.
         * The original x64 short-path tail does not update either slot.
         * Validate that invariant against the live post-app guest values,
         * never against the pre-app reference seed. */
        uint64_t before_g0=0U,before_g1=0U;
        if(!mx_cfg_transfer(ctx->guest,TAIL_G0,&before_g0,8U,0) ||
           !mx_cfg_transfer(ctx->guest,TAIL_G1,&before_g1,8U,0))
            return -1;
        mx_crt_cluster_state child={0};
        child.rip=TAIL_CALLBACK;child.rsp=CALLBACK_SP;
        child.rax=UINT64_C(0xbbbb0000);
        child.rbx=UINT64_C(0xaaaa0000);
        child.rcx=UINT64_C(0x140140000);
        int tail_status=mx_crt_tail_callback2_to_wrapper(&child,ctx->guest,
             TAIL_CALLBACK,TAIL_ARG,TAIL_WRAPPER,TAIL_CHILD,
             lifted_crt_import_cluster,tail_import,ctx);
        if(tail_status!=MX_CRT_CLUSTER_RETURNED ||
           child.rip!=ret || child.rsp!=CALLBACK_SP+8U ||
           child.rax!=TAIL_EXPECT_RAX || ctx->tail_imports!=2U){
#ifdef HOST
            fprintf(stderr,"tail callback mismatch: code=%d fault=%u rip=%llx expected=%llx rsp=%llx expected_rsp=%llx rax=%llx expected_rax=%llx imports=%u visited=%llx\\n",
                tail_status,(unsigned)child.fault,
                (unsigned long long)child.rip,(unsigned long long)ret,
                (unsigned long long)child.rsp,
                (unsigned long long)(CALLBACK_SP+8U),
                (unsigned long long)child.rax,
                (unsigned long long)TAIL_EXPECT_RAX,ctx->tail_imports,
                (unsigned long long)child.visited);
#endif
            return -1;
        }
        uint64_t g0=0U,g1=0U;
        if(!mx_cfg_transfer(ctx->guest,TAIL_G0,&g0,8U,0) ||
           !mx_cfg_transfer(ctx->guest,TAIL_G1,&g1,8U,0) ||
           g0!=before_g0||g1!=before_g1){
#ifdef HOST
            fprintf(stderr,"tail global mismatch: g0=%llx expected=%llx g1=%llx expected=%llx\\n",
                (unsigned long long)g0,(unsigned long long)before_g0,
                (unsigned long long)g1,(unsigned long long)before_g1);
#endif
            return -1;
        }
        ctx->tail_calls++;
        ctx->plain_callbacks++;
        *result=(uint32_t)child.rax;
        return 1;
    }
    return 0;
}
static int fake_sleep(void *p,uint32_t millis) {
    sleep_ctx *ctx=(sleep_ctx*)p;
    if(millis!=1000U)return 0;
    ctx->slept++;
    if(ctx->release) {
        uint64_t zero=0;
        return mx_cfg_transfer(ctx->memory,GLOBAL,&zero,8,1);
    }
    return 1;
}
int smoke(void) {
    /* Sparse original PE guest page image keeps startup, CRT callbacks
     * and PE header in one nonoverlapping address space. */
    mx_cfg_region areas[PE_PAGE_COUNT+5U];
    areas[0]=(mx_cfg_region){WIN,stack_bytes,512};
    areas[1]=(mx_cfg_region){GS,teb,256};
    areas[2]=(mx_cfg_region){CALLBACK_STACK_BEGIN,callback_stack,256};
    areas[3]=(mx_cfg_region){APP_EXTERNAL,app_external_data,4096};
    for(uint32_t k=0;k<PE_PAGE_COUNT;k++)
        areas[k+4U]=(mx_cfg_region){UINT64_C(0x140000000)+pe_page_rvas[k],
                                   pe_pages[k],PE_PAGE_SIZE};
    areas[PE_PAGE_COUNT+4U]=(mx_cfg_region){
        EXTRA_MAIN_STACK_BEGIN,extra_main_stack,sizeof(extra_main_stack)};
    mx_cfg_memory memory={areas,PE_PAGE_COUNT+5U};
    if(memory.count>20U)return 1;
    if(!pe_seed64((uint32_t)(MAIN_COOKIE-UINT64_C(0x140000000)),
                  MAIN_COOKIE_INIT))return 2;
    for(uint32_t k=0;k<4096U;k++)
        if(!pe_seed_byte(k,original_pe_header[k]))return 2;
    for(uint32_t k=0;k<3U;k++)
        if(!mx_cfg_transfer(&memory,E_BEGIN+8U*k,
                 (void*)&e_init_words[k],8U,1))return 3;
    for(uint32_t k=0;k<4U;k++)
        if(!mx_cfg_transfer(&memory,I_BEGIN+8U*k,
                 (void*)&i_init_words[k],8U,1))return 4;
    for(unsigned i=0;i<sizeof(cases)/sizeof(cases[0]);i++) {
        const fixture *f=&cases[i];
        for(unsigned j=0;j<512;j++)stack_bytes[j]=0;
        for(unsigned j=0;j<256;j++)teb[j]=0;
        if(f->state==0U && !f->init_status){
            for(unsigned j=0;j<ARG_DATA_SIZE;j++)
                if(!pe_seed_byte((uint32_t)(ARG_DATA-UINT64_C(0x140000000))+j,
                      (uint8_t)((j*9U+i*13U+3U)&255U)))return 5;
            for(unsigned k=0;k<sizeof(app_seeds)/sizeof(app_seeds[0]);k++)
                for(unsigned j=0;j<8U;j++)
                    if(!pe_seed_byte(app_seeds[k].address+j,
                           app_seeds[k].bytes[j]))return 6;
            for(unsigned j=0;j<4U;j++)
                if(!pe_seed64(app_iat_rvas[j],
                        UINT64_C(0x600000000)+16U*j))return 7;
            if(!pe_seed64((uint32_t)(APP_DATA_SLOT-UINT64_C(0x140000000)),APP_EXTERNAL)||
               !pe_seed64((uint32_t)(APP_MODE_SLOT-UINT64_C(0x140000000)),APP_EXTERNAL+8U))
                return 8;
            for(unsigned j=0;j<16U;j++)app_external_data[j]=0;
            if(!pe_seed64((uint32_t)(TAIL_G0-UINT64_C(0x140000000)),TAIL_INIT_G0) ||
               !pe_seed64((uint32_t)(TAIL_G1-UINT64_C(0x140000000)),TAIL_INIT_G1))
                return 9;
            for(unsigned j=0;j<6U;j++)
                if(!pe_seed64(child_iat_rvas[j],
                      UINT64_C(0x600000100)+16U*j))return 9;
        }
        uint64_t ptr=GS;
        uint64_t initial=f->global_initial;
        uint32_t state=(uint32_t)f->state,alt=(uint32_t)f->alt;
        if(!mx_cfg_transfer(&memory,GS+UINT64_C(0x30),&ptr,8,1) ||
           !mx_cfg_transfer(&memory,GS+8U,(void*)&f->thread,8,1) ||
           !mx_cfg_transfer(&memory,GLOBAL,&initial,8,1) ||
           !mx_cfg_transfer(&memory,STATE,&state,4,1) ||
           !mx_cfg_transfer(&memory,ALT,&alt,4,1))return 10+i;
        mx_crt_state s={0};
        s.rip=ENTRY;s.rsp=SP;s.rax=f->rax;s.rbx=f->rbx;
        s.rcx=f->rcx;s.rdi=f->rdi;s.rsi=f->rsi;
        uint64_t rdx=f->rdx;
        uint32_t init_e_calls=0,init_void_calls=0;
        for(unsigned j=0;j<256;j++)callback_stack[j]=0;
        startup_callback_context routed={0};
        routed.guest=&memory;
        routed.first_status=(uint32_t)f->init_status;
        mx_crt_startup_bridge bridge={0};
        bridge.memory=&memory;bridge.callback=startup_callback;
        bridge.callback_context=&routed;
        bridge.checked_begin=E_BEGIN;bridge.checked_end=E_BEGIN+24U;
        bridge.plain_begin=I_BEGIN;bridge.plain_end=I_BEGIN+32U;
        if(lifted_crt_entry_prefix(&s,&memory)!=MX_CRT_IMPORT_BOUNDARY)return 30+i;
        /* The original CALL pushes a return address before GetStartupInfoA. */
        uint64_t ret=AFTER_INFO;
        if(!mx_cfg_transfer(&memory,s.rsp-8U,&ret,8,1))return 50+i;
        for(unsigned j=0;j<13;j++) {
            uint64_t word=(j==0?104U:0U);
            if(!mx_cfg_transfer(&memory,s.rcx+8U*j,&word,8,1))return 70+i;
        }
        s.rip=AFTER_INFO;
        s.visited=0;s.instructions=0;
        if(lifted_crt_gs_lock_prefix(&s,&memory,GS,1)!=MX_CRT_BRANCH_BOUNDARY)
            return 90+i;
        if(s.rip!=BRANCH || s.instructions!=6U)return 110+i;
        s.visited=0;s.instructions=0;
        sleep_ctx host={&memory,0,f->mode==2};
        if(lifted_crt_lock_retry(&s,&memory,fake_sleep,&host,1)!=MX_CRT_BRANCH_BOUNDARY)
            return 130+i;
        if(s.fault || s.pending_import || s.imports!=host.slept)return 150+i;
        if(s.visited!=f->e_suffix_bits || s.instructions!=f->e_suffix_steps ||
           s.imports!=f->e_sleep_calls)return 210+i;
        if(s.rip!=UINT64_C(STATE_BEGIN_VA))return 160+i;
        /* State frontier is reached continuously, but resets only the
         * instruction-trace counters, not guest memory/registers/flags. */
        s.visited=0;s.instructions=0;
        int state_result=lifted_crt_init_state(&s,&memory,&rdx);
        int expected_result=(f->state==0U || f->state==1U)?5:MX_CRT_BRANCH_BOUNDARY;
        if(state_result!=expected_result)return 165+i;
        if(s.visited!=f->e_state_bits || s.instructions!=f->e_state_steps)
            return 220+i;
        if(f->state==0U){
            if(s.rip!=INITIALIZER_CALL)return 161+i;
            if(mx_crt_invoke_init_thunk(&s,&memory,MX_CRT_INITTERM_E,
                  INITIALIZER_CALL,INITIALIZER_CALL+5U,rdx,
                  mx_crt_startup_bridge_call,&bridge)!=MX_CRT_BRANCH_BOUNDARY)
                return 162+i;
            init_e_calls=bridge.checked_calls;
            s.visited=0;s.instructions=0;
            if(crt_after_initterm_e(&s)!=MX_CRT_BRANCH_BOUNDARY)return 163+i;
        }
        if(f->state==2U || (f->state==0U && !f->init_status)){
            if(s.rip!=RELEASE)return 164+i;
            s.visited=0;s.instructions=0;
            int released=lifted_crt_common_release(&s,&memory,&rdx,1);
            if(f->state==2U){
                if(released!=MX_CRT_BRANCH_BOUNDARY)return 165+i;
            }else{
                if(released!=5 || s.rip!=VOID_INITIALIZER_CALL)return 166+i;
                if(mx_crt_invoke_init_thunk(&s,&memory,MX_CRT_INITTERM,
                      VOID_INITIALIZER_CALL,VOID_INITIALIZER_CALL+5U,
                      rdx,mx_crt_startup_bridge_call,&bridge)!=MX_CRT_BRANCH_BOUNDARY)
                      return 167+i;
                init_void_calls=bridge.plain_calls;
                s.visited=0;s.instructions=0;
                if(crt_after_initterm(&s,&memory,1)!=MX_CRT_BRANCH_BOUNDARY)return 168+i;
            }
        }
        if(f->state==2U){
            if(s.visited!=f->e_release_bits || s.instructions!=f->e_release_steps)
                return 169+i;
        }
        if(init_e_calls!=f->e_crt_e_calls || init_void_calls!=f->e_crt_void_calls)
            return 170+i;
        const uint32_t e_count=f->state==0U?(f->init_status?1U:2U):0U;
        const uint32_t plain_count=(f->state==0U&&!f->init_status)?3U:0U;
        const uint32_t filter_count=(f->state==0U&&!f->init_status)?1U:0U;
        if(routed.e_callbacks!=e_count ||
           routed.plain_callbacks!=plain_count ||
           routed.filter_calls!=filter_count ||
           routed.second_calls!=(plain_count?1U:0U) ||
           routed.app_calls!=(plain_count?1U:0U) ||
           routed.tail_calls!=(plain_count?1U:0U) ||
           routed.tail_imports!=(plain_count?2U:0U) ||
           routed.argument_calls!=(plain_count?1U:0U) ||
           routed.argument_imports!=(plain_count?1U:0U) ||
           routed.argument_local_calls!=(plain_count?1U:0U) ||
           bridge.checked_callbacks!=e_count ||
           bridge.plain_callbacks!=plain_count)
            return 171+i;
        if(s.rax!=f->e_rax || s.rbx!=f->e_rbx || s.rcx!=f->e_rcx ||
           rdx!=f->e_rdx || s.rdi!=f->e_rdi || s.rsi!=f->e_rsi)return 170+i;
        if(s.rsp!=f->e_rsp || s.rip!=f->e_rip || s.zf!=f->e_zf)
            return 190+i;
        uint64_t global=0,last_return=0;
        if(!mx_cfg_transfer(&memory,GLOBAL,&global,8,0) ||
           !mx_cfg_transfer(&memory,SP-UINT64_C(0xb0),&last_return,8,0))
            return 230+i;
        if(global!=f->e_global || last_return!=f->e_sleep_return)return 250+i;
        uint32_t init_state=0,other_state=0;
        if(!mx_cfg_transfer(&memory,STATE,&init_state,4,0) ||
           !mx_cfg_transfer(&memory,ALT,&other_state,4,0) ||
           init_state!=f->e_state_after || other_state!=f->e_alt_after)return 255+i;
        for(unsigned j=0;j<512;j++)
            if(stack_bytes[j]!=f->expected_stack[j])return 270+i;
        /* Keep the existing 49-instruction x64 comparison intact.
         * Only the successful CRT case may proceed into this *additional*
         * independently reference-checked original command-line frontier. */
        if(f->state==0U && !f->init_status){
            uint64_t cmd=CMDLINE_TEXT, var=CMDLINE_VAR;
            const uint8_t nul=0U;
            uint32_t show_flag=i%2U;
            uint16_t show_value=(uint16_t)(11U+i);
            if(s.rip!=POST_RELEASE_PC ||
               !pe_seed64((uint32_t)(CMDLINE_IAT-UINT64_C(0x140000000)),var) ||
               !mx_cfg_transfer(&memory,var,&cmd,8U,1) ||
               !mx_cfg_transfer(&memory,cmd,(void*)&nul,1U,1) ||
               !mx_cfg_transfer(&memory,s.rsp+0x6cU,&show_flag,4U,1) ||
               !mx_cfg_transfer(&memory,s.rsp+0x70U,&show_value,2U,1))
               return 330+i;
            mx_crt_main_handoff hand={0};
            hand.continuation_pc=POST_RELEASE_PC;
            hand.main_call_pc=MAIN_CALL_PC;
            hand.executable_base=UINT64_C(0x140000000);
            hand.onexit_state_va=ONEXIT_GUARD;
            hand.command_line_iat_va=CMDLINE_IAT;
            if(mx_crt_advance_to_main_call(&s,&memory,&hand)!=MX_CRT_BRANCH_BOUNDARY ||
               !hand.reached_main_call || hand.commands_consumed!=1U)
               return 350+i;
            const uint64_t actual[11]={
                s.rax,s.rdi,s.rsi,s.rcx,hand.rdx,hand.r8,hand.r9,
                s.rsp,s.rip,s.zf,0U};
            uint64_t stackword=0U;
            if(!mx_cfg_transfer(&memory,s.rsp+0x28U,&stackword,8U,0))
                return 355+i;
            for(unsigned j=0;j<11U;j++){
                uint64_t value=j==10U?stackword:actual[j];
                if(value!=f->main_out[j]){
#ifdef HOST
                    fprintf(stderr,"main handoff mismatch case=%u field=%u actual=%llx expected=%llx\\n",
                        i,j,(unsigned long long)value,
                        (unsigned long long)f->main_out[j]);
#endif
                    return 360+i;
                }
            }
            /* Continue from the ORIGINAL CRT-proven CALL main ABI.
             * The same physical guest map retains all CRT globals,
             * initializer callback writes and the original Win64 stack. */
            mx_crt_to_main_layout layout={0};
            layout.crt_direct_call_pc=MAIN_CALL_PC;
            layout.crt_return_pc=MAIN_RETURN_PC;
            layout.prefix=(mx_main_prefix_layout){
                MAIN_ENTRY_PC,MAIN_FIRST_CALL,MAIN_COOKIE,
                MAIN_ARG0,MAIN_ARG1,MAIN_SHOW,0x288U,0x250U
            };
            mx_main_prefix_state main_state={0};
            const uint64_t pre_call_rsp=s.rsp;
            if(mx_crt_enter_main_prefix(&s,&hand,&memory,
                   &layout,&main_state)!=MX_MAIN_PREFIX_CALL_BOUNDARY)
                   return 370+i;
            uint64_t saved_cookie=0U,pushed_return=0U,
                     stored_arg0=0U,stored_arg1=0U,original_cookie=0U;
            uint32_t stored_show=0U;
            if(!mx_cfg_transfer(&memory,MAIN_COOKIE,&original_cookie,8U,0)||
               !mx_cfg_transfer(&memory,main_state.rsp+0x250U,
                                &saved_cookie,8U,0)||
               !mx_cfg_transfer(&memory,pre_call_rsp-8U,
                                &pushed_return,8U,0)||
               !mx_cfg_transfer(&memory,MAIN_ARG0,&stored_arg0,8U,0)||
               !mx_cfg_transfer(&memory,MAIN_ARG1,&stored_arg1,8U,0)||
               !mx_cfg_transfer(&memory,MAIN_SHOW,&stored_show,4U,0))
                  return 380+i;
            if(main_state.rip!=MAIN_FIRST_CALL||
               main_state.rsp!=pre_call_rsp-8U-0x288U||
               main_state.rax!=saved_cookie||
               main_state.rcx!=hand.r8||main_state.rdx!=hand.rdx||
               main_state.r8!=hand.r8||main_state.r9!=hand.r9||
               main_state.instructions!=8U||
               main_state.zf!=(saved_cookie==0U)||
               main_state.sf!=((saved_cookie>>63U)&1U)||
               main_state.cf!=0U||
               saved_cookie!=(original_cookie^main_state.rsp)||
               pushed_return!=MAIN_RETURN_PC||
               stored_arg0!=hand.executable_base||
               stored_arg1!=hand.rdx||
               stored_show!=(uint32_t)hand.r9||
               s.rsp!=pre_call_rsp||s.rip!=MAIN_CALL_PC)
               return 390+i;
            /* The CRT supplied CMDLINE_TEXT (NUL), rather than a newly
             * manufactured input buffer. Execute the original main CALL,
             * genuine empty-argument callee body and first modeled Win32
             * filename import in this same guest process. */
            mx_native_link_registry linker={0};
            linker.entries=verified_game_children;
            linker.count=2U;linker.max_depth=4U;
            if(mx_native_link_seal(&linker)!=MX_NATIVE_LINK_OK)
                return 410+i;
            mx_crt_cluster_state game={0};
            game.rip=main_state.rip;game.rsp=main_state.rsp;
            game.rax=main_state.rax;game.rcx=main_state.rcx;
            game.rdx=main_state.rdx;game.r8=main_state.r8;
            game.r9=main_state.r9;
            game.rbx=s.rbx;game.rdi=s.rdi;game.rsi=s.rsi;
            game.zf=(uint8_t)main_state.zf;
            game.cf=(uint8_t)main_state.cf;
            game.sf=(uint8_t)main_state.sf;
            game.instructions=main_state.instructions+1U;
            if(game.rcx!=CMDLINE_TEXT||
               mx_native_link_call(&linker,&game,&memory,
                   GAME_CALLEE,GAME_CALLEE_RET)!=MX_NATIVE_LINK_OK ||
               linker.calls_completed!=1U||linker.unresolved_calls||
               game.rip!=GAME_CALLEE_RET ||
               game.rsp!=main_state.rsp||game.rax!=0U||
               game.instructions!=18U)
                return 420+i;
            uint64_t callee_address=0U;
            uint32_t callee_flag=0U;
            if(!mx_cfg_transfer(&memory,GAME_CALLEE_G0,
                                &callee_address,8U,0)||
               !mx_cfg_transfer(&memory,GAME_CALLEE_G1,
                                &callee_flag,4U,0)||
               callee_address!=GAME_CALLEE_CONST||callee_flag!=1U)
                return 430+i;
            if(mx_game_main_filename_prepare(&game,
                    GAME_CALLEE_RET,GAME_FILENAME_CALL)!=
                    MX_GAME_FILENAME_OK||game.instructions!=21U)
                return 440+i;
            mx_game_module_context filename={
               modeled_filename,MODELED_FILENAME_LENGTH
            };
            if(mx_game_main_filename_import_call(&game,&memory,
                   &filename,GAME_FILENAME_CALL,GAME_FILENAME_AFTER)!=
                   MX_GAME_FILENAME_OK||
               game.rip!=GAME_FILENAME_AFTER||
               game.rsp!=main_state.rsp||
               game.rax!=MODELED_FILENAME_LENGTH||
               game.instructions!=23U||game.imports!=1U)
                return 450+i;
            for(uint32_t c=0;c<=MODELED_FILENAME_LENGTH;c++){
                uint8_t got=0U;
                if(!mx_cfg_transfer(&memory,main_state.rsp+0x140U+c,
                                    &got,1U,0)||
                   got!=modeled_filename[c])return 460+i;
            }
            /* Continue in the SAME guest stack to the genuine original
             * nonleaf helper at 0x15b790. The x64 CALL pushes the return PC,
             * the helper allocates 0x38, then dispatches the genuine PE
             * strcpy thunk to an explicitly modeled MSVCR90 service.
             * Source filename comes from KERNEL32's preceding buffer, not
             * an invented fresh argument or copied process. */
            if(mx_game_main_prepare_path_helper(&game,
                    GAME_FILENAME_AFTER,GAME_HELPER_CALL)!=
                    MX_GAME_PATH_HELPER_FRONTIER ||
               game.rcx!=main_state.rsp+0x140U||
               game.instructions!=24U)
                return 480+i;
            game.instructions++; /* Original main direct CALL helper. */
            if(mx_native_link_call_prologue_frontier(
                    &linker,&game,&memory,GAME_HELPER,
                    GAME_HELPER_RETURN,GAME_HELPER_TRANSFER,0x38U)!=
                    MX_NATIVE_LINK_FRONTIER_REACHED ||
               game.rip!=GAME_HELPER_TRANSFER ||
               game.rsp!=main_state.rsp-8U-0x38U ||
               game.rcx!=GAME_HELPER_DEST ||
               game.rdx!=main_state.rsp+0x140U ||
               linker.calls_attempted!=2U ||
               linker.calls_completed!=1U ||
               linker.unresolved_calls || linker.active_depth ||
               game.instructions!=29U)
                return 490+i;
            uint64_t helper_saved_argument=0U,helper_saved_return=0U;
            if(!mx_cfg_transfer(&memory,main_state.rsp,
                                &helper_saved_argument,8U,0)||
               !mx_cfg_transfer(&memory,main_state.rsp-8U,
                                &helper_saved_return,8U,0)||
               helper_saved_argument!=main_state.rsp+0x140U ||
               helper_saved_return!=GAME_HELPER_RETURN)
                return 500+i;
            if(mx_game_crt_strcpy_import_call(&game,&memory,
                    GAME_HELPER_TRANSFER,GAME_STRCPY_THUNK,
                    GAME_STRCPY_RETURN,260U)!=MX_GAME_STRCPY_OK ||
               game.rax!=GAME_STRCPY_DEST ||
               game.rip!=GAME_STRCPY_RETURN ||
               game.rsp!=main_state.rsp-8U-0x38U ||
               game.instructions!=32U || game.imports!=2U)
                return 510+i;
            uint64_t strcpy_saved_return=0U;
            if(!mx_cfg_transfer(&memory,game.rsp-8U,
                               &strcpy_saved_return,8U,0)||
                strcpy_saved_return!=GAME_STRCPY_RETURN)
                return 520+i;
            for(uint32_t b=0;b<=MODELED_FILENAME_LENGTH;b++){
                uint8_t output_byte=0U;
                if(!mx_cfg_transfer(&memory,GAME_STRCPY_DEST+b,
                                    &output_byte,1U,0)||
                   output_byte!=modeled_filename[b])
                    return 530+i;
            }
            /* Batch the preverified ORIGINAL filename-helper blocks in
             * this exact CRT-initialized guest frame. The original test path
             * "C:\MXBikes\mxbikes.exe" first encounters C, ':', then '\'.
             * Stop precisely at its original separator-found PC.
             * No arbitrary flow-through or invented guest pointer resets.
             */
            if(mx_game_path_after_strcpy(&game,&memory,
                  &original_post_strcpy)!=
                  MX_GAME_PATH_AFTER_STRCPY_FRONTIER ||
               game.rip!=GAME_POST_STRCPY_JUMP ||
               game.rax!=GAME_STRCPY_DEST||
               game.instructions!=36U)
                return 540+i;
            mx_game_path_after_strcpy_branch_result char_first={0};
            if(mx_game_path_after_strcpy_branch(&game,&memory,
                   &original_branch,&char_first)!=
                   MX_GAME_PATH_BRANCH_REACHED ||
               char_first.source_pointer!=GAME_STRCPY_DEST ||
               char_first.source_byte!=0x43U||char_first.branch_taken||
               game.rip!=GAME_NONZERO_START||
               game.instructions!=40U)
                return 550+i;
            mx_game_path_separator_result sep={0};
            if(mx_game_path_separator_branch(&game,&memory,
                   &original_separators,&sep)!=
                   MX_GAME_SEPARATOR_FRONTIER||
               sep.normalized_byte!=0x43U||sep.branch_taken||
               game.rip!=original_slash_loop.start_va||
               game.instructions!=44U)
                return 560+i;
            if(mx_game_slash_loop(&game,&memory,
                    &original_slash_loop)!=MX_GAME_SLASH_LOOP_REACHED||
               game.rip!=GAME_FIRST_LOOP||
               game.instructions!=49U)
                return 570+i;
            mx_game_filename_iteration_result next={0};
            if(mx_game_filename_loop_iteration(&game,&memory,
                    &original_iteration,&next)!=
                    MX_GAME_LOOP_ITERATION_REACHED||
               next.original_next_pointer!=GAME_STRCPY_DEST+1U||
               next.next_character!=0x3aU||next.zero_branch||
               game.rip!=GAME_NONZERO_START||game.instructions!=56U)
                return 580+i;
            if(mx_game_path_separator_branch(&game,&memory,
                   &original_separators,&sep)!=
                   MX_GAME_SEPARATOR_FRONTIER||
               sep.normalized_byte!=0x3aU||sep.branch_taken||
               game.rip!=original_slash_loop.start_va||
               game.instructions!=60U)
                return 590+i;
            if(mx_game_slash_loop(&game,&memory,
                    &original_slash_loop)!=MX_GAME_SLASH_LOOP_REACHED||
               game.rip!=GAME_FIRST_LOOP||
               game.instructions!=65U)
                return 600+i;
            if(mx_game_filename_loop_iteration(&game,&memory,
                    &original_iteration,&next)!=
                    MX_GAME_LOOP_ITERATION_REACHED||
               next.original_next_pointer!=GAME_STRCPY_DEST+2U||
               next.next_character!=0x5cU||next.zero_branch||
               game.rip!=GAME_NONZERO_START||game.instructions!=72U)
                return 610+i;
            if(mx_game_path_separator_branch(&game,&memory,
                   &original_separators,&sep)!=
                   MX_GAME_SEPARATOR_FRONTIER||
               sep.normalized_byte!=0x5cU||!sep.branch_taken||
               game.rip!=GAME_SEPARATOR_FOUND||
               game.rax!=0x5cU||game.zf!=1U||
               game.sf!=0U||game.cf!=0U||
               game.instructions!=76U||game.imports!=2U)
                return 620+i;
            uint64_t current_pointer=0U,zero_stack_local=1U;
            if(!mx_cfg_transfer(&memory,game.rsp+0x28U,
                                &current_pointer,8U,0)||
               !mx_cfg_transfer(&memory,game.rsp+0x20U,
                                &zero_stack_local,8U,0)||
               current_pointer!=GAME_STRCPY_DEST+2U||
               zero_stack_local!=0U)
                return 630+i;
            /* Entire original path uses actual previously copied bytes and
             * already verified x64 blocks. Stop at the original post-NUL
             * with-separator branch BEFORE any unseen helper instructions. */
            mx_game_filename_scan_result complete={0};
            if(mx_game_filename_scan_to_nul(&game,&memory,
                   &original_entire_filename_scan,&complete)!=
                   MX_GAME_FILENAME_SCAN_REACHED ||
               game.rip!=BASE+UINT64_C(0x15b809)||
               game.rsp!=main_state.rsp-8U-0x38U||
               game.rax!=0U||game.cf!=0U||game.sf!=0U||game.zf!=0U||
               game.instructions!=390U||game.imports!=2U||
               complete.loop_iterations!=20U||
               complete.separator_records!=2U||
               complete.ordinary_characters!=18U||
               complete.last_separator!=GAME_STRCPY_DEST+10U||
               complete.terminator!=GAME_STRCPY_DEST+MODELED_FILENAME_LENGTH||
               !complete.ended_with_separator)
                return 640+i;
            uint64_t final_ptr=0U,saved_last=0U;
            if(!mx_cfg_transfer(&memory,game.rsp+0x28U,
                                  &final_ptr,8U,0)||
               !mx_cfg_transfer(&memory,game.rsp+0x20U,
                                  &saved_last,8U,0)||
               final_ptr!=complete.terminator||
               saved_last!=complete.last_separator)
                return 650+i;
            /* Original 0x15B809 instructions replace only byte after the
             * final separator with NUL, LEA the actual filename global and
             * JMP to shared original exit; do not imply RET happened. */
            if(mx_game_filename_finish_separator(
                   &game,&memory,&original_directory_finish)!=
                   MX_GAME_FILENAME_FINISH_REACHED ||
               game.rip!=BASE+UINT64_C(0x15b862)||
               game.rax!=GAME_STRCPY_DEST||
               game.instructions!=394U||
               game.imports!=2U||
               game.rsp!=main_state.rsp-8U-0x38U)
                return 660+i;
            uint8_t separator_byte=0U, nul_after=0xffU, intact_after=0U;
            if(!mx_cfg_transfer(&memory,GAME_STRCPY_DEST+10U,
                                 &separator_byte,1U,0)||
               !mx_cfg_transfer(&memory,GAME_STRCPY_DEST+11U,
                                 &nul_after,1U,0)||
               !mx_cfg_transfer(&memory,GAME_STRCPY_DEST+12U,
                                 &intact_after,1U,0)||
               separator_byte!=0x5cU||nul_after!=0U||
               intact_after!=0x78U)
                return 670+i;
            /* Original helper's ADD RSP,0x38; RET consumes the existing
             * saved guest Win64 CALL return, never a synthetic host return.
             * It restores the actual main caller stack and continuation. */
            const mx_game_filename_helper_return_layout helper_return={
                BASE+UINT64_C(0x15b862),GAME_HELPER_RETURN,
                main_state.rsp,0x38U
            };
            if(mx_game_filename_helper_return(
                    &game,&memory,&helper_return)!=
                    MX_GAME_HELPER_EPILOGUE_RETURNED||
               game.rip!=GAME_HELPER_RETURN||
               game.rsp!=main_state.rsp||
               game.rax!=GAME_STRCPY_DEST||
               game.zf!=0U||game.sf!=0U||game.cf!=0U||
               game.instructions!=396U||
               game.imports!=2U||
               linker.calls_attempted!=2U||
               linker.calls_completed!=1U||
               linker.unresolved_calls)
                return 680+i;
            /* Original MOV RCX,RAX and KERNEL32!SetCurrentDirectoryA CALL
             * use the guest directory buffer already trimmed by the real
             * native filename helper. Explicit virtual policy callback,
             * never the host process cwd. */
            uint32_t cwd_policy=1U;
            mx_game_cwd_context cwd={0};
            cwd.validate=authorized_virtual_game_directory;
            cwd.opaque=&cwd_policy;
            if(mx_game_setcwd_prepare(
                   &game,GAME_CWD_PREPARE,GAME_CWD_CALL)!=MX_GAME_CWD_OK ||
               game.rcx!=GAME_STRCPY_DEST||game.instructions!=397U ||
               mx_game_setcwd_import_call(&game,&memory,&cwd,
                   GAME_CWD_CALL,GAME_CWD_AFTER,260U)!=MX_GAME_CWD_OK ||
               game.rip!=GAME_CWD_AFTER||game.rsp!=main_state.rsp||
               game.rax!=1U||game.instructions!=399U||
               game.imports!=3U||cwd.calls!=1U||cwd.length!=11U||
               cwd.virtual_path[10]!=0x5cU||cwd.virtual_path[11]!=0U)
                return 690+i;
            uint32_t expected_next_argument=0U;
            if(!mx_cfg_transfer(&memory,GAME_NEXT_ARG_GLOBAL,
                                  &expected_next_argument,4U,0))
                return 700+i;
            if(mx_game_main_after_cwd_prepare(&game,&memory,
                   GAME_CWD_AFTER,GAME_NEXT_ARG_GLOBAL,
                   GAME_NEXT_RDX_ADDRESS,GAME_NEXT_CALL)!=MX_GAME_CWD_OK ||
               game.rip!=GAME_NEXT_CALL||
               game.rcx!=(uint64_t)expected_next_argument||
               game.rdx!=GAME_NEXT_RDX_ADDRESS||
               game.instructions!=401U||game.imports!=3U||
               game.rsp!=main_state.rsp||game.rax!=1U||
               game.zf!=0U||game.cf!=0U||game.sf!=0U)
                return 710+i;
            /* Stop BEFORE original CALL 0x133e80. Untranslated callee's
             * behavior or return status is never inferred from this gate. */
            /* The game initialized globals, but the CRT caller state and
             * its guest memory stay intact: no fresh guest/process created. */
            if(s.rip!=MAIN_CALL_PC||s.rsp!=pre_call_rsp||
               game.rcx!=(uint64_t)expected_next_argument||
               game.rdx!=GAME_NEXT_RDX_ADDRESS||game.r8!=0x104U)
                return 470+i;
        }
    }
    return 0;
}
#ifdef HOST
int main(void){return smoke();}
#endif
"""

def verify_main_handoff_instructions(pe, imported):
    """Pin the actual post-initializer route and its DLL data import."""
    md=Cs(CS_ARCH_X86,CS_MODE_64)
    md.detail=True
    code=pe.read_rva(RELEASE_END,MAIN_CALL-RELEASE_END)
    ins=list(md.disasm(code,RELEASE_END))
    if not ins or sum(i.size for i in ins)!=len(code):
        raise RuntimeError("Original post-CRT x64 continuation no longer decodes")
    by_pc={i.address:i for i in ins}
    guard=by_pc.get(RELEASE_END)
    je=by_pc.get(0x2ab110)
    cmd=by_pc.get(0x2ab131)
    first=by_pc.get(0x2ab138)
    if (not guard or guard.mnemonic!="cmp" or
        guard.operands[0].type!=X86_OP_MEM or
        guard.operands[0].size!=8 or
        guard.operands[1].type!=X86_OP_IMM or
        guard.operands[1].imm!=0 or
        not je or je.mnemonic!="je" or je.operands[0].imm!=0x2ab131 or
        not cmd or cmd.mnemonic!="mov" or
        cmd.operands[1].type!=X86_OP_MEM or
        not first or first.mnemonic!="mov" or
        first.operands[1].type!=X86_OP_MEM):
        raise RuntimeError("Original post-CRT guard/command-line data route changed")
    exit_gate=guard.address+guard.size+guard.operands[0].mem.disp
    cmd_slot=cmd.address+cmd.size+cmd.operands[1].mem.disp
    ident=imported.get(cmd_slot)
    if (not ident or ident[0]!="msvcr90.dll" or
        "cmd" not in ident[1].lower()):
        raise RuntimeError("Original command-line data IAT symbol changed: "+repr(ident))
    call=list(md.disasm(pe.read_rva(MAIN_CALL,5),MAIN_CALL))
    if (len(call)!=1 or call[0].mnemonic!="call" or
        call[0].operands[0].type!=X86_OP_IMM or
        call[0].operands[0].imm!=MAIN_TARGET or
        exit_gate!=0xe4adc8):
        raise RuntimeError("Original main-call direct target/exit gate changed")
    return code,exit_gate,cmd_slot

def reference_main_handoff(source,exit_gate,cmd_slot,f,out,idx):
    """Run the actual original x64 suffix; STOP before the game main CALL."""
    if f["state"]!=0 or f["init_status"]!=0:
        return [0]*11
    from unicorn import UcError
    machine=Uc(UC_ARCH_X86,UC_MODE_64)
    for page in {(BASE+RELEASE_END)&~4095,
                 (BASE+exit_gate)&~4095,
                 (BASE+cmd_slot)&~4095}:
        machine.mem_map(page,4096)
    machine.mem_map(STACK,0x20000)
    machine.mem_map(EXTERNAL_GLOBAL,4096)
    machine.mem_write(BASE+RELEASE_END,source)
    machine.mem_write(BASE+exit_gate,b"\x00"*8)
    cmd_variable=EXTERNAL_GLOBAL+0x100
    cmd_string=EXTERNAL_GLOBAL+0x180
    machine.mem_write(BASE+cmd_slot,struct.pack("<Q",cmd_variable))
    machine.mem_write(cmd_variable,struct.pack("<Q",cmd_string))
    machine.mem_write(cmd_string,b"\x00")
    machine.mem_write(WIN,bytes(out["stack"]))
    flag=idx%2
    show_value=11+idx
    machine.mem_write(out["rsp"]+0x6c,struct.pack("<I",flag))
    machine.mem_write(out["rsp"]+0x70,struct.pack("<H",show_value))
    for key,reg in (("rax",UC_X86_REG_RAX),("rcx",UC_X86_REG_RCX),
                    ("rdi",UC_X86_REG_RDI),("rsi",UC_X86_REG_RSI),
                    ("rdx",UC_X86_REG_RDX)):
        machine.reg_write(reg,out[key])
    machine.reg_write(UC_X86_REG_RSP,out["rsp"])
    machine.reg_write(UC_X86_REG_RIP,BASE+RELEASE_END)
    invalid=[]
    def on_fault(uc,access,address,size,value,opaque):
        invalid.append({"pc":hex(uc.reg_read(UC_X86_REG_RIP)),
                        "address":hex(address),"size":size,
                        "rax":hex(uc.reg_read(UC_X86_REG_RAX)),
                        "rdi":hex(uc.reg_read(UC_X86_REG_RDI)),
                        "rsp":hex(uc.reg_read(UC_X86_REG_RSP))})
        return False
    machine.hook_add(UC_HOOK_MEM_INVALID,on_fault)
    try:
        machine.emu_start(BASE+RELEASE_END,BASE+MAIN_CALL,
                          timeout=2000000,count=96)
    except UcError as exc:
        raise RuntimeError("Original x64 post-CRT memory dependency: "+
                           repr(invalid[-1] if invalid else {})) from exc
    if machine.reg_read(UC_X86_REG_RIP)!=BASE+MAIN_CALL:
        raise RuntimeError("Original x64 main CALL boundary not reached")
    registers=[UC_X86_REG_RAX,UC_X86_REG_RDI,UC_X86_REG_RSI,
               UC_X86_REG_RCX,UC_X86_REG_RDX,UC_X86_REG_R8,UC_X86_REG_R9,
               UC_X86_REG_RSP,UC_X86_REG_RIP]
    results=[machine.reg_read(reg) for reg in registers]
    results+=[int(bool(machine.reg_read(UC_X86_REG_EFLAGS)&64)),
              struct.unpack("<Q",bytes(machine.mem_read(out["rsp"]+0x28,8)))[0]]
    if (results[3]!=BASE or results[4]!=0 or results[5]!=cmd_string or
        results[6]!=(show_value if flag else 10) or
        results[8]!=BASE+MAIN_CALL or results[10]!=cmd_string):
        raise RuntimeError("Original x64 post-CRT main-call ABI changed")
    return results

def encode(pairs,main_references):
    rows=[]
    for (f,out),handoff in zip(pairs,main_references):
        values=[f[k] for k in ("mode","thread","global_initial","rax","rbx","rcx","rsi","rdi","state","alt","rdx","init_status")]
        values+=[out[k] for k in FIELDS]
        mainpart="{"+",".join("UINT64_C("+str(v)+")" for v in handoff)+"}"
        bytespart="{"+",".join(str(x) for x in out["stack"])+"}"
        rows.append(" {"+",".join("UINT64_C("+str(v)+")" for v in values)+","+mainpart+","+bytespart+"},")
    return "\n".join(rows)

def checked(argv):
    result=subprocess.run(argv,capture_output=True,text=True)
    if result.returncode:
        raise RuntimeError("Original joined CRT host/AArch64 failed exit "+
                           str(result.returncode)+": "+(result.stderr or result.stdout)[-3200:])

def run(executable,output):
    pe=PE(executable)
    init_begin,init_values,e_begin,e_values=source_tables(inventory(executable))
    _,second_body,second_args=inspect_second_initializer(pe)
    argument_body,arg_meta,_,_=inspect_argument_initializer(pe)
    if arg_meta["decoded_instructions"]!=19 or ARG_DATA_SIZE!=8192:
        raise RuntimeError("Original argument initializer identity changed")
    app_body,app_meta,app_code,app_slots,app_targets,app_header,app_nt_offset=inspect_app_initializer(pe)
    if app_meta["decoded_instructions"]!=52:
        raise RuntimeError("Original 52-instruction app initializer changed")
    app_image=mapped_original_image(pe)
    main_layout,_,_=inspect_main_prefix(pe)
    module_iat=verify_module_api(pe)
    _, helper_stop, helper_dest=verify_game_path_helper(pe)
    strcpy_iat,strcpy_dest=verify_game_strcpy(pe)
    _,_,after_strcpy_dest=verify_post_strcpy(pe)
    verify_game_first_branch(pe)
    verify_game_separator(pe)
    verify_game_slash_loop(pe)
    decoder=Cs(CS_ARCH_X86,CS_MODE_64)
    decoder.detail=True
    known_imports={
        slot:{"dll":dll,"symbol":symbol}
        for slot,dll,symbol in import_slots(pe)
    }
    directory_prefix,possible_successors=inspect_next_main_block(
        pe,decoder,0x136769,known_imports)
    next_prefix,next_successors=inspect_next_main_block(
        pe,decoder,0x136772,known_imports)
    if (directory_prefix["straightline_original_instructions"]!=1 or
        directory_prefix["forms"][0]["mnemonic"]!="mov" or
        directory_prefix["forms"][0]["operands"]!="rcx, rax" or
        directory_prefix["first_control_rva"]!="0x13676c" or
        directory_prefix["first_control_mnemonic"]!="call" or
        directory_prefix.get("original_indirect_pointer_rva")!="0x3210d0" or
        directory_prefix.get("named_original_import",{}).get("dll","").lower()
            !="kernel32.dll" or
        directory_prefix.get("named_original_import",{}).get("symbol","").lower()
            !="setcurrentdirectorya" or
        possible_successors!=[0x136772] or
        next_prefix["straightline_original_instructions"]!=2 or
        next_prefix["forms"][0]["mnemonic"]!="mov" or
        next_prefix["forms"][0]["operands"]!="ecx, dword ptr [rip + 0xd14678]" or
        next_prefix["forms"][1]["mnemonic"]!="lea" or
        next_prefix["forms"][1]["operands"]!="rdx, [rip + 0xd146a1]" or
        next_prefix["first_control_rva"]!="0x13677f" or
        next_prefix["first_control_mnemonic"]!="call" or
        next_prefix.get("original_direct_destination_rva")!="0x133e80" or
        next_successors!=[0x136784]):
        raise RuntimeError("Original game-main directory-call and next callee identity changed")
    if after_strcpy_dest!=strcpy_dest:
        raise RuntimeError("Original post-strcpy destination layout changed")
    from mxbikes_joined_strcpy_native import CASES, STACK_MAIN_RSP
    oracle=original_filename_branch(
        pe,module_iat,strcpy_iat,strcpy_dest,CASES[0],MODELED_GAME_PATH[0],
        follow_successor=True,follow_slash_loop=True,
        follow_loop_iteration=True,follow_second_loopback=True,
        follow_third_backslash=True,follow_to_nul=True,
        follow_separator_finalize=True,
        follow_helper_return=True)
    if (oracle["rip"]!=BASE+0x136769 or
        oracle["rsp"]!=STACK_MAIN_RSP or
        oracle["helper_return_instructions"]!=2 or
        not oracle["helper_return_was_executed"] or
        oracle["rax"]!=strcpy_dest or
        not oracle["original_directory_NUL_after_last_sep"] or
        oracle["separator_finish_instructions"]!=4 or
        oracle["pointer"]!=strcpy_dest+len(MODELED_GAME_PATH) or
        oracle["last_separator"]!=strcpy_dest+10 or
        oracle["scan_instructions"]!=314 or
        (oracle["cf"],oracle["zf"],oracle["sf"])!=(0,0,0)):
        raise RuntimeError("Authentic original x64 whole-filename oracle diverged")
    if (helper_stop.address!=0x15b7a5 or
        helper_dest!=strcpy_dest or
        not (BASE < strcpy_dest < BASE+0x1000000) or
        not (BASE < BASE+strcpy_iat < BASE+0x1000000)):
        raise RuntimeError("Original filename helper/strcpy target changed")
    if not isinstance(module_iat,int) or not (0 < module_iat < 0x1000000):
        raise RuntimeError("Original GetModuleFileNameA IAT identity changed")
    if MODELED_GAME_PATH!=b"C:\\MXBikes\\mxbikes.exe":
        raise RuntimeError("Expected deterministic modeled Windows module path")
    finish_ins=list(Cs(CS_ARCH_X86,CS_MODE_64).disasm(
        pe.read_rva(0x15b809,0x15b81b-0x15b809),0x15b809))
    expected_finish=[
        ("mov","rax, qword ptr [rsp + 0x20]"),
        ("mov","byte ptr [rax + 1], 0"),
        ("lea","rax, [rip + 0x23b087]"),
        ("jmp","0x15b862"),
    ]
    if (len(finish_ins)!=4 or
        [(x.mnemonic,x.op_str) for x in finish_ins]!=expected_finish or
        sum(x.size for x in finish_ins)!=(0x15b81b-0x15b809) or
        BASE+0x15b819+0x23b087!=strcpy_dest):
        raise RuntimeError("Original separator-present helper finalizer identity changed")
    epilogue=list(Cs(CS_ARCH_X86,CS_MODE_64).disasm(
        pe.read_rva(0x15b862,5),0x15b862))
    if (len(epilogue)!=2 or
        [(inst.mnemonic,inst.op_str) for inst in epilogue]!=[
            ("add","rsp, 0x38"),("ret","")] or
        sum(inst.size for inst in epilogue)!=5):
        raise RuntimeError("Original filename helper shared ADD RSP / RET identity changed")
    if (main_layout["main_va"]!=BASE+MAIN_TARGET or
        main_layout["callsite_va"]!=BASE+0x136741):
        raise RuntimeError("Original game-main entry layout changed")
    cookie_rva=main_layout["cookie_va"]-BASE
    main_cookie=struct.unpack("<Q",app_image[cookie_rva:cookie_rva+8])[0]
    app_expect=app_reference(pe,app_code,app_slots,app_targets,
                             app_header,app_nt_offset,0,app_image)
    app_pages=sorted({0,((STATE-BASE)&~4095),((GLOBAL-BASE)&~4095),
        ARG_DATA_RVA&~4095,(ARG_DATA_RVA+4096)&~4095,
        (e_begin-BASE)&~4095,(init_begin-BASE)&~4095,
        DATA_POINTER_SLOT&~4095,MODE_POINTER_SLOT&~4095} |
        {rva&~4095 for rva in app_targets} |
        {rva&~4095 for rva in app_slots.values()} |
        {(main_layout[k]-BASE)&~4095 for k in
         ("cookie_va","arg0_va","arg1_va","show_va",
          "callee_global0","callee_global1")} |
        {((strcpy_dest-BASE)&~4095),
         (((strcpy_dest-BASE)+259)&~4095)})
    if len(app_pages)>20 or any(rva+4096>0x1000000 for rva in app_pages):
        raise RuntimeError("Original app guest page map exceeds bounded memory")
    app_seed_rvas=sorted(set(app_targets)|{DATA_POINTER_SLOT,MODE_POINTER_SLOT})
    app_seed_rows=",\n".join("{"+str(rva)+",{"+
        ",".join(str(v) for v in app_image[rva:rva+8])+"}}"
        for rva in app_seed_rvas)
    original_child,wrapper_pcs=verify_tail_wrapper(pe)
    verify_tail_callback(pe)
    tail_case=next(tail_cases())
    tail_expected=tail_reference(pe,tail_case,original_child,wrapper_pcs,tail=True)
    if (tail_expected["trace"]!=["_decode_pointer","_onexit"] or
        tail_expected["g0"]!=tail_case["global0"] or
        tail_expected["g1"]!=tail_case["global1"]):
        raise RuntimeError("Original short-path CRT child import/guest-global invariant changed")
    imported={rva:(dll,name) for rva,dll,name in import_slots(pe)}
    thunk_bytes={rva:pe.read_rva(rva,6) for rva in TAIL_CHILD_THUNKS}
    child_body,child_meta=lift_crt_import_cluster(
        pe.read_rva(TAIL_CHILD_RVA,TAIL_CHILD_END-TAIL_CHILD_RVA),
        TAIL_CHILD_RVA,imported,thunk_bytes,BASE)
    if child_meta["decoded_instructions"]!=39:
        raise RuntimeError("Original 39-instruction tail child changed")
    if not all((rva&~4095) in app_pages for rva in TAIL_CHILD_IAT):
        raise RuntimeError("Original child IAT not mapped in unified guest PE")
    if hashlib.sha256(pe.b).hexdigest()!=SHA:
        raise RuntimeError("Private MX Bikes exe SHA mismatch")
    iat={rva:(dll.lower(),name) for rva,dll,name in import_slots(pe)}
    entry,info=lift_crt_entry_prefix(pe.read_rva(ENTRY,AFTER_INFO-ENTRY),ENTRY,iat,BASE)
    gs,gsmeta=lift_crt_gs_lock_prefix(pe.read_rva(AFTER_INFO,LOCK_BRANCH+2-AFTER_INFO),AFTER_INFO,BASE)
    state_c,state_meta=lift_crt_init_state(pe.read_rva(DONE,FINAL-DONE),DONE,BASE)
    release_c,release_meta=lift_crt_common_release(pe.read_rva(FINAL,RELEASE_END-FINAL),FINAL,BASE)
    post_e,e_meta=after_initterm_e(pe.read_rva(AFTER_E,POST_E_END-AFTER_E),AFTER_E,BASE)
    post_void,void_meta=after_initterm(pe.read_rva(AFTER_VOID,RELEASE_END-AFTER_VOID),AFTER_VOID,BASE)
    specs=decode_calls(pe)
    retry,retrymeta=lift_crt_retry(pe.read_rva(CAS_RETRY,LOCK_BRANCH-CAS_RETRY),
                               pe.read_rva(LOCK_BRANCH,DONE-LOCK_BRANCH),
                               CAS_RETRY,LOCK_BRANCH,iat,BASE)
    if (info["stop_before_import_rva"]!=hex(GET_INFO_CALL) or
        gsmeta["stop_before_branch_rva"]!=hex(LOCK_BRANCH) or
        retrymeta["stop_before_rva"]!=hex(DONE) or
        state_meta["join_rva"]!=hex(FINAL) or state_meta["decoded_original_instructions"]!=18 or
        release_meta["release_join_rva"]!=hex(RELEASE_END) or
        release_meta["decoded_original_instructions"]!=11 or
        release_meta["lock_owner_global_va"]!=hex(GLOBAL) or
        release_meta["state_global_va"]!=hex(STATE) or
        release_meta["direct_call_site_rva"]!=hex(RELEASE_CALL) or
        e_meta["return_success_rva"]!=hex(FINAL) or
        e_meta["return_error_rva"]!=hex(ERROR_STOP) or
        void_meta["state_global_va"]!=hex(STATE) or
        void_meta["lock_owner_va"]!=hex(GLOBAL) or
        void_meta["join_rva"]!=hex(RELEASE_END)):
        raise RuntimeError("Original source spans cannot be joined")
    get_call_slot=int(info["verified_import_symbol"]=="kernel32.dll::GetStartupInfoA")
    if get_call_slot!=1:
        raise RuntimeError("Unvalidated original GetStartupInfoA call")
    original=pe.read_rva(ENTRY,RELEASE_END-ENTRY)
    md=Cs(CS_ARCH_X86,CS_MODE_64);md.detail=True
    static=list(md.disasm(original,ENTRY))
    if len(static)!=49 or sum(x.size for x in static)!=len(original):
        raise RuntimeError("Unexpected original 49-instruction source interval")
    info_ins=next(x for x in static if x.address==GET_INFO_CALL)
    sleep_ins=next(x for x in static if x.mnemonic=="call" and x.address>AFTER_INFO)
    info_slot=info_ins.address+info_ins.size+info_ins.operands[0].mem.disp
    sleep_slot=sleep_ins.address+sleep_ins.size+sleep_ins.operands[0].mem.disp
    if (iat.get(info_slot)!=("kernel32.dll","GetStartupInfoA") or
        iat.get(sleep_slot)!=("kernel32.dll","Sleep")):
        raise RuntimeError("Wrong original Win64 imports")
    pairs=[(f,reference(original,info_slot,sleep_slot,static,f,specs)) for f in scenarios()]
    continuation,exit_guard,cmdline_iat=verify_main_handoff_instructions(pe,iat)
    handoff_refs=[reference_main_handoff(
        continuation,exit_guard,cmdline_iat,f,out,i)
        for i,(f,out) in enumerate(pairs)]
    if len(pairs)!=54 or len({f["state"] for f,_ in pairs})!=3:
        raise RuntimeError("Missing joined state cases")
    if (sum(1 for f,_ in pairs if f["state"]==2 and f["mode"]==1)!=6 or
        sum(1 for f,_ in pairs if f["state"]==2 and f["mode"]!=1)!=12 or
        sum(1 for f,_ in pairs if f["state"]==0 and f["init_status"]==0)!=9 or
        sum(1 for f,_ in pairs if f["state"]==0 and f["init_status"]!=0)!=9):
        raise RuntimeError("Missing recursive and exclusive-release joint paths")
    with tempfile.TemporaryDirectory(prefix="mxbikes-private-crt-joined-retry-") as td:
        root=Path(td)
        sources=[root/"private-entry.c",root/"private-gs.c",root/"private-retry.c",
                 root/"private-init-state.c",root/"private-release.c",
                 root/"private-post-status.c",root/"private-post-void.c"]
        for file,code in zip(sources,(entry,gs,retry,state_c,release_c,post_e,post_void)):
            file.write_text(code)
        second_source=root/"private-original-second-initializer.c"
        second_source.write_text(second_body)
        sources.append(second_source)
        argument_source=root/"private-original-argument-initializer.c"
        argument_source.write_text(argument_body)
        sources.append(argument_source)
        app_source=root/"private-original-app-initializer.c"
        app_source.write_text(app_body)
        sources.append(app_source)
        child_source=root/"private-original-tail-child.c"
        child_source.write_text(child_body)
        sources.append(child_source)
        smoke=root/"private-smoke.c"
        smoke.write_text(NATIVE.replace("ENTRY_VA",str(BASE+ENTRY))
                .replace("GS_VA",str(GS)).replace("SP_VA",str(SP))
                .replace("WIN_VA",str(WIN)).replace("GLOBAL_VA",str(GLOBAL))
                .replace("AFTER_INFO_VA",str(BASE+AFTER_INFO))
                .replace("BRANCH_VA",str(BASE+LOCK_BRANCH))
                .replace("RELEASE_VA",str(BASE+FINAL))
                .replace("INIT_CALL_VA",str(BASE+CALL_INIT))
                .replace("VOID_CALL_VA",str(BASE+RELEASE_CALL))
                .replace("STATE_VA",str(STATE))
                .replace("STATE_BEGIN_VA",str(BASE+DONE)).replace("ALT_VA",str(ALT))
                .replace("E_BEGIN_VA",str(e_begin))
                .replace("I_BEGIN_VA",str(init_begin))
                .replace("APP_CALLBACK_VA",str(e_values[1]))
                .replace("EXCEPTION_CALLBACK_VA",str(e_values[2]))
                .replace("EXCEPTION_HANDLER_VA",str(BASE+0x2ab6d0))
                .replace("ARG_CALLBACK_VA",str(init_values[1]))
                .replace("SECOND_CALLBACK_VA",str(init_values[2]))
                .replace("TAIL_CALLBACK_VA",str(init_values[3]))
                .replace("SECOND_LOCAL_VA",str(BASE+SECOND_LOCAL_RVA))
                .replace("SECOND_WRAPPER_VA",str(BASE+SECOND_WRAPPER_RVA))
                .replace("SECOND_FIRST_ARG_VA",str(second_args[0]))
                .replace("SECOND_TAIL_ARG_VA",str(second_args[1]))
                .replace("ARG_WRAPPER_VA",str(BASE+ARG_WRAPPER_RVA))
                .replace("ARG_DATA_VA",str(BASE+ARG_DATA_RVA))
                .replace("PE_PAGE_COUNT_V",str(len(app_pages)))
                .replace("PE_PAGE_RVAS",",".join(str(v) for v in app_pages))
                .replace("APP_HEADER_DATA",",".join(str(v) for v in app_header))
                .replace("APP_SEED_ROWS",app_seed_rows)
                .replace("APP_IAT_RVAS",",".join(str(app_slots[v]) for v in APP_API_NAMES))
                .replace("APP_LOCAL_A_VA",str(BASE+APP_LOCAL_A_RVA))
                .replace("APP_LOCAL_B_VA",str(BASE+APP_LOCAL_B_RVA))
                .replace("APP_EXTERNAL_VA",str(EXTERNAL_GLOBAL))
                .replace("APP_DATA_SLOT_VA",str(BASE+DATA_POINTER_SLOT))
                .replace("APP_MODE_SLOT_VA",str(BASE+MODE_POINTER_SLOT))
                .replace("APP_EXPECTED_RAX_V",str(app_expect["expected"][0]))
                .replace("APP_EXPECTED_VISITED_V",str(app_expect["visited"]))
                .replace("APP_EXPECTED_CALLS_V",str(len(app_expect["trace"])))
                .replace("TAIL_ARG_VA",str(BASE+TAIL_ARGUMENT))
                .replace("TAIL_WRAPPER_VA",str(BASE+SECOND_WRAPPER_RVA))
                .replace("TAIL_CHILD_VA",str(BASE+TAIL_CHILD_RVA))
                .replace("TAIL_G0_VA",str(BASE+TAIL_CHILD_GLOBALS[0]))
                .replace("TAIL_G1_VA",str(BASE+TAIL_CHILD_GLOBALS[1]))
                .replace("TAIL_INIT_G0_V",str(tail_case["global0"]))
                .replace("TAIL_INIT_G1_V",str(tail_case["global1"]))
                .replace("TAIL_EXPECT_RAX_V",str(tail_expected["rax"]))
                .replace("POST_RELEASE_PC_V",str(BASE+RELEASE_END))
                .replace("MAIN_CALL_PC_V",str(BASE+MAIN_CALL))
                .replace("MAIN_ENTRY_PC_V",str(main_layout["main_va"]))
                .replace("MAIN_FIRST_CALL_V",str(main_layout["callsite_va"]))
                .replace("MAIN_COOKIE_V",str(main_layout["cookie_va"]))
                .replace("MAIN_ARG0_V",str(main_layout["arg0_va"]))
                .replace("MAIN_ARG1_V",str(main_layout["arg1_va"]))
                .replace("MAIN_SHOW_V",str(main_layout["show_va"]))
                .replace("MAIN_COOKIE_INIT_V",str(main_cookie))
                .replace("GAME_CALLEE_V",str(main_layout["callee_va"]))
                .replace("GAME_CALLEE_CONST_V",str(main_layout["callee_constant"]))
                .replace("GAME_CALLEE_G0_V",str(main_layout["callee_global0"]))
                .replace("GAME_CALLEE_G1_V",str(main_layout["callee_global1"]))
                .replace("GAME_CALLEE_TAKEN_V",str(main_layout["taken_va"]))
                .replace("GAME_CALLEE_FALL_V",str(main_layout["fallthrough_va"]))
                .replace("GAME_CALLEE_RET_V",str(main_layout["return_va"]))
                .replace("GAME_FILENAME_CALL_V",str(BASE+0x136756))
                .replace("GAME_FILENAME_AFTER_V",str(BASE+0x13675c))
                .replace("MODELED_FILENAME_LENGTH_V",str(len(MODELED_GAME_PATH)))
                .replace("GAME_HELPER_V",str(BASE+0x15b790))
                .replace("GAME_HELPER_CALL_V",str(BASE+0x136764))
                .replace("GAME_HELPER_RETURN_V",str(BASE+0x136769))
                .replace("GAME_HELPER_TRANSFER_V",str(BASE+0x15b7a5))
                .replace("GAME_HELPER_DEST_V",str(helper_dest))
                .replace("GAME_STRCPY_THUNK_V",str(BASE+0x2ab41a))
                .replace("GAME_STRCPY_RETURN_V",str(BASE+0x15b7aa))
                .replace("GAME_STRCPY_DEST_V",str(strcpy_dest))
                .replace("CMDLINE_IAT_V",str(BASE+cmdline_iat))
                .replace("ONEXIT_GUARD_V",str(BASE+exit_guard))
                .replace("TAIL_IAT_RVAS",",".join(str(v) for v in TAIL_CHILD_IAT))
                .replace("E_VALUES",",".join("UINT64_C("+str(v)+")" for v in e_values))
                .replace("I_VALUES",",".join("UINT64_C("+str(v)+")" for v in init_values))
                .replace("__CASES__",encode(pairs,handoff_refs)))
        inc=ROOT/"arm64-lab"/"runtime"
        exe=root/"host"
        checked(["cc","-std=c11","-O2","-Wall","-Wextra","-Werror",
                "-DHOST","-I"+str(inc),*map(str,sources),str(smoke),"-o",str(exe)])
        checked([str(exe)])
        a64=root/"translated-original-crt-arm64.elf"
        checked(["clang","--target=aarch64-unknown-linux-gnu","-fuse-ld=lld",
                 "-nostdlib","-static","-ffreestanding","-fno-builtin",
                 "-fno-stack-protector","-O2","-std=c11","-I"+str(inc),
                 "-Wl,-e,smoke","-Wl,-z,max-page-size=4096",
                 "-Wl,--build-id=none",*map(str,sources),str(smoke),"-o",str(a64)])
        arm=execute_arm64_elf(a64,instruction_budget=6000000,timeout_us=15000000)
    output.mkdir(parents=True,exist_ok=True)
    report={
        "continuous_original_instructions_available":49,
        "static_original_crt_instructions":126,
        "matched_original_x64_and_arm64_fixtures":54,
        "test_groups":{"lock_acquisition":18,"recursive_ownership":18,"sleep_retry":18,
                       "initializer_success_two_calls":9,"initializer_failure_error_jump":9,
                       "nonreturning_amsg_exit_boundary":18,"already_initialized":18},
        "native_arm64_smoke_exit":arm["arm64_smoke_exit"],
        "bounded_arm64_instruction_budget":1950000,
        "two_win64_import_calls_modeled_with_injected_callbacks":True,
        "real_windows_imports_implemented":False,
        "native_multithreading_correct":False,
        "full_crt_or_game_boot":False,
        "last_original_address_exclusive":hex(RELEASE_END),
        "imported_CRT_thunks_executed_in_x64":True,
        "real_MSVCR90_initializer_executed":False,
        "authentic_initializer_tables_joined_to_native_startup":True,
        "original_exception_body_executed_in_joined_native_startup":True,
        "original_second_callback_body_executed_in_joined_native_startup":True,
        "original_argument_body_executed_in_joined_native_startup":True,
        "original_app_body_executed_in_joined_native_success_cases":True,
        "original_tail_callback_wrapper_and_child_executed_in_native_success_cases":True,
        "post_crt_command_line_main_call_reached_on_native_empty_arg_cases":True,
        "original_game_main_call_executed":True,
        "crt_main_one_guest_address_space":True,
        "original_main_eight_instruction_prefix_joined_cases":9,
        "first_internal_game_main_call_executed_in_crt_harness":True,
        "first_original_game_main_callee_empty_branch_returned":True,
        "native_game_getmodulefilename_modeled_in_crt_memory":True,
        "native_main_filename_import_reached_rva":"0x13675c",
        "original_main_filename_continuation_joined_cases":9,
        "game_main_next_filename_helper_executed_in_crt_harness":True,
        "game_main_filename_helper_and_strcpy_joined_cases":9,
        "native_crt_to_game_filename_helper_frontier_rva":"0x15b809",
        "original_filename_whole_string_x64_oracle_verified":True,
        "native_full_filename_suffix_original_instruction_count":314,
        "native_game_main_full_filename_parser_instructions":396,
        "original_filename_helper_returned_to_game_main":True,
        "original_filename_helper_return_pc":"0x136769",
        "native_game_main_after_setcwd_frontier_rva":"0x13677f",
        "native_original_game_main_total_instructions":401,
        "native_guest_virtual_current_directory_calls":9,
        "native_model_setcwd_is_host_filesystem_mutation":False,
        "original_game_next_direct_callee_rva":"0x133e80",
        "original_game_next_callee_executed":False,
        "original_filename_helper_guest_stack_restored":True,
        "original_filename_separator_finalizer_x64_verified":True,
        "native_filename_directory_global_truncated_after_backslash":True,
        "native_next_shared_filename_epilogue_rva":"0x15b862",
        "native_CRT_game_main_filename_NUL_boundary_joined_cases":9,
        "original_last_separator_offset":10,
        "original_NUL_offset":22,
        "whole_original_filename_helper_returned":False,
        "original_filename_parser_x64_third_backslash_oracle_verified":True,
        "crt_initialized_one_guest_memory_parser_instructions":76,
        "crt_to_filename_three_character_control_path_cases":9,
        "original_filename_separator_found_rva":"0x15b7f5",
        "entire_original_game_filename_helper_returned":False,
        "guest_process_modeled_external_imports_in_main":2,
        "real_kernel32_or_msvcr90_imports_executed":False,
        "original_x64_full_crt_to_game_main_oracle_executed":False,
        "original_post_release_command_line_x64_references":sum(
            1 for f,_ in pairs if f["state"]==0 and not f["init_status"]),
        "tail_import_services_still_injected":True,
        "original_app_error_cases_still_use_injected_import_status":True,
        "original_app_header_and_data_seeded_from_private_executable":True,
        "argument_services_share_guest_memory_with_startup":True,
        "all_five_original_callback_bodies_joined_in_native_success_cases":True,
        "injected_error_case_and_import_service_boundaries_remain":True
    }
    (output/"next-crt-joined-release-arm64.json").write_text(json.dumps(report,indent=2)+"\n")
    summary="\n".join([
        "# MX Bikes original CRT startup joined through MSVCR90 import return","",
        "- **54/54** original x64 / native host / AArch64 comparisons matched",
        "- Three lock paths: **18 acquired, 18 recursive, 18 Sleep+retry**",
        "- Joined original **49-instruction** region through two synthetic Win64 CALL responses",
        "- Compared RAX/RBX/RCX/RDX/RDI/RSI, ZF, 512-byte stack, lock/CRT globals, and state/release path bitmaps",
        "- ARM64 smoke exit: **"+str(arm["arm64_smoke_exit"])+"**","",
        "**Native startup now walks both authentic initializer arrays. All five original callback bodies execute inside the native success-path startup, including the 52-instruction app initializer and the two-instruction tail through the original eight-instruction wrapper and 39-instruction child. Imported services and error-case statuses still use controlled responses. Nine successful native CRT fixtures now perform the Win64 CALL main transition and execute the first eight independently verified game-main instructions using the SAME guest memory, preserving CRT globals and callback effects. The first game-main internal CALL and genuine empty-argument callee body now return into the original main path, and the modeled GetModuleFileNameA import writes the verified deterministic module filename in the SAME guest memory, reaching RVA 0x13675C. The original filename-helper prologue and bounded modeled MSVCR90 strcpy thunk now run in that same CRT-initialized guest context, copying the modeled module path into the game global and reaching the original 0x15B7AA continuation. Its original post-strcpy MOV/LEA/JMP, signed first-char CMP/JE, backslash and slash comparisons, two loop iterations and the third-character backslash JE now execute in the same CRT-initialized guest context. The authentic full filename scan reaches original post-NUL RVA 0x15B809 and executes four original directory-truncation instructions to the shared epilogue boundary RVA 0x15B862 in the same CRT-initialized native guest process. The exact last separator at guest offset 10, NUL inserted at offset 11 and untouched following bytes match the independently executed original x64 opcode trace. The original separator-present helper now executes the authentic shared epilogue (ADD RSP,0x38; RET) and returns to game-main RVA 0x136769 in the same CRT-initialized native guest process. Full original x64 main-through-helper original machine trace verifies the exact memory mutation, return address and caller stack restoration; the game-main continuation then executes the original MOV RCX,RAX, models an explicitly validated virtual KERNEL32 SetCurrentDirectoryA call without mutating the host filesystem, and prepares the original direct CALL 0x133E80 with the authentic RIP-relative inputs in the SAME guest process. The new internal callee is not executed. This combined path is not yet an end-to-end original x64 oracle. Full Windows CRT, engine and iOS are not implemented.**",""])
    (output/"next-crt-joined-release-arm64.md").write_text(summary)
    print(summary)

if __name__=="__main__":
    if len(sys.argv)!=3:raise SystemExit("usage: python script.py /private/exe REPORT_DIR")
    run(Path(sys.argv[1]),Path(sys.argv[2]))
