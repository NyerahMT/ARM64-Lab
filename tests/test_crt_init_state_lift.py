"""Host execution and rejection matrix for strict three-way CRT state frontier."""
from pathlib import Path
import re
import subprocess
import tempfile
import unittest

from tools.crt_init_state_lift import lift_crt_init_state
from tools.crt_cfg_lift import UnsupportedCRT

ASSEMBLY=r"""
.intel_syntax noprefix
.text
.globl crt_entry
crt_entry:
    mov eax, DWORD PTR [rip+crt_state]
    cmp eax, 1
    jne other_state
    lea ecx, [rax+0x1e]
    call direct_a
    jmp join_state
other_state:
    mov eax, DWORD PTR [rip+crt_state]
    test eax, eax
    jne alternate
    mov DWORD PTR [rip+crt_state], 1
    lea rdx, [rip+arg_end]
    lea rcx, [rip+arg_begin]
    call direct_b
    test eax, eax
    je join_state
    mov eax, 255
    jmp error_exit
alternate:
    mov DWORD PTR [rip+alt_state], 1
join_state:
    ret
direct_a:
    ret
direct_b:
    ret
error_exit:
    ret
    .balign 8
crt_state:
    .long 0
alt_state:
    .long 0
arg_begin:
    .quad 0
arg_end:
    .quad 0
"""

class StateFrontierTests(unittest.TestCase):
    def fixture(self,root):
        src=root/"crt.s"
        obj=root/"crt.o"
        binary=root/"crt.bin"
        src.write_text(ASSEMBLY)
        subprocess.run(["as","--64",str(src),"-o",str(obj)],check=True,
                       capture_output=True,text=True)
        subprocess.run(["objcopy","--only-section=.text","-O","binary",
                        str(obj),str(binary)],check=True,
                       capture_output=True,text=True)
        nm=subprocess.run(["nm","-n",str(obj)],check=True,
                          capture_output=True,text=True).stdout
        symbols={}
        for line in nm.splitlines():
            fields=line.split()
            if len(fields)>=3:
                symbols[fields[-1]]=int(fields[0],16)
        return binary.read_bytes(),symbols

    def test_all_three_paths_with_native_guest_state(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td)
            raw,syms=self.fixture(root)
            start=0x3000
            end=syms["join_state"]
            code,meta=lift_crt_init_state(raw[:end],start)
            self.assertEqual(meta["decoded_original_instructions"],18)
            self.assertEqual(meta["join_rva"],hex(start+end))
            self.assertEqual(len(meta["direct_call_targets_rva"]),2)
            self.assertFalse(meta["direct_calls_executed"])
            (root/"lift.c").write_text(code)
            harness=r"""
#include <stdint.h>
#include "mx_crt_vm.h"
#define BASE UINT64_C(0x140003000)
#define STATE (BASE+UINT64_C(STATE_OFFSET))
#define ALT (BASE+UINT64_C(ALT_OFFSET))
#define JOIN (BASE+UINT64_C(JOIN_OFFSET))
#define FIRSTCALL (BASE+UINT64_C(CALL_A_OFFSET))
#define SECONDCALL (BASE+UINT64_C(CALL_B_OFFSET))
#define ARGEND (BASE+UINT64_C(ARG_END_OFFSET))
#define ARGBEGIN (BASE+UINT64_C(ARG_BEGIN_OFFSET))
int lifted_crt_init_state(mx_crt_state*,mx_cfg_memory*,uint64_t*);
int main(void) {
    uint8_t data[512]={0};
    mx_cfg_region region={BASE,data,sizeof(data)};
    mx_cfg_memory m={&region,1};
    for(unsigned k=0;k<3;k++){
        uint32_t state=(k==0?1U:(k==1?0U:7U)),flag=0,after=0,alt=0;
        if(!mx_cfg_transfer(&m,STATE,&state,4,1) ||
           !mx_cfg_transfer(&m,ALT,&flag,4,1))return 10;
        mx_crt_state s={0};
        uint64_t rdx=UINT64_C(0x123456789abcdef0);
        s.rip=BASE;s.rsp=UINT64_C(0x70000080);
        s.rbx=1234;s.rcx=555;s.rdi=4321;s.rsi=987;
        int status=lifted_crt_init_state(&s,&m,&rdx);
        if(!mx_cfg_transfer(&m,STATE,&after,4,0) ||
           !mx_cfg_transfer(&m,ALT,&alt,4,0))return 20;
        if(s.fault || s.pending_import || s.imports ||
           s.rbx!=1234 || s.rdi!=4321 || s.rsi!=987 ||
           s.rsp!=UINT64_C(0x70000080))return 21;
        if(k==0){
            if(status!=5 || s.rip!=FIRSTCALL || s.rax!=1 ||
               s.rcx!=31 || rdx!=UINT64_C(0x123456789abcdef0) ||
               !s.zf || after!=1 || alt || s.visited!=15U ||
               s.instructions!=4U)return 30;
        }else if(k==1){
            if(status!=5 || s.rip!=SECONDCALL || s.rax ||
               s.rcx!=ARGBEGIN || rdx!=ARGEND ||
               !s.zf || after!=1 || alt || s.visited!=4039U ||
               s.instructions!=9U)return 40;
        }else{
            if(status!=MX_CRT_BRANCH_BOUNDARY || s.rip!=JOIN ||
               s.rax!=7 || s.rcx!=555 ||
               rdx!=UINT64_C(0x123456789abcdef0) ||
               s.zf || after!=7 || alt!=1 ||
               s.visited!=131527U || s.instructions!=7U)return 50;
        }
    }
    return 0;
}
"""
            for label,name in [("STATE_OFFSET","crt_state"),
                               ("ALT_OFFSET","alt_state"),
                               ("JOIN_OFFSET","join_state"),
                               ("CALL_A_OFFSET","direct_a"),
                               ("CALL_B_OFFSET","direct_b"),
                               ("ARG_END_OFFSET","arg_end"),
                               ("ARG_BEGIN_OFFSET","arg_begin")]:
                if label.startswith("CALL_"):
                    # STOP at call instructions inside the initial span,
                    # not at the call target's function address.
                    address=int(meta["direct_call_sites_rva"][0 if label=="CALL_A_OFFSET" else 1],16)-start
                else:
                    address=syms[name]
                harness=harness.replace(label,str(address))
            (root/"test.c").write_text(harness)
            includes=Path(__file__).resolve().parents[1]/"runtime"
            target=root/"check"
            c=subprocess.run(["cc","-std=c11","-O2","-Wall","-Wextra","-Werror",
                "-I",str(includes),str(root/"lift.c"),str(root/"test.c"),
                "-o",str(target)],capture_output=True,text=True)
            self.assertEqual(c.returncode,0,c.stderr)
            out=subprocess.run([str(target)],capture_output=True,text=True)
            self.assertEqual(out.returncode,0,f"Native CRT path exit {out.returncode} {out.stderr}")

    def test_wrong_frontier_fails_closed(self):
        with tempfile.TemporaryDirectory() as td:
            raw,syms=self.fixture(Path(td))
            code=raw[:syms["join_state"]]
            with self.assertRaises(UnsupportedCRT):
                lift_crt_init_state(code[:-1],0x3000)
            # Change original cmp eax,1 to cmp eax,2 without moving boundaries.
            marker=bytes.fromhex("83f801")
            self.assertEqual(code.count(marker),1)
            changed=code.replace(marker,bytes.fromhex("83f802"))
            with self.assertRaises(UnsupportedCRT):
                lift_crt_init_state(changed,0x3000)

if __name__=="__main__":
    unittest.main()
