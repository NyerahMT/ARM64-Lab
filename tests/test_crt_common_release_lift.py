"""Synthetic matrix for CRT post-initialization lock-release branches."""
from pathlib import Path
import subprocess,tempfile,unittest
from tools.crt_common_release_lift import lift_crt_common_release
from tools.crt_cfg_lift import UnsupportedCRT

ASSEMBLY=r"""
.intel_syntax noprefix
.text
.globl start
start:
    mov eax, DWORD PTR [rip+crt_state]
    cmp eax, 1
    jne branch_owner
    lea rdx, [rip+callback_end]
    lea rcx, [rip+callback_begin]
    call direct
    mov DWORD PTR [rip+crt_state], 2
branch_owner:
    test esi, esi
    jne next
    xor eax, eax
    xchg QWORD PTR [rip+owner], rax
next:
    ret
direct:
    ret
    .balign 8
crt_state:
    .long 0
    .balign 8
owner:
    .quad 0
callback_begin:
    .quad 0
callback_end:
    .quad 0
"""

class CRTReleaseTests(unittest.TestCase):
    def sample(self,work):
        code=work/"code.s";obj=work/"code.o";raw=work/"code.bin"
        code.write_text(ASSEMBLY)
        subprocess.run(["as","--64",str(code),"-o",str(obj)],check=True,
                       capture_output=True,text=True)
        subprocess.run(["objcopy","-O","binary","--only-section=.text",
                        str(obj),str(raw)],check=True,capture_output=True,text=True)
        syms={}
        output=subprocess.run(["nm","-n",str(obj)],check=True,
                              capture_output=True,text=True).stdout
        for line in output.splitlines():
            parts=line.split()
            if len(parts)>=3:syms[parts[-1]]=int(parts[0],16)
        return raw.read_bytes(),syms

    def test_state_and_both_owner_paths(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)
            contents,syms=self.sample(root)
            code,meta=lift_crt_common_release(contents[:syms["next"]],0x5000)
            self.assertEqual(meta["decoded_original_instructions"],11)
            self.assertEqual(meta["release_join_rva"],hex(0x5000+syms["next"]))
            self.assertFalse(meta["concurrent_exchange_supported"])
            (root/"translated.c").write_text(code)
            smoke=r"""
#include <stdint.h>
#include "mx_crt_primitives.h"
#define BASE UINT64_C(0x140005000)
#define STATE (BASE+UINT64_C(STATE_OFF))
#define OWNER (BASE+UINT64_C(OWNER_OFF))
#define DIRECT (BASE+UINT64_C(DIRECT_OFF))
#define JOIN (BASE+UINT64_C(JOIN_OFF))
#define ARG1 (BASE+UINT64_C(ARG1_OFF))
#define ARG2 (BASE+UINT64_C(ARG2_OFF))
int lifted_crt_common_release(mx_crt_state*,mx_cfg_memory*,uint64_t*,int);
int main(void){
    uint8_t bytes[512]={0};
    mx_cfg_region r={BASE,bytes,512};
    mx_cfg_memory mem={&r,1};
    for(unsigned i=0;i<3;i++){
        uint32_t state=(i==0?1U:2U);
        uint64_t owner=UINT64_C(0x1122334455667788);
        if(!mx_cfg_transfer(&mem,STATE,&state,4,1) ||
           !mx_cfg_transfer(&mem,OWNER,&owner,8,1))return 10+i;
        mx_crt_state s={0};
        s.rip=BASE;s.rsp=UINT64_C(0x70000040);
        s.rsi=(i==1?1U:0U);
        s.rbx=77;s.rcx=88;s.rax=99;s.rdi=33;
        uint64_t rdx=UINT64_C(0xfedcba);
        int status=lifted_crt_common_release(&s,&mem,&rdx,1);
        uint64_t after=0;
        if(!mx_cfg_transfer(&mem,OWNER,&after,8,0))return 20+i;
        if(s.fault || s.rsp!=UINT64_C(0x70000040) || s.rbx!=77 ||
           s.rdi!=33)return 30+i;
        if(i==0){
            if(status!=5 || s.rip!=DIRECT || s.rax!=1 ||
               s.rcx!=ARG1 || rdx!=ARG2 || !s.zf ||
               after!=owner || s.visited!=31U ||
               s.instructions!=5U)return 40;
        }else if(i==1){
            if(status!=MX_CRT_BRANCH_BOUNDARY || s.rip!=JOIN || s.rax!=2 ||
               s.rcx!=88 || rdx!=UINT64_C(0xfedcba) || s.zf ||
               after!=owner || s.visited!=391U ||
               s.instructions!=5U)return 41;
        }else{
            if(status!=MX_CRT_BRANCH_BOUNDARY || s.rip!=JOIN ||
               s.rax!=owner || !s.zf || after!=0 ||
               s.visited!=1927U || s.instructions!=7U)return 42;
        }
    }
    uint32_t state=2;
    uint64_t owner=55;
    if(!mx_cfg_transfer(&mem,STATE,&state,4,1) ||
       !mx_cfg_transfer(&mem,OWNER,&owner,8,1))return 50;
    mx_crt_state fail={0};fail.rip=BASE;fail.rsi=0;
    uint64_t rdx=1;
    if(lifted_crt_common_release(&fail,&mem,&rdx,0)!=MX_CRT_MEMORY_FAULT ||
       !fail.fault)return 51;
    return 0;
}
"""
            mapping={
                "STATE_OFF":syms["crt_state"],"OWNER_OFF":syms["owner"],
                "DIRECT_OFF":next(int(x,16)-0x5000 for x in
                                   [meta["direct_call_site_rva"]]),
                "JOIN_OFF":syms["next"],
                "ARG1_OFF":syms["callback_begin"],
                "ARG2_OFF":syms["callback_end"]
            }
            for key,val in mapping.items():
                smoke=smoke.replace(key,str(val))
            (root/"smoke.c").write_text(smoke)
            runtime=Path(__file__).resolve().parents[1]/"runtime"
            executable=root/"smoke"
            compiled=subprocess.run(
                ["cc","-std=c11","-O2","-Wall","-Wextra","-Werror",
                 "-I",str(runtime),str(root/"translated.c"),str(root/"smoke.c"),
                 "-o",str(executable)],capture_output=True,text=True)
            self.assertEqual(compiled.returncode,0,compiled.stderr)
            run=subprocess.run([str(executable)],capture_output=True,text=True)
            self.assertEqual(run.returncode,0,f"native release failure exit={run.returncode} {run.stderr}")

    def test_reject_mismatched_branch_and_code_length(self):
        with tempfile.TemporaryDirectory() as tmp:
            contents,syms=self.sample(Path(tmp))
            source=contents[:syms["next"]]
            with self.assertRaises(UnsupportedCRT):
                lift_crt_common_release(source[:-1],0x5000)
            marker=bytes.fromhex("83f801")
            self.assertEqual(source.count(marker),1)
            with self.assertRaises(UnsupportedCRT):
                lift_crt_common_release(source.replace(marker,bytes.fromhex("83f802")),0x5000)

if __name__=="__main__":
    unittest.main()
