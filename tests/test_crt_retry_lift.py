"""Batch coverage: immediate acquisition, recursive owner, Sleep/retry, failures."""
from pathlib import Path
import subprocess,tempfile,unittest
from tools.crt_retry_lift import lift_crt_retry
from tools.crt_cfg_lift import UnsupportedCRT

RETRY=bytes.fromhex("31c0f0480fb13d05010000")
BRANCH=bytes.fromhex("74194839f87507be01000000eb0db9e8030000ff1522000000ebda")
START=0x4000
BR=START+len(RETRY)
IAT={0x4046:("kernel32.dll","Sleep")}

class CRTLockRetryTests(unittest.TestCase):
    def test_all_three_paths_and_fail_closed(self):
        source,meta=lift_crt_retry(RETRY,BRANCH,START,BR,IAT)
        self.assertEqual(meta["static_instruction_count"],10)
        self.assertEqual(meta["stop_before_rva"],"0x4026")
        self.assertTrue(meta["sleep_is_injected"])
        harness=r"""
#include <stdint.h>
#include "mx_crt_primitives.h"
int lifted_crt_lock_retry(mx_crt_state *,mx_cfg_memory *,
                            int (*)(void *,uint32_t),void *,int);
typedef struct {mx_cfg_memory *memory; uint32_t calls; int release;} ctx_t;
static int sleep_hook(void *v,uint32_t ms) {
    ctx_t *ctx=(ctx_t*)v;
    if(ms!=1000U)return 0;
    ctx->calls++;
    if(ctx->release) {
        uint64_t zero=0;
        if(!mx_cfg_transfer(ctx->memory,UINT64_C(0x140004110),&zero,8,1))return 0;
    }
    return 1;
}
int main(void) {
    uint8_t shared[8]={0},stack[128]={0};
    mx_cfg_region regions[2]={{UINT64_C(0x140004110),shared,8},
                              {UINT64_C(0x500000),stack,128}};
    mx_cfg_memory m={regions,2};
    for(unsigned k=0;k<3;k++){
        uint64_t starting=k==0?42U:(k==1?42U:7U),result=0;
        if(!mx_cfg_transfer(&m,UINT64_C(0x140004110),&starting,8,1))return 10;
        mx_crt_state s={0};
        s.rip=UINT64_C(0x14000400b);
        s.rsp=UINT64_C(0x500040);
        s.rdi=42;
        s.rsi=98;
        s.rax=(k==0?0U:(k==1?42U:7U));
        s.zf=(k==0);
        ctx_t context={&m,0,k==2};
        int status=lifted_crt_lock_retry(&s,&m,sleep_hook,&context,1);
        if(status!=MX_CRT_BRANCH_BOUNDARY || s.rip!=UINT64_C(0x140004026))return 20+k;
        if(!mx_cfg_transfer(&m,UINT64_C(0x140004110),&result,8,0) || result!=42)return 30+k;
        if(s.rsi!=(k==1?1U:98U) || s.rax!=(k==1?42U:0U) || !s.zf)return 40+k;
        if(context.calls!=(k==2?1U:0U) || s.imports!=context.calls)return 50+k;
        if(s.instructions!=(k==0?1U:(k==1?5U:9U)))return 60+k;
        if(s.fault)return 70+k;
    }
    /* Contention that never clears must fail closed, not spin forever. */
    uint64_t occupied=7;
    if(!mx_cfg_transfer(&m,UINT64_C(0x140004110),&occupied,8,1))return 80;
    mx_crt_state blocked={0};
    blocked.rip=UINT64_C(0x14000400b);
    blocked.rsp=UINT64_C(0x500040);
    blocked.rdi=42;
    blocked.rax=7;
    ctx_t no_release={&m,0,0};
    if(lifted_crt_lock_retry(&blocked,&m,sleep_hook,&no_release,1)!=MX_CRT_INVALID)return 81;
    if(no_release.calls==0 || no_release.calls>32)return 82;
    blocked=(mx_crt_state){0};
    blocked.rip=UINT64_C(0x14000400b);
    blocked.rsp=UINT64_C(0x500040);
    blocked.rdi=42;
    blocked.rax=7;
    if(lifted_crt_lock_retry(&blocked,&m,0,0,1)!=MX_CRT_INVALID)return 83;
    return 0;
}
"""
        root=Path(__file__).resolve().parents[1]
        with tempfile.TemporaryDirectory() as td:
            folder=Path(td);(folder/"lift.c").write_text(source);(folder/"harness.c").write_text(harness)
            exe=folder/"test"
            run=subprocess.run(["cc","-std=c11","-O2","-Wall","-Wextra","-Werror",
                "-I",str(root/"runtime"),str(folder/"lift.c"),str(folder/"harness.c"),"-o",str(exe)],
                capture_output=True,text=True)
            self.assertEqual(run.returncode,0,run.stderr)
            done=subprocess.run([str(exe)],capture_output=True,text=True)
            self.assertEqual(done.returncode,0,"native exit "+str(done.returncode)+done.stderr)

    def test_reject_wrong_branch_and_import(self):
        with self.assertRaises(UnsupportedCRT):
            lift_crt_retry(RETRY,BRANCH,START,BR,{})
        wrong=bytearray(BRANCH);wrong[0]=0x75
        with self.assertRaises(UnsupportedCRT):
            lift_crt_retry(RETRY,bytes(wrong),START,BR,IAT)
        with self.assertRaises(UnsupportedCRT):
            lift_crt_retry(RETRY,BRANCH,START,BR,{0x4046:("steam_api64.dll","SteamAPI_Init")})
