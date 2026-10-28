"""Host and genuinely executed AArch64 checks for the original Steam CALL ABI.

Synthetic guest memory only. No Steam client, token, DLL call, or license
result is provided; an unavailable platform MUST remain unavailable.
"""
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "arm64-lab"))
from tools.import_aot_smoke import execute_arm64_elf

C_SOURCE = r"""
#include <stdint.h>
#include "mxbikes_steam_platform_boundary.h"

static uint8_t stack_bytes[128];

int smoke(void) {
    const uint64_t base=UINT64_C(0x73000000);
    mx_cfg_region region={base,stack_bytes,sizeof(stack_bytes)};
    mx_cfg_memory memory={&region,1U};
    mx_crt_cluster_state cpu={0};
    cpu.rip=MXB_ORIGINAL_STEAM_PC;
    cpu.rcx=MXB_ORIGINAL_STEAM_APP_ID;
    cpu.rax=UINT64_C(0x12345678);
    cpu.rsp=base+80U;
    const uint64_t old=UINT64_C(0xabcdef0123456789);
    uint64_t value=old;
    if(!mx_cfg_transfer(&memory,cpu.rsp-8U,&value,8U,1))return 1;
    mxb_steam_call_contract frame={0};
    if(mxb_steam_capture_call_contract(&cpu,&memory,MXB_HOST_DESKTOP,&frame)!=
        MXB_STEAM_DESKTOP_CLIENT_NOT_CONNECTED)return 2;
    if(frame.guest_call_pc!=MXB_ORIGINAL_STEAM_PC||
       frame.import_iat_slot!=MXB_ORIGINAL_STEAM_IAT_SLOT||
       frame.original_return_pc!=MXB_ORIGINAL_STEAM_RETURN_PC||
       frame.guest_app_id!=MXB_ORIGINAL_STEAM_APP_ID||
       frame.caller_rsp!=cpu.rsp||
       frame.callee_rsp_if_invoked!=cpu.rsp-8U||
       frame.prior_callee_stack_bytes!=old)return 3;
    if(cpu.rip!=MXB_ORIGINAL_STEAM_PC||
       cpu.rax!=UINT64_C(0x12345678)||cpu.rcx!=MXB_ORIGINAL_STEAM_APP_ID||
       cpu.rsp!=base+80U||cpu.imports!=0U||cpu.fault!=0U)return 4;
    value=0;
    if(!mx_cfg_transfer(&memory,cpu.rsp-8U,&value,8U,0)||
       value!=old)return 5;
    if(mxb_steam_capture_call_contract(&cpu,&memory,MXB_HOST_IOS,&frame)!=
       MXB_STEAM_UNSUPPORTED_IOS||
       frame.callee_rsp_if_invoked!=cpu.rsp-8U)return 6;
    if(mxb_steam_capture_call_contract(&cpu,&memory,
       (enum mxb_host_platform)99,&frame)!=
       MXB_STEAM_INVALID_GUEST_STATE)return 7;
    if(mxb_steam_capture_call_contract(&cpu,0,MXB_HOST_DESKTOP,&frame)!=
       MXB_STEAM_INVALID_GUEST_STATE)return 8;
    if(mxb_steam_capture_call_contract(&cpu,&memory,MXB_HOST_DESKTOP,0)!=
       MXB_STEAM_INVALID_GUEST_STATE)return 9;
    cpu.rip++;
    if(mxb_steam_capture_call_contract(&cpu,&memory,MXB_HOST_DESKTOP,&frame)!=
       MXB_STEAM_INVALID_GUEST_STATE||frame.guest_call_pc!=0)return 10;
    cpu.rip--;
    cpu.rcx++;
    if(mxb_steam_capture_call_contract(&cpu,&memory,MXB_HOST_DESKTOP,&frame)!=
       MXB_STEAM_INVALID_GUEST_STATE)return 11;
    cpu.rcx--;
    cpu.rsp++;
    if(mxb_steam_capture_call_contract(&cpu,&memory,MXB_HOST_DESKTOP,&frame)!=
       MXB_STEAM_INVALID_GUEST_STATE)return 12;
    cpu.rsp=base+144U;
    if(mxb_steam_capture_call_contract(&cpu,&memory,MXB_HOST_DESKTOP,&frame)!=
       MXB_STEAM_INVALID_GUEST_STATE)return 13;
    cpu.rsp=base+80U;
    cpu.fault=1;
    if(mxb_steam_capture_call_contract(&cpu,&memory,MXB_HOST_DESKTOP,&frame)!=
       MXB_STEAM_INVALID_GUEST_STATE)return 14;
    cpu.fault=0;
    if(mxb_steam_capture_call_contract(&cpu,&memory,MXB_HOST_DESKTOP,&frame)!=
       MXB_STEAM_DESKTOP_CLIENT_NOT_CONNECTED)return 15;
    value=0;
    if(!mx_cfg_transfer(&memory,cpu.rsp-8U,&value,8U,0)||
       value!=old)return 16;
    return 0;
}
int main(void) {return smoke();}
"""

class SteamCallContractTests(unittest.TestCase):
    def test_host_and_real_aarch64_fail_closed_contract(self):
        with tempfile.TemporaryDirectory(prefix="mxb-steam-call-contract-") as tmp:
            folder=Path(tmp)
            source=folder/"steam_contract.c"
            source.write_text(C_SOURCE)
            includes=[
                "-I"+str(ROOT/"scripts"),
                "-I"+str(ROOT/"arm64-lab"/"runtime"),
            ]
            flags=["-O2","-std=c11","-Wall","-Wextra","-Werror"]
            host=folder/"host_smoke"
            subprocess.run(["cc",*flags,*includes,str(source),"-o",str(host)],
                           check=True,capture_output=True,text=True)
            subprocess.run([str(host)],check=True,capture_output=True,text=True)
            native=folder/"steam_contract_arm64.elf"
            subprocess.run([
                "clang","--target=aarch64-unknown-linux-gnu","-fuse-ld=lld",
                "-nostdlib","-static","-ffreestanding","-fno-builtin",
                "-fno-stack-protector",*flags,*includes,
                "-Wl,-e,smoke","-Wl,-z,max-page-size=4096",
                "-Wl,--build-id=none",str(source),"-o",str(native)
            ],check=True,capture_output=True,text=True)
            result=execute_arm64_elf(native,instruction_budget=100000,
                                     timeout_us=3000000)
            self.assertTrue(result["return_to_sentinel"])

if __name__ == "__main__":
    unittest.main()
