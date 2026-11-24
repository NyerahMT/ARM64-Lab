"""Opt-in *synthetic* offline relaunch experiment on host and executed ARM64.

Does not emulate SteamAPI_Init, validate ownership, patch the game, or boot it.
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
#include "mxbikes_steam_offline_relaunch_experiment.h"
static uint8_t guest_stack[128];

int smoke(void) {
    const uint64_t base = UINT64_C(0x73000000);
    mx_cfg_region region = {base, guest_stack, sizeof(guest_stack)};
    mx_cfg_memory memory = {&region, 1U};
    mx_crt_cluster_state s = {0};
    const uint64_t old = UINT64_C(0x123456789abcdef0);
    uint64_t check = old;
    s.rip = MXB_ORIGINAL_STEAM_PC;
    s.rcx = MXB_ORIGINAL_STEAM_APP_ID;
    s.rax = UINT64_C(0x778899aa);
    s.rsp = base + 80U;
    s.imports = 3U;
    s.rbx = UINT64_C(0xabcde);
    s.zf = 1U;
    if (!mx_cfg_transfer(&memory, s.rsp - 8U, &check, 8U, 1)) return 1;
#if MXB_EXPERIMENTAL_OFFLINE_RELAUNCH
    if (mxb_steam_offline_relaunch_experiment(&s, &memory) !=
        MXB_OFFLINE_RELAUNCH_TEST_RETURN) return 2;
    if (s.rip != MXB_ORIGINAL_STEAM_RETURN_PC || s.rax != 0U ||
        s.rcx != MXB_ORIGINAL_STEAM_APP_ID || s.rsp != base + 80U ||
        s.rbx != UINT64_C(0xabcde) || s.zf != 1U ||
        s.imports != 4U || s.fault != 0U) return 3;
    check = 0;
    if (!mx_cfg_transfer(&memory, s.rsp-8U, &check, 8U, 0) ||
        check != old) return 4;
    /* A second call at the next PC is never silently handled. */
    if (mxb_steam_offline_relaunch_experiment(&s, &memory) !=
        MXB_OFFLINE_RELAUNCH_INVALID) return 5;
    s.rip = MXB_ORIGINAL_STEAM_PC;
    s.rcx++;
    if (mxb_steam_offline_relaunch_experiment(&s, &memory) !=
        MXB_OFFLINE_RELAUNCH_INVALID) return 6;
    s.rcx--;
    s.imports = UINT32_MAX;
    if (mxb_steam_offline_relaunch_experiment(&s, &memory) !=
        MXB_OFFLINE_RELAUNCH_INVALID) return 7;
    s.imports = 4U;
    s.rsp++;
    if (mxb_steam_offline_relaunch_experiment(&s, &memory) !=
        MXB_OFFLINE_RELAUNCH_INVALID) return 8;
    s.rsp--;
    s.fault = 1U;
    if (mxb_steam_offline_relaunch_experiment(&s, &memory) !=
        MXB_OFFLINE_RELAUNCH_INVALID) return 9;
    s.fault = 0U;
    if (mxb_steam_offline_relaunch_experiment(&s, 0) !=
        MXB_OFFLINE_RELAUNCH_INVALID) return 10;
#else
    if (mxb_steam_offline_relaunch_experiment(&s, &memory) !=
        MXB_OFFLINE_RELAUNCH_DISABLED) return 11;
    if (s.rip != MXB_ORIGINAL_STEAM_PC || s.rax != UINT64_C(0x778899aa) ||
        s.imports != 3U || s.rsp != base+80U) return 12;
#endif
    return 0;
}
int main(void) {return smoke();}
"""

class OfflineRelaunchExperimentTests(unittest.TestCase):
    def test_disabled_by_default_and_opt_in_synthetic_arm64(self):
        with tempfile.TemporaryDirectory(prefix="mxb-offline-relaunch-") as td:
            p = Path(td)
            source = p / "relaunch_probe.c"
            source.write_text(C_SOURCE)
            includes = ["-I"+str(ROOT/"scripts"),
                        "-I"+str(ROOT/"arm64-lab"/"runtime")]
            common = ["-O2", "-std=c11", "-Wall", "-Wextra", "-Werror"]
            for enabled in (0, 1):
                define = "-DMXB_EXPERIMENTAL_OFFLINE_RELAUNCH="+str(enabled)
                host = p / ("host_"+str(enabled))
                subprocess.run(["cc", *common, define, *includes,
                                str(source), "-o", str(host)],
                               check=True, capture_output=True, text=True)
                subprocess.run([str(host)], check=True, capture_output=True,
                               text=True)
                arm = p / ("arm64_"+str(enabled)+".elf")
                subprocess.run([
                    "clang", "--target=aarch64-unknown-linux-gnu",
                    "-fuse-ld=lld", "-nostdlib", "-static",
                    "-ffreestanding", "-fno-builtin", "-fno-stack-protector",
                    *common, define, *includes,
                    "-Wl,-e,smoke", "-Wl,-z,max-page-size=4096",
                    "-Wl,--build-id=none", str(source), "-o", str(arm)
                ], check=True, capture_output=True, text=True)
                result = execute_arm64_elf(arm, instruction_budget=100000,
                                           timeout_us=3000000)
                self.assertTrue(result["return_to_sentinel"])

if __name__ == "__main__":
    unittest.main()
