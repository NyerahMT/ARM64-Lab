"""Six MSVCR90-style synthetic service contracts, host and executed ARM64.

These are bounded independently authored fixtures, not original DLL execution
or production-compatible Windows synchronization.
"""
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
SOURCE = r"""
#include <stdint.h>
#include "mx_crt_service_dispatch.h"

#define BASE UINT64_C(0x70001000)
#define KEY UINT64_C(0x91c653e86da420f7)
static uint8_t bytes[512];

int smoke(void) {
    mx_crt_services s;
    if(mx_crt_services_init(0,KEY)!=MX_CRT_SVC_INVALID)return 1;
    if(mx_crt_services_init(&s,0)!=MX_CRT_SVC_INVALID)return 2;
    if(mx_crt_services_init(&s,KEY)!=MX_CRT_SVC_OK)return 3;
    const uint64_t pointers[]={
        0,1,UINT64_C(0xffffffffffffffff),
        UINT64_C(0x140000000),UINT64_C(0x123456789abcdef0)
    };
    for(unsigned i=0;i<5;i++) {
        uint64_t encoded=mx_crt_encode_pointer(&s,pointers[i]);
        if(mx_crt_decode_pointer(&s,encoded)!=pointers[i])return 4+i;
    }
    if(mx_crt_encode_pointer(&s,0)==0 ||
       mx_crt_decode_pointer(&s,mx_crt_encode_pointer(&s,0))!=0)return 11;
    if(mx_crt_service_lock(&s,8,111)!=MX_CRT_SVC_OK ||
       mx_crt_service_lock(&s,8,111)!=MX_CRT_SVC_OK ||
       s.lock_depth[8]!=2)return 12;
    if(mx_crt_service_lock(&s,8,222)!=MX_CRT_SVC_BUSY ||
       mx_crt_service_unlock(&s,8,222)!=MX_CRT_SVC_INVALID ||
       mx_crt_service_unlock(&s,8,111)!=MX_CRT_SVC_OK ||
       s.lock_depth[8]!=1)return 13;
    if(mx_crt_service_unlock(&s,8,111)!=MX_CRT_SVC_OK ||
       mx_crt_service_unlock(&s,8,111)!=MX_CRT_SVC_INVALID ||
       mx_crt_service_lock(&s,8,222)!=MX_CRT_SVC_OK)return 14;
    if(mx_crt_service_lock(&s,16,222)!=MX_CRT_SVC_INVALID ||
       mx_crt_service_lock(&s,8,0)!=MX_CRT_SVC_INVALID ||
       mx_crt_service_unlock(&s,16,222)!=MX_CRT_SVC_INVALID)return 15;

    if(mx_crt_service_onexit(&s,0)!=0 || s.onexit_count!=0)return 20;
    for(unsigned i=0;i<MX_CRT_SVC_ONEXIT_MAX;i++) {
        uint64_t cb=UINT64_C(0x140003000)+i*16U;
        if(mx_crt_service_onexit(&s,cb)!=cb ||
           s.onexit[i]!=cb || s.onexit_count!=i+1U)return 21;
    }
    if(mx_crt_service_onexit(&s,UINT64_C(0x1234))!=0 ||
       s.onexit_count!=MX_CRT_SVC_ONEXIT_MAX)return 22;

    mx_cfg_region region={BASE,bytes,sizeof(bytes)};
    mx_cfg_memory memory={&region,1};
    uint64_t heap=BASE+0x100U;
    if(!mx_cfg_transfer(&memory,BASE+0x20U,&heap,8,1) ||
       !mx_cfg_transfer(&memory,BASE+0x28U,&heap,8,1))return 30;
    if(mx_crt_service_dllonexit(&memory,0,BASE+0x20U,BASE+0x28U,heap,4)!=0)
       return 31;
    for(unsigned i=0;i<4;i++){
        uint64_t callback=UINT64_C(0x140004000)+i;
        if(mx_crt_service_dllonexit(&memory,callback,BASE+0x20U,
                                    BASE+0x28U,heap,4)!=callback)return 32;
        uint64_t saved=0,end=0;
        if(!mx_cfg_transfer(&memory,heap+(uint64_t)i*8U,&saved,8,0) ||
           !mx_cfg_transfer(&memory,BASE+0x28U,&end,8,0) ||
           saved!=callback || end!=heap+(uint64_t)(i+1)*8U)return 33;
    }
    if(mx_crt_service_dllonexit(&memory,5,BASE+0x20U,
                                BASE+0x28U,heap,4)!=0)return 34;
    if(mx_crt_service_dllonexit(&memory,5,BASE+0x20U,
                                BASE+0x28U,heap,33)!=0)return 35;
    if(mx_crt_service_dllonexit(&memory,5,BASE+0x400U,
                                BASE+0x28U,heap,4)!=0)return 36;
    uint64_t wrong=heap+1U;
    if(!mx_cfg_transfer(&memory,BASE+0x28U,&wrong,8,1))return 37;
    if(mx_crt_service_dllonexit(&memory,5,BASE+0x20U,
                                BASE+0x28U,heap,4)!=0)return 38;
    /* Typed Win64 RCX/RDX/R8 adapter with explicit RAX and memory effects. */
    mx_crt_service_adapter adapter={&s,&memory,222,heap,4};
    uint64_t rax=UINT64_C(0xfeedface);
    if(mx_crt_dispatch_service(&adapter,MX_CRT_SERVICE_UNSUPPORTED,
                               0,0,0,&rax)!=0||rax!=UINT64_C(0xfeedface))
        return 40;
    if(mx_crt_dispatch_service(&adapter,MX_CRT_SERVICE_ENCODE_POINTER,
                               0x12345678U,0,0,&rax)!=1||
       mx_crt_decode_pointer(&s,rax)!=0x12345678U)return 41;
    uint64_t token=rax;
    if(mx_crt_dispatch_service(&adapter,MX_CRT_SERVICE_DECODE_POINTER,
                               token,0,0,&rax)!=1||rax!=0x12345678U)
       return 42;
    rax=UINT64_C(0xfeedface);
    if(mx_crt_dispatch_service(&adapter,MX_CRT_SERVICE_LOCK,
                               8,0,0,&rax)!=1||rax!=UINT64_C(0xfeedface))
       return 43;
    if(mx_crt_dispatch_service(&adapter,MX_CRT_SERVICE_UNLOCK,
                               8,0,0,&rax)!=1||rax!=UINT64_C(0xfeedface))
       return 44;
    if(mx_crt_dispatch_service(&adapter,MX_CRT_SERVICE_LOCK,
                               99,0,0,&rax)!=-1||
       mx_crt_dispatch_service(&adapter,MX_CRT_SERVICE_UNLOCK,
                               UINT64_C(0x100000000),0,0,&rax)!=-1)
       return 45;
    if(mx_crt_services_init(&s,KEY)!=MX_CRT_SVC_OK)return 46;
    if(mx_crt_dispatch_service(&adapter,MX_CRT_SERVICE_ONEXIT,
                               UINT64_C(0x140005000),0,0,&rax)!=1||
       rax!=UINT64_C(0x140005000)||s.onexit_count!=1)
       return 47;
    if(!mx_cfg_transfer(&memory,BASE+0x28U,&heap,8,1))return 48;
    if(mx_crt_dispatch_service(&adapter,MX_CRT_SERVICE_DLLONEXIT,
                               UINT64_C(0x140006000),
                               BASE+0x20U,BASE+0x28U,&rax)!=1||
       rax!=UINT64_C(0x140006000))return 49;
    if(mx_crt_dispatch_service(0,MX_CRT_SERVICE_LOCK,8,0,0,&rax)!=-1)
       return 50;
    rax=UINT64_C(0xdeadbeef98765432);
    const mx_crt_service_id external[]={
        MX_CRT_SERVICE_GETMAINARGS,MX_CRT_SERVICE_SET_APP_TYPE,
        MX_CRT_SERVICE_SET_USERMATHERR,MX_CRT_SERVICE_CONFIGTHREADLOCALE};
    for(unsigned i=0;i<sizeof(external)/sizeof(external[0]);i++){
        if(mx_crt_dispatch_service(&adapter,external[i],1,2,3,&rax)!=0||
           rax!=UINT64_C(0xdeadbeef98765432))return 51+i;
    }
    return 0;
}
#ifdef HOST
int main(void){return smoke();}
#endif
"""


class CRTServiceTests(unittest.TestCase):
    def test_portable_guest_service_contract(self):
        cc, clang = shutil.which("cc"), shutil.which("clang")
        if not cc or not clang:
            self.skipTest("native and AArch64 C compilers required")
        with tempfile.TemporaryDirectory() as td:
            wd = Path(td)
            src = wd / "crt_services.c"
            src.write_text(SOURCE)
            flags = ["-O2", "-std=c11", "-Wall", "-Wextra", "-Werror",
                     "-I", str(ROOT / "runtime")]
            subprocess.run([cc, *flags, "-DHOST", str(src),
                            "-o", str(wd / "host")], check=True)
            subprocess.run([str(wd / "host")], check=True)
            arm = wd / "arm64.elf"
            subprocess.run([
                clang, "--target=aarch64-unknown-linux-gnu",
                "-fuse-ld=lld", "-nostdlib", "-static", "-ffreestanding",
                "-fno-stack-protector", "-fno-builtin", *flags,
                "-Wl,-e,smoke", "-Wl,-z,max-page-size=4096",
                "-Wl,--build-id=none", str(src), "-o", str(arm),
            ], check=True)
            from tools.import_aot_smoke import execute_arm64_elf
            result = execute_arm64_elf(arm, instruction_budget=250000,
                                       timeout_us=3000000)
            self.assertEqual(result["arm64_smoke_exit"], 0)
            self.assertTrue(result["return_to_sentinel"])


if __name__ == "__main__":
    unittest.main()
