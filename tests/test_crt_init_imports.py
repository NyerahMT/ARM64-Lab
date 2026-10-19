"""Synthetic MSVCR90 imported CRT callback bridge cases, strict native/AArch64."""
from pathlib import Path
import subprocess,tempfile,unittest

ROOT=Path(__file__).resolve().parents[1]
SMOKE=r"""
#include <stdint.h>
#include "mx_crt_init_imports.h"
typedef struct {
    uint32_t times,previous_kind;
    uint64_t first,second;
    uint32_t return_value;
    int allow;
} context;
static int synthetic(void *p,uint32_t kind,uint64_t first,
                     uint64_t second,uint32_t *result) {
    context *c=(context*)p;
    c->times++;c->previous_kind=kind;c->first=first;c->second=second;
    if(!c->allow)return 0;
    *result=c->return_value;
    return 1;
}
int smoke(void) {
    uint8_t stack[256]={0};
    mx_cfg_region regions[1]={{UINT64_C(0x500000),stack,sizeof(stack)}};
    mx_cfg_memory memory={regions,1};
    for(uint32_t mode=0U;mode<3U;mode++) {
        mx_crt_state state={0};
        state.rsp=UINT64_C(0x500080);
        state.rip=UINT64_C(0x1402ab0b6);
        state.rcx=UINT64_C(0x140322000);
        state.rax=UINT64_C(0x7788990011223344);
        context c={0,0,0,0,mode==0U?0U:31U,1};
        int rc=mx_crt_invoke_init_thunk(&state,&memory,MX_CRT_INITTERM_E,
             UINT64_C(0x1402ab0b6),UINT64_C(0x1402ab0bb),
             UINT64_C(0x140322100),synthetic,&c);
        if(rc!=MX_CRT_BRANCH_BOUNDARY || state.fault ||
           state.rax!=(mode==0U?0U:31U) || state.rip!=UINT64_C(0x1402ab0bb) ||
           state.rsp!=UINT64_C(0x500080) || state.imports!=1U ||
           state.import_trace!=MX_CRT_INITTERM_E ||
           c.times!=1U || c.first!=UINT64_C(0x140322000) ||
           c.second!=UINT64_C(0x140322100))return 10+mode;
        uint64_t saved=0;
        if(!mx_cfg_transfer(&memory,state.rsp-8U,&saved,8U,0) ||
           saved!=UINT64_C(0x1402ab0bb))return 20+mode;
    }
    mx_crt_state void_call={0};
    void_call.rsp=UINT64_C(0x500080);
    void_call.rip=UINT64_C(0x1402ab0ec);
    void_call.rax=UINT64_C(0x8899aabbccdd00);
    context void_ctx={0,0,0,0,77U,1};
    if(mx_crt_invoke_init_thunk(&void_call,&memory,MX_CRT_INITTERM,
        UINT64_C(0x1402ab0ec),UINT64_C(0x1402ab0f1),
        0U,synthetic,&void_ctx)!=MX_CRT_BRANCH_BOUNDARY)return 30;
    if(void_call.rax!=UINT64_C(0x8899aabbccdd00) ||
       void_call.rip!=UINT64_C(0x1402ab0f1) ||
       void_call.import_trace!=MX_CRT_INITTERM ||
       void_ctx.previous_kind!=MX_CRT_INITTERM)return 31;

    mx_crt_state fatal={0};
    fatal.rip=UINT64_C(0x1402ab08d);fatal.rsp=UINT64_C(0x500080);
    context fatal_cb={0};
    if(mx_crt_invoke_init_thunk(&fatal,&memory,MX_CRT_AMSG_EXIT,
       UINT64_C(0x1402ab08d),UINT64_C(0x1402ab092),0U,
       synthetic,&fatal_cb)!=MX_CRT_IMPORT_BOUNDARY)return 40;
    if(fatal_cb.times || fatal.rip!=UINT64_C(0x1402ab08d) ||
       fatal.imports || fatal.rax)return 41;

    mx_crt_state invalid={0};
    invalid.rip=UINT64_C(0x1402ab0b6);invalid.rsp=UINT64_C(0x500080);
    if(mx_crt_invoke_init_thunk(&invalid,&memory,999U,
       UINT64_C(0x1402ab0b6),UINT64_C(0x1402ab0bb),0U,
       synthetic,&void_ctx)!=MX_CRT_INVALID)return 50;
    invalid.rsp++;
    if(mx_crt_invoke_init_thunk(&invalid,&memory,MX_CRT_INITTERM_E,
       UINT64_C(0x1402ab0b6),UINT64_C(0x1402ab0bb),0U,
       synthetic,&void_ctx)!=MX_CRT_INVALID)return 51;
    invalid.rsp=UINT64_C(0x500080);
    if(mx_crt_invoke_init_thunk(&invalid,&memory,MX_CRT_INITTERM_E,
       UINT64_C(0x1402ab0b6),UINT64_C(0x1402ab0bc),0U,
       synthetic,&void_ctx)!=MX_CRT_INVALID)return 52;
    invalid.rsp=UINT64_C(0x500800);
    if(mx_crt_invoke_init_thunk(&invalid,&memory,MX_CRT_INITTERM_E,
       UINT64_C(0x1402ab0b6),UINT64_C(0x1402ab0bb),0U,
       synthetic,&void_ctx)!=MX_CRT_MEMORY_FAULT || !invalid.fault)return 53;
    return 0;
}
#ifdef HOST
int main(void){return smoke();}
#endif
"""
class InitImportTests(unittest.TestCase):
    def test_all_import_return_and_refusal_paths(self):
        with tempfile.TemporaryDirectory() as td:
            dir=Path(td)
            path=dir/"test.c";path.write_text(SMOKE)
            host=dir/"host"
            result=subprocess.run(["cc","-std=c11","-O2","-Wall","-Wextra","-Werror",
                "-DHOST","-I"+str(ROOT/"runtime"),str(path),"-o",str(host)],
                capture_output=True,text=True)
            self.assertEqual(result.returncode,0,result.stderr)
            ran=subprocess.run([str(host)],capture_output=True,text=True)
            self.assertEqual(ran.returncode,0,f"native import thunk exit {ran.returncode}: {ran.stderr}")
            arm=dir/"init-arm64.o"
            cross=subprocess.run(["clang","--target=aarch64-unknown-linux-gnu",
                "-ffreestanding","-fno-builtin","-fno-stack-protector",
                "-O2","-std=c11","-Wall","-Wextra","-Werror",
                "-I"+str(ROOT/"runtime"),"-c",str(path),"-o",str(arm)],
                capture_output=True,text=True)
            self.assertEqual(cross.returncode,0,cross.stderr)

if __name__=="__main__":
    unittest.main()
