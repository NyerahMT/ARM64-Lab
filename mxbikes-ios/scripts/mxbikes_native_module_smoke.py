#!/usr/bin/env python3
"""Compile/link/execute the standalone generated module, not a duplicate lifter."""
from mxbikes_native_slice_lift import compile_native
if __name__=="__main__":
    src=r'''
#include "mxb_native_exec.h"
int smoke(void){return mxb_native_probe_smoke()?0:1;}
#ifdef HOST
int main(void){return smoke();}
#endif
'''
    compile_native(src,("mxb_guest_memory.c","mxb_guest_crt.c","mxb_pe_guest_image.c",
                        "generated/mxb_native_probe.c","mxb_native_probe_smoke.c"))
    print("PASS: actual generated synthetic native module linked against shared memory, CRT and PE loader on host/ARM64")
