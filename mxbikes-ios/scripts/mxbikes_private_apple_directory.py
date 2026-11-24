"""Prepare the optional owned-image directory module in an ignored build directory."""
import argparse
import struct
from pathlib import Path

from mxbikes_native_cfg_lift import (
    EXTRA, FILENAME_GLOBAL, MEMORY_RUNTIME, RSP, STACK, decode_cfg, owned_filename_input, u,
)
from tools.pe_probe import PE


def prepare(executable, destination):
    windows, entry, stop, _, imports, iat = owned_filename_input(executable)
    pe = PE(executable)
    base = pe.u64(pe.opt + 24)
    # The mapped file still contains the on-disk import names. Resolve each
    # known slot to its typed adapter only while its original value matches.
    on_disk = {slot: struct.unpack("<Q", pe.read_rva(slot-base, 8))[0] for slot in iat}
    code, _, _ = decode_cfg(windows, entry, stop, imports, iat, disk_imports=on_disk)
    wrapper = r"""
#include "mxb_owned_directory.h"
int mxb_private_directory(MXBGuestMemory *image, const char *path, char *out, size_t capacity){
    if(!image || !path || !out || !capacity)return 0;
    size_t length=0;
    while(length<260 && path[length])length++;
    if(length==260)return 0;
    State state={0};
    state.memory=*image;
    uint8_t stack[4096]={0};
    if(!mxb_guest_map(&state.memory,STACK,stack,sizeof(stack),MXB_MEM_READ|MXB_MEM_WRITE) ||
       !mxb_guest_write(&state.memory,RSP+0x140,path,length+1))return 0;
    state.r[MXB_RSP]=RSP;
    state.flags=0x202;
    Cursor cursor=lifted_begin();
    int rc;
    do { rc=lifted_resume(&state,&cursor,64); } while(rc==MXB_NATIVE_YIELD);
    if(rc || cursor.pc!=STOP || state.r[MXB_RSP]!=RSP || state.r[MXB_RAX]!=GLOBAL)return 0;
    char result[262];
    for(size_t i=0;i<sizeof(result) && i<capacity;i++){
        if(!mxb_guest_read(&state.memory,GLOBAL+i,result+i,1))return 0;
        if(!result[i]){
            for(size_t j=0;j<=i;j++)out[j]=result[j];
            return 1;
        }
    }
    return 0;
}
"""
    # Substitute delimiters rather than substrings of register names.
    import re
    constants = {"STACK":STACK,"RSP":RSP,"STOP":stop,"GLOBAL":FILENAME_GLOBAL}
    wrapper = re.sub(r"\b(STACK|RSP|STOP|GLOBAL)\b", lambda m: u(constants[m[0]]), wrapper)
    destination.mkdir(parents=True, exist_ok=True)
    (destination/"mxb_private_directory.c").write_text(MEMORY_RUNTIME+EXTRA+code+wrapper)


if __name__=="__main__":
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--owned-exe",required=True,type=Path)
    args=parser.parse_args()
    from mxbikes_private_apple_startup import prepare_startup
    destination=Path(__file__).resolve().parents[1]/"runtime"/"private"
    prepare(args.owned_exe,destination)
    prepare_startup(args.owned_exe,destination)
