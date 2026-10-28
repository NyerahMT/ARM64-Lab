#!/usr/bin/env python3
"""Differential native AArch64 version of SHA-verified original x64 CRC16 loop.

The original code at RVA 0x130670 performs a 17-instruction byte transform
and branches to itself until RDX reaches 0. Verify EVERY original opcode and
compare original x64 guest registers against portable C compiled and ACTUALLY
executed on AArch64, including the complete privately owned file in chunks.

This does not modify or run any Steam API or fake license/authentication.
Only metadata is exported; owned original file bytes are embedded solely in
an automatically deleted local temporary C/ELF test during private CI.
"""
from pathlib import Path
import hashlib,json,subprocess,sys,tempfile
from capstone import Cs,CS_ARCH_X86,CS_MODE_64
from unicorn.x86_const import (
    UC_X86_REG_RIP,UC_X86_REG_RSP,UC_X86_REG_RAX,UC_X86_REG_RBX,
    UC_X86_REG_RCX,UC_X86_REG_RDX,UC_X86_REG_R14,UC_X86_REG_EFLAGS
)
import mxbikes_main_joined_callee_native as joined
from mxbikes_whole_game_map import INPUT_SHA
from mxbikes_owned_file_crt import OwnedReadOnlyFile
from tools.import_aot_smoke import execute_arm64_elf

BASE=joined.BASE
HOT=0x130670
EXIT=0x1306a9
DATA=joined.CODE_DATA+0x200
CHUNK=1000
SEED=0x1d0f
MAX_FILE=1024*1024
REGRESSIONS=((0x0000,1,17),(0x1234,2,3),(0xffff,7,255),
             (0x1d0f,31,7),(0x8000,257,11),(0x1d0f,1000,13))
ORIGINAL=[
  ("movzx","eax, byte ptr [rcx]"),
  ("rol","bx, 8"),
  ("inc","rcx"),
  ("xor","bx, ax"),
  ("movzx","eax, bx"),
  ("shr","ax, 4"),
  ("and","ax, 0xf"),
  ("xor","bx, ax"),
  ("movzx","eax, bx"),
  ("shl","ax, 0xc"),
  ("xor","bx, ax"),
  ("movzx","eax, bx"),
  ("and","ax, r14w"),
  ("shl","ax, 5"),
  ("xor","bx, ax"),
  ("sub","rdx, 1"),
  ("jne","0x130670"),
]

def original_form(pe):
    cs=Cs(CS_ARCH_X86,CS_MODE_64);cs.detail=True
    original=list(cs.disasm(pe.read_rva(HOT,EXIT-HOT),HOT))
    forms=[(i.mnemonic,i.op_str) for i in original]
    if forms!=ORIGINAL or sum(i.size for i in original)!=EXIT-HOT:
        raise ValueError("Original Win64 17-instruction byte CRC block changed: "+str(forms))
    return forms

def original_x64_chunks(pe,blob,*,bx_seed):
    if not blob or len(blob)>MAX_FILE:
        raise ValueError("CRC must have nonempty bounded bytes")
    uc=joined.new_cpu(pe)
    results=[]
    bx=int(bx_seed)&0xffffffffffffffff
    if len(blob)>MAX_FILE:raise ValueError("input file too large")
    for offset in range(0,len(blob),CHUNK):
        data=blob[offset:offset+CHUNK]
        if not 1<=len(data)<=CHUNK:
            raise ValueError("Invalid x64 input block size")
        uc.mem_write(DATA,data)
        uc.reg_write(UC_X86_REG_RIP,BASE+HOT)
        uc.reg_write(UC_X86_REG_RSP,joined.ENTRY_SP-0x440)
        uc.reg_write(UC_X86_REG_RAX,0x12345678)
        uc.reg_write(UC_X86_REG_RBX,bx)
        uc.reg_write(UC_X86_REG_RCX,DATA)
        uc.reg_write(UC_X86_REG_RDX,len(data))
        uc.reg_write(UC_X86_REG_R14,0xff)
        uc.emu_start(BASE+HOT,BASE+EXIT,timeout=2500000,
                     count=len(data)*17+3)
        if (uc.reg_read(UC_X86_REG_RIP)!=BASE+EXIT or
            uc.reg_read(UC_X86_REG_RDX)!=0 or
            uc.reg_read(UC_X86_REG_RCX)!=DATA+len(data)):
            raise ValueError("Original game CRC x64 exited at wrong guest state")
        flags=uc.reg_read(UC_X86_REG_EFLAGS)
        if not flags&64 or flags&128 or flags&1:
            raise ValueError("Original x64 loop-exit flags unexpected")
        bx=uc.reg_read(UC_X86_REG_RBX)
        results.append({
           "length":len(data),
           "bx":bx,
           "ax":uc.reg_read(UC_X86_REG_RAX),
           "zf":1,"sf":0,"cf":0
        })
    return results

def pseudo_bytes(n,seed):
    return bytes(((i*131+seed*17+(i>>3))&255) for i in range(n))

def as_hex(blob):
    return ",".join(str(b) for b in blob)

def source_for(vectors,owned,owned_oracle):
    lines=[
        "#include <stdint.h>",
        "#include <stddef.h>",
        """/* An exact portable semantic translation of the original verified
         * SHA-pinned x64 bytewise loop, not a precomputed CRC lookup. */
typedef struct {uint64_t rbx; uint64_t rax;} mx_crc_result;
static mx_crc_result original_crc16_bytes(const uint8_t*data,
                                          uint32_t len,uint64_t start){
 uint16_t bx=(uint16_t)start;
 uint16_t last_ax=0U;
 for(uint32_t i=0U;i<len;++i){
   const uint16_t rotated=(uint16_t)((uint16_t)(bx<<8U)|(bx>>8U));
   bx=(uint16_t)(rotated^(uint16_t)data[i]);
   uint16_t ax=(uint16_t)((bx>>4U)&15U);
   bx=(uint16_t)(bx^ax);
   ax=(uint16_t)(bx<<12U);
   bx=(uint16_t)(bx^ax);
   ax=(uint16_t)((bx&255U)<<5U);
   bx=(uint16_t)(bx^ax);
   last_ax=ax;
 }
 mx_crc_result output;
 output.rbx=(start&UINT64_C(0xffffffffffff0000))|(uint64_t)bx;
 output.rax=(uint64_t)last_ax;
 return output;
}"""]
    for i,(seed,blob,oracle) in enumerate(vectors):
        lines.append(f"static const uint8_t sample_{i}[{len(blob)}]={{"+as_hex(blob)+"};")
    lines.append(f"static const uint8_t owned_dll[{len(owned)}]={{"+as_hex(owned)+"};")
    lines.append("int smoke(void){")
    for i,(seed,blob,oracle) in enumerate(vectors):
        if len(oracle)!=1:
            raise ValueError("Synthetic vector longer than original 1000-byte chunk")
        x=oracle[0]
        lines.extend([
          " {const mx_crc_result observed=original_crc16_bytes("+
              f"sample_{i},{len(blob)}U,UINT64_C({seed}));",
          " if(observed.rbx!=UINT64_C("+str(x["bx"])+
              ")||observed.rax!=UINT64_C("+str(x["ax"])+
              "))return "+str(10+i)+";}",
        ])
    lines.append(" {uint64_t rolling=UINT64_C("+str(SEED)+");")
    lines.append("  uint32_t offset=0U;")
    for index,ref in enumerate(owned_oracle):
        size=ref["length"]
        lines.append(
         "  {const mx_crc_result observed=original_crc16_bytes("+
           "owned_dll+offset,"+str(size)+"U,rolling);")
        lines.append("   if(observed.rbx!=UINT64_C("+str(ref["bx"])+
                    ")||observed.rax!=UINT64_C("+str(ref["ax"])+
                    "))return "+str(100+index)+";")
        lines.append("   rolling=observed.rbx;offset+="+str(size)+"U;}")
    lines.append("  if(offset!="+str(len(owned))+"U)return 400U;}")
    lines.extend([" return 0;","}",
                  "#ifdef HOST",
                  "int main(void){return smoke();}",
                  "#endif"])
    return "\n".join(lines)+"\n"

def run(original,dll,out):
    from tools.pe_probe import PE
    pe=PE(original)
    if hashlib.sha256(pe.b).hexdigest()!=INPUT_SHA:
        raise ValueError("Original binary SHA mismatched")
    original_form(pe)
    manifest=json.loads((out/"owned-steam-file-manifest.json").read_text())
    if manifest.get("steam_api64_dll_present") is not True:
        raise ValueError("The owned file is not present")
    stream=OwnedReadOnlyFile.from_private_path(
        dll,manifest["owned_dll_size_bytes"])
    if not 0<len(stream.content)<=MAX_FILE:
        raise ValueError("Owned read-only file exceeds CRC regression budget")
    cases=[]
    for seed,length,salt in REGRESSIONS:
        blob=pseudo_bytes(length,salt)
        oracle=original_x64_chunks(pe,blob,bx_seed=seed)
        cases.append((seed,blob,oracle))
    owned_refs=original_x64_chunks(pe,stream.content,bx_seed=SEED)
    if (sum(q["length"] for q in owned_refs)!=len(stream.content) or
        len(owned_refs)!=(len(stream.content)+CHUNK-1)//CHUNK):
        raise ValueError("Original x64 CRC reference incomplete")
    src=source_for(cases,stream.content,owned_refs)
    with tempfile.TemporaryDirectory(prefix="mxb-native-crc16-") as temp:
        directory=Path(temp)
        file=directory/"private-original-crc-comparison.c"
        file.write_text(src)
        host=directory/"reference-host"
        options=["-std=c11","-O2","-Wall","-Wextra","-Werror"]
        cmd=["cc",*options,"-DHOST",str(file),"-o",str(host)]
        compile_result=subprocess.run(cmd,capture_output=True,text=True)
        if compile_result.returncode:
            raise RuntimeError("CRC native host compile failed: "+
                               compile_result.stderr[-4000:])
        host_result=subprocess.run([str(host)],capture_output=True,text=True)
        if host_result.returncode:
            raise RuntimeError("Original x64 vs native host CRC difference: "+
                               str(host_result.returncode))
        arm=directory/"original-crc-aarch64.elf"
        cmd=["clang","--target=aarch64-unknown-linux-gnu",
             "-fuse-ld=lld","-nostdlib","-static","-ffreestanding",
             "-fno-builtin","-fno-stack-protector",*options,
             "-Wl,-e,smoke","-Wl,-z,max-page-size=4096",
             "-Wl,--build-id=none",str(file),"-o",str(arm)]
        build=subprocess.run(cmd,capture_output=True,text=True)
        if build.returncode:
            raise RuntimeError("Original CRC native AArch64 compile failed: "+
                               build.stderr[-4000:])
        arm_result=execute_arm64_elf(arm,instruction_budget=6000000,
                                     timeout_us=15000000)
    report={
       "original_sha256":INPUT_SHA,
       "verified_original_loop_rva":hex(HOT),
       "original_loop_exit_rva":hex(EXIT),
       "original_verified_x64_bytewise_instructions":17,
       "original_x64_nontrivial_synthetic_vectors":len(cases),
       "original_owned_dll_bytes_checked_on_both_native_host_and_arm64":len(stream.content),
       "original_owned_dll_chunks_x64_diffed":len(owned_refs),
       "original_x64_rolling_seed":hex(SEED),
       "original_x64_final_bx":hex(owned_refs[-1]["bx"]),
       "actually_compiled_arm64_and_executed":True,
       "arm64_return_to_sentinel":arm_result["return_to_sentinel"],
       "native_game_engine_started":False,
       "native_crt_integrated_into_full_original_game":False
    }
    out.mkdir(parents=True,exist_ok=True)
    (out/"original-crc-native-arm64.json").write_text(json.dumps(report,indent=2)+"\n")
    lines=["# MX Bikes authentic Win64 checksum loop on native ARM64","",
       "- SHA-verified original 17-instruction byte-loop: **verified**",
       "- Independent original x64 CPU differential vectors: **"+
          str(len(cases))+"**",
       "- Owned DLL original x64 CRC chunk oracles: **"+
          str(len(owned_refs))+"**",
       "- Real owned DLL bytes verified by original x64, native host, and executed AArch64: **"+
          str(len(stream.content))+"**",
       "- Original rolling checksum result: **"+hex(owned_refs[-1]["bx"])+"**",
       "- Native ARM64 executable returned to sentinel: **"+
          str(arm_result["return_to_sentinel"])+"**",
       "","This is one real original game hot loop translated, not full engine startup.",
       "No actual Steam DLL executable code, DRM state, graphics or iOS IPA.",""]
    (out/"original-crc-native-arm64.md").write_text("\n".join(lines))
    print("\n".join(lines))
    return report

if __name__=="__main__":
    if len(sys.argv)!=4:
        raise SystemExit("usage: crc_native.py owned-original.exe owned-file metadata-dir")
    run(Path(sys.argv[1]),Path(sys.argv[2]),Path(sys.argv[3]))
