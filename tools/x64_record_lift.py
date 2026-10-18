"""Strict, fail-closed x64 indexed-record writer -> portable C pattern lifter.

This recognizes ONE bounded instruction pattern from a genuine unwind-backed
MX Bikes routine. Unlike the SSE lifter, it models indexed integer stores,
64-bit addressing, Win64 stack-passed arguments, and a global counter.

The generated C is only equivalent for a bounded nonnegative counter range
whose complete record array is supplied by the caller; there is no general
guest virtual-memory manager, Win64 ABI machinery, or control-flow handling.
"""
import re
from capstone import Cs,CS_ARCH_X86,CS_MODE_64
from capstone.x86 import X86_OP_MEM,X86_OP_REG


class UnsupportedRecordWriter(ValueError):
    pass


def _rip_address(ins, operand):
    if operand.type!=X86_OP_MEM or ins.reg_name(operand.mem.base)!="rip" or operand.mem.index:
        raise UnsupportedRecordWriter("Expected RIP-relative 64-bit guest global")
    return ins.address+ins.size+operand.mem.disp


def lift_indexed_record_writer(code:bytes,start_rva:int,max_records:int=8):
    if not isinstance(code,bytes) or not (1<=len(code)<=256):
        raise UnsupportedRecordWriter("Unsupported original function size")
    if not (1<=max_records<=128):
        raise UnsupportedRecordWriter("Unsafe record bounds")
    md=Cs(CS_ARCH_X86,CS_MODE_64)
    md.detail=True
    ins=list(md.disasm(code,start_rva))
    mn=[i.mnemonic for i in ins]
    expected=["mov","movsxd","mov","lea","lea","inc","mov","mov","mov",
              "mov","mov","mov","mov","mov","mov","xor","ret"]
    if mn!=expected or sum(i.size for i in ins)!=len(code):
        raise UnsupportedRecordWriter("Not the specific 17-instruction indexed writer")
    # Verify every non-RIP instruction for exact register and addressing shape.
    fixed={
        0:"qword ptr [rsp + 8], rbx",
        2:"eax, dword ptr [rsp + 0x28]",
        4:"r10, [r11 + r11*8]",
        5:"r11d",
        6:"dword ptr [rbx + r10*8], edx",
        7:"dword ptr [rbx + r10*8 + 4], r8d",
        8:"dword ptr [rbx + r10*8 + 8], r9d",
        9:"dword ptr [rbx + r10*8 + 0xc], eax",
        10:"eax, dword ptr [rsp + 0x30]",
        12:"dword ptr [rbx + r10*8 + 0x10], eax",
        13:"rbx, qword ptr [rsp + 8]",
        14:"dword ptr [rcx], r11d",
        15:"eax, eax",
        16:"",
    }
    for ix,operands in fixed.items():
        if ins[ix].op_str!=operands:
            raise UnsupportedRecordWriter(f"Unexpected addressing or register shape at instruction {ix}")
    if ins[1].reg_name(ins[1].operands[0].reg)!="r11" or ins[3].reg_name(ins[3].operands[0].reg)!="rbx":
        raise UnsupportedRecordWriter("Incorrect global register setup")
    if len(ins[11].operands)!=2 or ins[11].reg_name(ins[11].operands[1].reg)!="r11d":
        raise UnsupportedRecordWriter("Incorrect global counter store")
    count_read=_rip_address(ins[1],ins[1].operands[1])
    array_base=_rip_address(ins[3],ins[3].operands[1])
    count_written=_rip_address(ins[11],ins[11].operands[0])
    if count_read!=count_written or array_base-count_read!=16:
        raise UnsupportedRecordWriter("Different global locations or stride than expected")
    # Derive target write displacements from decoded operands, not source bytes.
    offsets=[]
    for ix in (6,7,8,9,12):
        dst=ins[ix].operands[0]
        if dst.type!=X86_OP_MEM or ins[ix].reg_name(dst.mem.base)!="rbx" or ins[ix].reg_name(dst.mem.index)!="r10" or dst.mem.scale!=8:
            raise UnsupportedRecordWriter("Unexpected indexed store address")
        offsets.append(dst.mem.disp)
    if offsets!=[0,4,8,12,16]:
        raise UnsupportedRecordWriter("Unexpected record field layout")
    # Eight-byte scale of R10, where R10=(R11+R11*8), yields a 72-byte stride.
    codegen=[
        "#include <stdint.h>\n",
        "/* bounded domain: 0 <= *counter < max_records; all pointers valid */\n",
        "uint32_t lifted_record(uint32_t *dst,uint32_t *counter,uint8_t *records,",
        "uint32_t a,uint32_t b,uint32_t c,uint32_t d,uint32_t e){\n",
        "    if(!dst || !counter || !records) return UINT32_MAX;\n",
        "    int64_t index=(int32_t)(*counter);\n",
        f"    if(index<0 || index>={max_records}) return UINT32_MAX;\n",
        "    uint64_t base=(uint64_t)index*72ULL;\n",
    ]
    for value,off in zip("abcde",offsets):
        # Compiler-generated str/ldr, avoids host and guest alignment assumptions.
        codegen.append(f"    __builtin_memcpy(records+base+{off},&{value},4);\n")
        if off==12:
            codegen.append("    *counter=(uint32_t)index+1U;\n")
    codegen+=["    *dst=(uint32_t)index+1U;\n",
              "    return 0;\n}\n"]
    return "".join(codegen),{
        "start_rva":hex(start_rva),
        "original_instruction_count":len(ins),
        "count_global_rva":hex(count_read),
        "array_global_rva":hex(array_base),
        "record_stride_bytes":72,
        "written_field_offsets":offsets,
        "bounded_counter_count":max_records,
        "scope":"One unwind-backed indexed-record writer pattern; no branches or arbitrary memory"
    }
