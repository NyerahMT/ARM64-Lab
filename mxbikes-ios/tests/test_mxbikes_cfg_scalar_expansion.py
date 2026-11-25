"""Synthetic x64 fixtures for indexed LEA and narrow guest-memory forms."""
from pathlib import Path
import sys
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"scripts"))
import mxbikes_cfg_full_native_wave as cfg

FORMS=[
    ("lea_indexed", "488d448b20c3"), # lea rax,[rbx+rcx*4+32]
    ("lea_index_only", "488d048d00000000c3"), # lea rax,[rcx*4]
    ("lea32_indexed", "8d448bf0c3"),
    ("movzx_byte", "0fb64301c3"),
    ("movzx_word", "480fb74302c3"),
    ("cmp_reg_mem32", "3b037406b801000000c3b802000000c3"),
    ("cmp_reg_mem64", "483b037406b801000000c3b802000000c3"),
    ("cmp_byte_imm", "807b01007406b801000000c3b802000000c3"),
    ("cmp_word_imm", "66817b02ffff7406b801000000c3b802000000c3"),
    ("mov_mem_byte_imm", "c643057fc3"),
    ("mov_mem_word_imm", "66c743067856c3"),
    ("movaps_stack_save_restore", "0f297424080f57f60f28742408c3"),
    ("movaps_heap_roundtrip", "0f29030f280bc3"),
    ("movups_unaligned_heap", "0f114b010f105301c3"),
    ("movss_heap_load", "f30f104304c3"),
    ("movsd_heap_load", "f20f107308c3"),
    ("movss_register", "f30f10c1c3"),
    ("movsd_register", "f20f10f7c3"),
    ("movss_heap_store", "f30f114304c3"),
    ("movsd_heap_store", "f20f117308c3"),
    ("pxor_high_register", "66450fefe5c3"),
    ("xorpd_register", "660f57c1c3"),
    ("movsd_static", "f20f100508000000c3"),

]

class Fixture:
    def __init__(self,rva,blob):
        self.rva=rva
        self.blob=blob+b"\xcc"*32
    def read_rva(self,offset,length):
        start=offset-self.rva
        if start<0 or start+length>len(self.blob):
            raise ValueError("outside fixture")
        return self.blob[start:start+length]

def prepare():
    plans=[]
    references={}
    for i,(name,body) in enumerate(FORMS):
        rva=0x240000+0x100*i
        pe=Fixture(rva,bytes.fromhex(body))
        plan,error=cfg.recover_cfg(pe,rva,{rva},require_branch=False)
        if error or not plan:
            raise RuntimeError(name+": "+str(error))
        refs=[]
        for case in range(cfg.CASES):
            result,error=cfg.x64_reference(pe,plan,case)
            if error:
                raise RuntimeError(name+": "+str(error))
            refs.append(result)
        plans.append(plan)
        references[rva]=refs
    return plans,references

if __name__=="__main__":
    plans,refs=prepare()
    for i in range(0,len(plans),4):
        cfg.compile_batch(plans[i:i+4],refs)
    print("Scalar and SIMD expansion x64 / native / ARM64 fixtures passed:",len(plans)*cfg.CASES)
