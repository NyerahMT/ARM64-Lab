"""Run a validated freestanding AArch64 ELF using one persistent Unicorn CPU.

Execution can be paused at a fixed per-call instruction limit and resumed
without resetting registers or memory. Explicit overall budget and timeout.
"""
from pathlib import Path
from elftools.elf.elffile import ELFFile
from unicorn import Uc, UC_ARCH_ARM64, UC_MODE_ARM
from unicorn.arm64_const import UC_ARM64_REG_PC, UC_ARM64_REG_SP, UC_ARM64_REG_LR, UC_ARM64_REG_X0

def execute_arm64_elf(path,instruction_budget=12000000,timeout_us=45000000):
    if not isinstance(instruction_budget,int) or not 1000<=instruction_budget<=24000000:
        raise ValueError("Invalid total instruction budget")
    if not isinstance(timeout_us,int) or not 1000000<=timeout_us<=60000000:
        raise ValueError("Invalid timeout")
    u=Uc(UC_ARCH_ARM64,UC_MODE_ARM)
    mapped=set()
    with Path(path).open("rb") as f:
        elf=ELFFile(f)
        if elf["e_machine"]!="EM_AARCH64":raise ValueError("Expected AArch64 ELF")
        entry=int(elf.header["e_entry"])
        for seg in elf.iter_segments():
            if seg["p_type"]!="PT_LOAD":continue
            addr=int(seg["p_vaddr"]);size=int(seg["p_memsz"])
            if addr<0x10000 or not 0<size<=4*1024*1024:
                raise ValueError("Unexpected program segment")
            for page in range(addr&~4095,(addr+size+4095)&~4095,4096):
                if page not in mapped:
                    u.mem_map(page,4096);mapped.add(page)
            if seg.data():u.mem_write(addr,seg.data())
    if not mapped:raise ValueError("No loadable ELF segments")
    sentinel=0x80020000
    u.mem_map(0x80000000,0x20000)
    u.mem_map(sentinel,4096)
    u.mem_write(sentinel,bytes.fromhex("1f2003d5"))
    u.reg_write(UC_ARM64_REG_SP,0x8001f000)
    u.reg_write(UC_ARM64_REG_LR,sentinel)
    u.reg_write(UC_ARM64_REG_PC,entry)
    steps_left=instruction_budget
    time_left=timeout_us
    slices=0
    while steps_left>0 and time_left>=1000000:
        pc=u.reg_read(UC_ARM64_REG_PC)
        if pc==sentinel:break
        limit=min(steps_left,5000000)
        timeout=min(time_left,15000000)
        u.emu_start(pc,sentinel,count=limit,timeout=timeout)
        steps_left-=limit
        time_left-=timeout
        slices+=1
        if u.reg_read(UC_ARM64_REG_PC)==sentinel:break
    pc=u.reg_read(UC_ARM64_REG_PC)
    rc=u.reg_read(UC_ARM64_REG_X0)
    if pc!=sentinel:raise RuntimeError("AArch64 execution incomplete at "+hex(pc))
    if rc:raise RuntimeError("AArch64 program returned error "+str(rc))
    return {"entry_va":hex(entry),"arm64_smoke_exit":rc,"return_to_sentinel":True,
            "loaded_pages":len(mapped),"same_machine_state":True,"slices":slices}
