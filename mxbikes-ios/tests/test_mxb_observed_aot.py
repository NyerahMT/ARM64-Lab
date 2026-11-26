"""Compile the actual generated dispatcher with the portable native runtime."""
import importlib.util
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/"scripts"))
import mxb_demo_auto_translate as auto

class ObservedAOTTests(unittest.TestCase):
    def build_and_run(self,arm64=False,native_imports=False,graphics=False):
        if importlib.util.find_spec("ziglang") is not None:
            cc=[sys.executable,"-m","ziglang","cc"]
        elif shutil.which("clang") or shutil.which("gcc"):
            cc=[shutil.which("clang") or shutil.which("gcc")]
        else:self.skipTest("host C compiler unavailable")
        # Synthetic, fully specified x64 instructions only; no game bytes.
        ins={
            0x1000:(bytes.fromhex("b878563412"),"mov","eax, 0x12345678"),
            0x1005:(bytes.fromhex("8901"),"mov","dword ptr [rcx], eax"),
            0x1007:(bytes.fromhex("e8f40f0000"),"call","0x2000"),
            0x100c:(bytes.fromhex("8b11"),"mov","edx, dword ptr [rcx]"),
            0x100e:(bytes.fromhex("90"),"nop",""),
        }
        if native_imports:
            ins={
                0x1000:(bytes.fromhex("b900300000"),"mov","ecx, 0x3000"),
                0x1005:(bytes.fromhex("e8f60f0000"),"call","0x2000"),
                0x100a:(bytes.fromhex("e801100000"),"call","0x2010"),
                0x100f:(bytes.fromhex("90"),"nop",""),
            }
        if graphics:
            ins={};pc=0x1000
            for value,token in ((4,0x2000),(0x3000,0x2010),(0x300c,0x2010),(0x3018,0x2010),(None,0x2020)):
                if value is not None:
                    ins[pc]=(b'\xb9'+value.to_bytes(4,'little'),'mov',f'ecx, {value:#x}');pc+=5
                ins[pc]=(b'\xe8'+(token-pc-5).to_bytes(4,'little',signed=True),'call',f'{token:#x}');pc+=5
            assert pc==0x102d
        shards,dispatcher=auto.generate_shards(ins,set(ins),2)
        self.assertEqual(len(shards),5 if graphics else 2 if native_imports else 3)
        extras=[]
        if native_imports or graphics:
            extras=[str(ROOT/"runtime"/name) for name in (
                "mxb_observed_imports.c","mxb_observed_session.c","mxb_standalone_crt.c","mxb_standalone_platform.c",
                "mxb_standalone_imports.c","mxb_standalone_heap.c","mxb_standalone_memory.c",
                "mxb_standalone_winsock.c","mxb_standalone_format.c","mxb_standalone_files.c")]
        if graphics:extras.extend(str(ROOT/"runtime"/name) for name in ("mxb_observed_graphics.c","mxb_gl_surface.c","mxb_gl_win64_abi.c"))
        fixture="mxb_observed_graphics_smoke.c" if graphics else "mxb_observed_imports_smoke.c" if native_imports else "mxb_observed_aot_smoke.c"
        with tempfile.TemporaryDirectory() as temp:
            folder=Path(temp)
            sources=[]
            for i,source in enumerate([*shards,dispatcher]):
                p=folder/f"unit-{i}.c"
                p.write_text(source,encoding="utf-8")
                sources.append(str(p))
            exe=folder/("smoke.exe" if os.name=="nt" else "smoke")
            target=["-target","aarch64-linux-musl","-ffreestanding","-fno-builtin","-fno-stack-protector","-nostdlib","-static","-Wl,-e,main","-Wl,-z,max-page-size=4096","-DMXB_FREESTANDING_SMOKE"] if arm64 else []
            if arm64 and importlib.util.find_spec("ziglang") is None:self.skipTest("Zig ARM64 cross-compiler unavailable")
            subprocess.run([*cc,*target,"-std=c11","-O2","-Wall","-Wextra","-Werror",
                            "-Wno-unused-function","-DMXB_USE_OBSERVED_RUNTIME_ABI",
                            "-I",str(ROOT/"runtime"),*sources,
                            str(ROOT/"runtime/mxb_observed_runtime.c"),
                            str(ROOT/"runtime/mxb_observed_memory.c"),
                            *extras,str(ROOT/"tests"/fixture),
                            *([] if arm64 or os.name=="nt" else ["-lm"]),"-o",str(exe)],check=True)
            if arm64:self.run_elf(exe)
            else:subprocess.run([str(exe)],check=True)

    def test_generated_dispatch_runtime(self):
        self.build_and_run()

    def test_generated_arm64_runtime(self):
        if importlib.util.find_spec("unicorn") is None or importlib.util.find_spec("elftools") is None:
            self.skipTest("ARM64 execution dependencies unavailable")
        self.build_and_run(arm64=True)

    def test_native_import_services_host(self):
        self.build_and_run(native_imports=True)

    def test_native_import_services_arm64(self):
        if importlib.util.find_spec("unicorn") is None or importlib.util.find_spec("elftools") is None:
            self.skipTest("ARM64 execution dependencies unavailable")
        self.build_and_run(arm64=True,native_imports=True)

    def test_translated_graphics_bridge_host(self):
        self.build_and_run(graphics=True)

    def run_elf(self,exe):
        from elftools.elf.elffile import ELFFile
        from unicorn import Uc, UC_ARCH_ARM64, UC_MODE_ARM
        from unicorn.arm64_const import UC_ARM64_REG_SP,UC_ARM64_REG_LR,UC_ARM64_REG_PC,UC_ARM64_REG_X0
        u=Uc(UC_ARCH_ARM64,UC_MODE_ARM);pages=set()
        with exe.open("rb") as f:
            ef=ELFFile(f)
            self.assertEqual(ef["e_machine"],"EM_AARCH64")
            entry=ef["e_entry"]
            for seg in ef.iter_segments():
                if seg["p_type"]!="PT_LOAD":continue
                va=int(seg["p_vaddr"]);n=int(seg["p_memsz"])
                self.assertLessEqual(n,8*1024*1024)
                for p in range(va&~4095,(va+n+4095)&~4095,4096):
                    if p not in pages:u.mem_map(p,4096);pages.add(p)
                if seg["p_filesz"]:u.mem_write(va,seg.data())
        stack=0x80000000;end=stack+0x20000
        u.mem_map(stack,0x21000)
        u.reg_write(UC_ARM64_REG_SP,end-16);u.reg_write(UC_ARM64_REG_LR,end)
        u.emu_start(entry,end,count=2_000_000)
        self.assertEqual(u.reg_read(UC_ARM64_REG_PC),end)
        self.assertEqual(u.reg_read(UC_ARM64_REG_X0),0)

if __name__=="__main__":unittest.main()
