"""Fail-closed native boot gate tests, no imitation game boot."""
from pathlib import Path
import sys
import unittest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"scripts"))
import mxbikes_first_launch_probe as probe
from mxbikes_whole_game_map import INPUT_SHA,ENTRY_RVA,CRT_RVA,MAIN_RVA

def fixed_map():
    return {
        "input_sha256":INPUT_SHA,"original_file_verified":True,
        "direct_call_graph":{hex(MAIN_RVA):["0x136120","0x136130"]},
    }

def proved(rva):
    return {
        "original_rva":hex(rva),
        "full_function_behavior_verified":True,
        "win64_guest_call_abi_verified":True,
        "code_presence":"ephemeral_ci_elf_only",
        "differential_test_run_url":
            "https://github.com/NyerahMT/ReflexBuildInput/actions/runs/40149128729",
    }

class FirstStartupProbeTests(unittest.TestCase):
    def test_crt_strlen_strchr_strcmp_batch_uses_only_bounded_guest_strings(self):
        from unicorn import Uc,UC_ARCH_X86,UC_MODE_64
        from unicorn.x86_const import UC_X86_REG_RAX
        from mxbikes_win64_string_api import (
            model_guest_strlen,model_guest_strchr,model_guest_strcmp)
        uc=Uc(UC_ARCH_X86,UC_MODE_64)
        base=0x711100000
        uc.mem_map(base,4096)
        uc.mem_write(base,b"mxbikes.exe\x00")
        uc.mem_write(base+64,b"mxbikes.exf\x00")
        uc.mem_write(base+128,b"mxbikes.exe\x00")
        allowed=[(base,base+4096)]
        self.assertTrue(model_guest_strlen(uc,base,readable_ranges=allowed))
        self.assertEqual(uc.reg_read(UC_X86_REG_RAX),11)
        self.assertTrue(model_guest_strchr(uc,base,ord("."),
            readable_ranges=allowed))
        self.assertEqual(uc.reg_read(UC_X86_REG_RAX),base+7)
        self.assertTrue(model_guest_strchr(uc,base,ord("#"),
            readable_ranges=allowed))
        self.assertEqual(uc.reg_read(UC_X86_REG_RAX),0)
        self.assertTrue(model_guest_strcmp(uc,base,base+128,
            readable_ranges=allowed))
        self.assertEqual(uc.reg_read(UC_X86_REG_RAX),0)
        self.assertTrue(model_guest_strcmp(uc,base,base+64,
            readable_ranges=allowed))
        self.assertEqual(uc.reg_read(UC_X86_REG_RAX),(-1)&0xffffffff)
        self.assertTrue(model_guest_strcmp(uc,base+64,base,
            readable_ranges=allowed))
        self.assertEqual(uc.reg_read(UC_X86_REG_RAX),1)
        self.assertFalse(model_guest_strlen(uc,base+4096,
            readable_ranges=allowed))
        self.assertFalse(model_guest_strcmp(uc,base,0x1000,
            readable_ranges=allowed))

    def test_win64_crt_strrchr_includes_terminator_and_last_matching_character(self):
        from unicorn import Uc,UC_ARCH_X86,UC_MODE_64
        from unicorn.x86_const import UC_X86_REG_RAX
        from mxbikes_win64_string_api import model_guest_strrchr
        uc=Uc(UC_ARCH_X86,UC_MODE_64)
        addr=0x711000000
        uc.mem_map(addr,4096)
        uc.mem_write(addr,b"foo/bar/baz\x00")
        allowed=[(addr,addr+4096)]
        for ch,offset in ((ord("/"),7),(ord("a"),9),(0,11)):
            self.assertTrue(model_guest_strrchr(uc,addr,ch,
                readable_ranges=allowed))
            self.assertEqual(uc.reg_read(UC_X86_REG_RAX),addr+offset)
        self.assertTrue(model_guest_strrchr(uc,addr,ord("z")+256,
            readable_ranges=allowed))
        self.assertEqual(uc.reg_read(UC_X86_REG_RAX),addr+10)
        self.assertTrue(model_guest_strrchr(uc,addr,ord("$"),
            readable_ranges=allowed))
        self.assertEqual(uc.reg_read(UC_X86_REG_RAX),0)
        self.assertFalse(model_guest_strrchr(uc,0x1000,ord("/"),
            readable_ranges=allowed))
        self.assertFalse(model_guest_strrchr(uc,addr,ord("/"),
            readable_ranges=allowed,max_bytes=3))
        self.assertEqual(uc.reg_read(UC_X86_REG_RAX),0)

    def test_original_crt_strcpy_is_bounded_and_returns_guest_destination(self):
        from unicorn import Uc,UC_ARCH_X86,UC_MODE_64
        from unicorn.x86_const import UC_X86_REG_RAX
        from mxbikes_win64_string_api import model_guest_strcpy
        uc=Uc(UC_ARCH_X86,UC_MODE_64)
        src=0x710000000
        dst=0x710010000
        uc.mem_map(src,4096)
        uc.mem_map(dst,4096)
        uc.mem_write(src,b"MX Bikes\x00"+b"A"*32)
        kwargs={"readable_ranges":[(src,src+4096)],
                "writable_ranges":[(dst,dst+4096)]}
        self.assertTrue(model_guest_strcpy(uc,dst+16,src,**kwargs))
        self.assertEqual(bytes(uc.mem_read(dst+16,9)),b"MX Bikes\x00")
        self.assertEqual(uc.reg_read(UC_X86_REG_RAX),dst+16)
        self.assertFalse(model_guest_strcpy(uc,dst+4090,src,**kwargs))
        self.assertFalse(model_guest_strcpy(uc,src+1,src,
            readable_ranges=[(src,src+4096)],
            writable_ranges=[(src,src+4096)]))
        self.assertFalse(model_guest_strcpy(uc,dst,src+2,
            readable_ranges=[(src,src+4)],writable_ranges=[(dst,dst+4096)]))
        self.assertFalse(model_guest_strcpy(uc,dst,0x1000,**kwargs))
        self.assertFalse(model_guest_strcpy(uc,dst,src,max_bytes=3,**kwargs))
        self.assertEqual(uc.reg_read(UC_X86_REG_RAX),dst+16)

    def test_real_steamworks_launch_import_requires_authorized_external_runtime(self):
        self.assertTrue(probe.external_steamworks_launch_service(
            "steam_api64.dll","SteamAPI_RestartAppIfNecessary"))
        self.assertTrue(probe.external_steamworks_launch_service(
            "steam_api64.dll","SteamAPI_Init"))
        self.assertFalse(probe.external_steamworks_launch_service(
            "kernel32.dll","GetModuleFileNameA"))
        self.assertFalse(probe.external_steamworks_launch_service(
            "MSVCR90.dll","fopen"))

    def test_genuine_readonly_crt_file_stream_lifecycle_from_owned_fixture(self):
        from unicorn import Uc,UC_ARCH_X86,UC_MODE_64
        from unicorn.x86_const import UC_X86_REG_RAX
        from mxbikes_win64_file_api import OriginalGuestFileIO
        uc=Uc(UC_ARCH_X86,UC_MODE_64)
        buf=0x712100000
        uc.mem_map(buf,4096)
        fs=OriginalGuestFileIO(b"ABCD1234")
        fs.install(uc)
        self.assertFalse(fs.fopen(uc,"../../steam_api64.dll","rb",
            cwd="C:\\MXBikes"))
        self.assertFalse(fs.fopen(uc,"steam_api64.dll","wb",
            cwd="C:\\MXBikes"))
        self.assertTrue(fs.fopen(uc,"steam_api64.dll","rb",
            cwd="C:\\MXBikes"))
        filehandle=uc.reg_read(UC_X86_REG_RAX)
        ranges=[(buf,buf+4096)]
        self.assertTrue(fs.fread(uc,buf+100,2,3,filehandle,
            writable_ranges=ranges))
        self.assertEqual(uc.reg_read(UC_X86_REG_RAX),3)
        self.assertEqual(bytes(uc.mem_read(buf+100,6)),b"ABCD12")
        self.assertTrue(fs.ftell(uc,filehandle))
        self.assertEqual(uc.reg_read(UC_X86_REG_RAX),6)
        self.assertTrue(fs.fseek(uc,filehandle,0xfffffffe,1))
        self.assertTrue(fs.fread(uc,buf+120,2,3,filehandle,
            writable_ranges=ranges))
        self.assertEqual(uc.reg_read(UC_X86_REG_RAX),2)
        self.assertEqual(bytes(uc.mem_read(buf+120,4)),b"1234")
        self.assertTrue(fs.ftell(uc,filehandle))
        self.assertEqual(uc.reg_read(UC_X86_REG_RAX),8)
        self.assertTrue(fs.fseek(uc,filehandle,0,0))
        self.assertFalse(fs.fread(uc,buf+4095,1,8,filehandle,
            writable_ranges=ranges))
        self.assertFalse(fs.fseek(uc,filehandle,0,9))
        self.assertTrue(fs.fclose(uc,filehandle))
        self.assertFalse(fs.fclose(uc,filehandle))
        self.assertEqual(fs.events["original_bytes_read"],10)
        self.assertEqual(fs.events["open"],1)

    def test_first_fopen_guest_path_and_mode_are_bounded_metadata_only(self):
        from unicorn import Uc,UC_ARCH_X86,UC_MODE_64
        uc=Uc(UC_ARCH_X86,UC_MODE_64)
        base=0x712000000
        uc.mem_map(base,4096)
        uc.mem_write(base,b"config.ini\x00")
        uc.mem_write(base+64,b"rb\x00")
        allow=[(base,base+4096)]
        self.assertEqual(probe.read_guest_ascii_import_argument(
            uc,base,allow),"config.ini")
        self.assertEqual(probe.read_guest_ascii_import_argument(
            uc,base+64,allow),"rb")
        self.assertIsNone(probe.read_guest_ascii_import_argument(
            uc,base+4096,allow))
        self.assertIsNone(probe.read_guest_ascii_import_argument(
            uc,base,[(base,base+4)]))

    def test_setcurrentdirectorya_uses_full_original_guest_filename_directory(self):
        from unicorn import Uc,UC_ARCH_X86,UC_MODE_64
        from unicorn.x86_const import UC_X86_REG_RAX
        from mxbikes_win64_module_api import (
            GUEST_EXE_FILENAME,GUEST_WORKING_DIRECTORY,model_setcurrentdirectorya)
        self.assertEqual(GUEST_EXE_FILENAME.rsplit(b"\\",1)[0],GUEST_WORKING_DIRECTORY)
        uc=Uc(UC_ARCH_X86,UC_MODE_64)
        base=0x711200000
        uc.mem_map(base,4096)
        uc.mem_write(base,GUEST_WORKING_DIRECTORY+b"\x00")
        state={"cwd":None,"changes":0}
        self.assertTrue(model_setcurrentdirectorya(uc,base,
            readable_ranges=[(base,base+4096)],process_state=state))
        self.assertEqual(state["cwd"],GUEST_WORKING_DIRECTORY.decode("ascii"))
        self.assertEqual(state["changes"],1)
        self.assertEqual(uc.reg_read(UC_X86_REG_RAX),1)
        uc.mem_write(base,b"Z:\\NotExisting\x00")
        self.assertFalse(model_setcurrentdirectorya(uc,base,
            readable_ranges=[(base,base+4096)],process_state=state))
        self.assertFalse(model_setcurrentdirectorya(uc,0x1000,
            readable_ranges=[(base,base+4096)],process_state=state))
        self.assertEqual(state["changes"],1)

    def test_original_win64_getmodulefilenamea_writes_filename_and_rejects_invalid(self):
        from unicorn import Uc,UC_ARCH_X86,UC_MODE_64
        from unicorn.x86_const import UC_X86_REG_RAX
        from mxbikes_win64_module_api import model_getmodulefilenamea,GUEST_EXE_FILENAME
        cpu=Uc(UC_ARCH_X86,UC_MODE_64)
        stack=0x710000000
        image=0x140000000
        cpu.mem_map(stack,0x10000)
        dest=stack+0x100
        named=GUEST_EXE_FILENAME.decode("ascii")
        opts=dict(image_base=image,stack_base=stack,stack_size=0x10000,
                  writable_sections=[])
        self.assertTrue(model_getmodulefilenamea(cpu,0,dest,260,**opts))
        self.assertEqual(bytes(cpu.mem_read(dest,len(named)+1)),GUEST_EXE_FILENAME+b"\x00")
        self.assertEqual(cpu.reg_read(UC_X86_REG_RAX),len(named))
        self.assertTrue(model_getmodulefilenamea(cpu,image,dest,260,**opts))
        for module,buffer,size in [
            (0x440000000,dest,260),(0,0x10,260),(0,dest,4),
            (0,dest,0),(0,dest,0xffffffff)]:
            self.assertFalse(model_getmodulefilenamea(
                cpu,module,buffer,size,**opts))
        self.assertEqual(cpu.reg_read(UC_X86_REG_RAX),len(named))

    def test_msvcr90_global_command_line_is_data_not_ret_opcode(self):
        import struct
        from unicorn import Uc,UC_ARCH_X86,UC_MODE_64
        from mxbikes_win64_thread_env import install_guest_main_arguments,CRT_EXE_STRING
        from mxbikes_win64_crt_data import (
            install_crt_data_globals,address_for_original_crt_data_import)
        uc=Uc(UC_ARCH_X86,UC_MODE_64)
        install_guest_main_arguments(uc)
        report=install_crt_data_globals(uc)
        self.assertTrue(report["typed_data_import_not_executable"])
        data=address_for_original_crt_data_import("MSVCR90.dll","_acmdln")
        self.assertIsNotNone(data)
        actual=struct.unpack("<Q",uc.mem_read(data,8))[0]
        self.assertEqual(actual,CRT_EXE_STRING)
        self.assertEqual(bytes(uc.mem_read(actual,12)),b"mxbikes.exe\x00")
        self.assertNotEqual(actual,0xc3)
        wide=address_for_original_crt_data_import("MSVCR90.dll","_wcmdln")
        wchar=struct.unpack("<Q",uc.mem_read(wide,8))[0]
        self.assertEqual(bytes(uc.mem_read(wchar,24)),
                         "mxbikes.exe\x00".encode("utf-16le"))
        self.assertIsNone(address_for_original_crt_data_import(
            "kernel32.dll","_acmdln"))
        self.assertIsNone(address_for_original_crt_data_import(
            "MSVCR90.dll","unknown_symbol"))

    def test_getmainargs_writes_bounded_win64_argv_and_environment(self):
        import struct
        from unicorn import Uc,UC_ARCH_X86,UC_MODE_64
        from mxbikes_win64_thread_env import (
            install_guest_main_arguments,model_win64_crt_getmainargs,
            CRT_ARGV_ARRAY,CRT_ENVP_ARRAY,CRT_EXE_STRING)
        cpu=Uc(UC_ARCH_X86,UC_MODE_64)
        stack=0x760000000
        cpu.mem_map(stack,0x10000)
        info=install_guest_main_arguments(cpu)
        self.assertEqual(info["synthetic_argv_count"],1)
        argc=stack+0x100
        argv=stack+0x110
        envp=stack+0x118
        self.assertTrue(model_win64_crt_getmainargs(
            cpu,argc,argv,envp,[],stack_base=stack,stack_size=0x10000,wildcard=0))
        self.assertEqual(struct.unpack("<I",cpu.mem_read(argc,4))[0],1)
        self.assertEqual(struct.unpack("<Q",cpu.mem_read(argv,8))[0],CRT_ARGV_ARRAY)
        self.assertEqual(struct.unpack("<Q",cpu.mem_read(envp,8))[0],CRT_ENVP_ARRAY)
        self.assertEqual(struct.unpack("<Q",cpu.mem_read(CRT_ARGV_ARRAY,8))[0],CRT_EXE_STRING)
        self.assertEqual(struct.unpack("<Q",cpu.mem_read(CRT_ENVP_ARRAY,8))[0],0)
        self.assertEqual(bytes(cpu.mem_read(CRT_EXE_STRING,12)),b"mxbikes.exe\x00")
        self.assertFalse(model_win64_crt_getmainargs(
            cpu,argc,argv,0x1000,[],stack_base=stack,stack_size=0x10000,wildcard=0))
        self.assertFalse(model_win64_crt_getmainargs(
            cpu,argc,argv,envp,[],stack_base=stack,stack_size=0x10000,wildcard=4))

    def test_crt_exit_callback_registration_tracks_original_addresses(self):
        class FakeCPU:
            def __init__(self):self.result=None
            def reg_write(self,reg,value):self.result=value
        cpu=FakeCPU()
        callbacks=[]
        text=[(0x140100000,0x140200000)]
        a=0x140136710
        b=0x140136120
        self.assertTrue(probe.model_crt_exit_callback_registration(
            cpu,a,text,callbacks))
        self.assertEqual(cpu.result,a)
        self.assertEqual(callbacks,[a])
        self.assertTrue(probe.model_crt_exit_callback_registration(
            cpu,b,text,callbacks,is_atexit=True))
        self.assertEqual(cpu.result,0)
        self.assertEqual(callbacks,[a,b])
        self.assertFalse(probe.model_crt_exit_callback_registration(
            cpu,0,text,callbacks))
        self.assertFalse(probe.model_crt_exit_callback_registration(
            cpu,0x550000000,text,callbacks))
        self.assertEqual(callbacks,[a,b])

    def test_win64_exception_filter_registration_returns_previous_handler(self):
        from unicorn.x86_const import UC_X86_REG_RAX
        class FakeGuest:
            def __init__(self):self.rax=None
            def reg_write(self,reg,value):
                self.assert_reg=reg
                self.rax=value
        emulator=FakeGuest()
        state={"handler":0,"registrations":0}
        executable=[(0x140100000,0x140200000)]
        first=0x140136710
        second=0x140138000
        self.assertTrue(probe.model_unhandled_exception_filter(
            emulator,first,executable,state))
        self.assertEqual(emulator.rax,0)
        self.assertEqual(state["handler"],first)
        self.assertTrue(probe.model_unhandled_exception_filter(
            emulator,second,executable,state))
        self.assertEqual(emulator.rax,first)
        self.assertEqual(state["handler"],second)
        self.assertEqual(state["registrations"],2)
        self.assertFalse(probe.model_unhandled_exception_filter(
            emulator,0x50000,executable,state))
        self.assertEqual(state["handler"],second)
        self.assertTrue(probe.model_unhandled_exception_filter(
            emulator,0,executable,state))
        self.assertEqual(emulator.rax,second)
        self.assertEqual(state["handler"],0)
        self.assertEqual(state["registrations"],3)

    def test_crt_pointer_encode_decode_is_reversible_and_nonidentity(self):
        originals=[0,1,0x1234,0x140136710,0x7fffffffffffffff,0xffffffffffffffff]
        for value in originals:
            encoded=probe.modeled_encode_pointer(value)
            self.assertNotEqual(encoded,value)
            self.assertEqual(probe.modeled_decode_pointer(encoded),value)

    def test_ms_visual_crt_app_type_enum_is_bounded(self):
        self.assertEqual(probe.modeled_crt_app_type(0),"unknown")
        self.assertEqual(probe.modeled_crt_app_type(1),"console")
        self.assertEqual(probe.modeled_crt_app_type(2),"gui")
        self.assertIsNone(probe.modeled_crt_app_type(3))
        self.assertIsNone(probe.modeled_crt_app_type(65536))

    def test_executed_guest_crt_callbacks_obey_real_win64_abi(self):
        from unicorn import Uc,UC_ARCH_X86,UC_MODE_64,UC_HOOK_CODE
        from unicorn.x86_const import (
            UC_X86_REG_RAX,UC_X86_REG_RCX,UC_X86_REG_RDX,
            UC_X86_REG_RSI,UC_X86_REG_RDI,UC_X86_REG_RSP)
        from mxbikes_first_callee_emu import STUB_BASE
        from mxbikes_win64_crt_dispatch import (
            THUNK_E_VA,THUNK_VOID_VA,install_original_crt_dispatch_thunks)
        import struct
        def execute(use_e,entries):
            uc=Uc(UC_ARCH_X86,UC_MODE_64)
            uc.mem_map(STUB_BASE,65536)
            uc.mem_map(0x5000000,4096)
            uc.mem_map(0x5200000,4096)
            uc.mem_map(0x70000000,65536)
            install_original_crt_dispatch_thunks(uc)
            callbacks=[
                (0x5000000,b"\x31\xc0\xc3"),
                (0x5000010,b"\xb8\x05\x00\x00\x00\xc3"),
                (0x5000020,b"\xb8\x09\x00\x00\x00\xc3"),
            ]
            for va,code in callbacks:uc.mem_write(va,code)
            uc.mem_write(0x5200000,b"".join(struct.pack("<Q",v) for v in entries))
            entry_sp=0x7000f008
            return_pc=0x8000000
            uc.mem_write(entry_sp,struct.pack("<Q",return_pc))
            uc.reg_write(UC_X86_REG_RSP,entry_sp)
            uc.reg_write(UC_X86_REG_RCX,0x5200000)
            uc.reg_write(UC_X86_REG_RDX,0x5200000+8*len(entries))
            uc.reg_write(UC_X86_REG_RSI,0xaabbccddee112233)
            uc.reg_write(UC_X86_REG_RDI,0x1122334455667788)
            visits=[]
            def visitor(emu,addr,size,user):
                if 0x5000000<=addr<0x5001000:visits.append(addr)
            uc.hook_add(UC_HOOK_CODE,visitor)
            uc.emu_start(THUNK_E_VA if use_e else THUNK_VOID_VA,
                         return_pc,count=500)
            self.assertEqual(uc.reg_read(UC_X86_REG_RSP),entry_sp+8)
            self.assertEqual(uc.reg_read(UC_X86_REG_RSI),0xaabbccddee112233)
            self.assertEqual(uc.reg_read(UC_X86_REG_RDI),0x1122334455667788)
            return uc.reg_read(UC_X86_REG_RAX),visits
        first=0x5000000
        second=0x5000010
        third=0x5000020
        status,visits=execute(True,[first,second,third])
        self.assertEqual(status,5)
        self.assertIn(first,visits)
        self.assertIn(second,visits)
        self.assertNotIn(third,visits)
        status,visits=execute(True,[0,first])
        self.assertEqual(status,0)
        self.assertIn(first,visits)
        status,visits=execute(False,[first,second,third])
        self.assertIn(third,visits)

    def test_crt_initializer_scan_only_accepts_empty_original_arrays(self):
        import struct
        class FakeMemory:
            def __init__(self,data):
                self.data=data
            def mem_read(self,addr,length):
                if addr!=probe.IMAGE_BASE+0x4000 or length>len(self.data):
                    raise ValueError("Guest array unmapped")
                return self.data[:length]
        start=probe.IMAGE_BASE+0x4000
        code_start=probe.IMAGE_BASE+0x136710
        code_ranges=[(code_start,code_start+0x100)]
        empty=probe.inspect_original_crt_initializer_array(
            FakeMemory(bytes(24)),start,start+24,code_ranges)
        self.assertEqual(empty["status"],"empty_original_crt_initializer_array")
        self.assertEqual(empty["callback_count"],0)
        nonempty=probe.inspect_original_crt_initializer_array(
            FakeMemory(struct.pack("<QQQ",0,code_start,0)),
            start,start+24,code_ranges)
        self.assertEqual(nonempty["status"],"original_crt_callbacks_require_execution")
        self.assertEqual(nonempty["first_callback_rva"],"0x136710")
        self.assertEqual(nonempty["callback_count"],1)
        external=probe.inspect_original_crt_initializer_array(
            FakeMemory(struct.pack("<QQ",0x710000000,0)),
            start,start+16,code_ranges)
        self.assertEqual(external["status"],"original_crt_callback_pointer_not_executable")
        self.assertEqual(probe.inspect_original_crt_initializer_array(
            FakeMemory(b""),start,start-8,code_ranges)["status"],
            "untrusted_original_crt_array_bounds")
        self.assertEqual(probe.inspect_original_crt_initializer_array(
            FakeMemory(b""),start,start+4096,code_ranges)["status"],
            "untrusted_original_crt_array_bounds")

    def test_real_x64_gs_teb_and_peb_offsets_reach_original_guest_memory(self):
        from unicorn import Uc,UC_ARCH_X86,UC_MODE_64
        from unicorn.x86_const import UC_X86_REG_RAX
        from mxbikes_win64_thread_env import (
            build_win64_thread_environment,TEB_BASE,PEB_BASE,
            PARAMS_BASE,HEAP_BASE,THREAD_ENV_PAGE)
        uc=Uc(UC_ARCH_X86,UC_MODE_64)
        guest_code=0x6000000
        stack=0x7000000
        uc.mem_map(guest_code,4096)
        uc.mem_map(stack,65536)
        report=build_win64_thread_environment(uc,stack_base=stack,
            stack_size=65536,image_base=0x140000000)
        self.assertTrue(report["win64_gs_base_initialized"])
        self.assertFalse(report["real_windows_teb_or_peb_created"])
        for disp,wanted in ((0x30,TEB_BASE),(0x60,PEB_BASE)):
            # mov rax,qword ptr gs:[disp32]
            code=b"\x65\x48\x8b\x04\x25"+disp.to_bytes(4,"little")
            uc.mem_write(guest_code,code)
            uc.emu_start(guest_code,guest_code+len(code),count=8)
            self.assertEqual(uc.reg_read(UC_X86_REG_RAX),wanted)
        def ptr(base,off):
            return int.from_bytes(uc.mem_read(base+off,8),"little")
        self.assertEqual(ptr(TEB_BASE,0x08),stack+65536)
        self.assertEqual(ptr(TEB_BASE,0x10),stack)
        self.assertEqual(ptr(TEB_BASE,0x30),TEB_BASE)
        self.assertEqual(ptr(TEB_BASE,0x60),PEB_BASE)
        self.assertEqual(ptr(PEB_BASE,0x10),0x140000000)
        self.assertEqual(ptr(PEB_BASE,0x20),PARAMS_BASE)
        self.assertEqual(ptr(PEB_BASE,0x30),HEAP_BASE)
        self.assertEqual(len(uc.mem_read(TEB_BASE,THREAD_ENV_PAGE)),THREAD_ENV_PAGE)
        with self.assertRaises(ValueError):
            build_win64_thread_environment(Uc(UC_ARCH_X86,UC_MODE_64),
                stack_base=stack+1,stack_size=65536,image_base=0x140000000)

    def test_getstartupinfoa_guest_model_has_exact_win64_size(self):
        class FakeGuest:
            def __init__(self):self.writes=[]
            def mem_write(self,addr,data):self.writes.append((addr,bytes(data)))
        uc=FakeGuest()
        rsp=probe.STACK_BASE+4096
        self.assertTrue(probe.model_getstartupinfoa(uc,rsp,[]))
        self.assertEqual(len(uc.writes),1)
        self.assertEqual(len(uc.writes[0][1]),104)
        self.assertEqual(int.from_bytes(uc.writes[0][1][:4],"little"),104)
        self.assertFalse(probe.model_getstartupinfoa(uc,0x810000000,[]))
        self.assertEqual(len(uc.writes),1)
        writable_start=probe.IMAGE_BASE+0x380000
        self.assertTrue(probe.model_getstartupinfoa(
            uc,writable_start,[(writable_start,writable_start+4096)]))
        self.assertEqual(len(uc.writes),2)
        self.assertFalse(probe.model_getstartupinfoa(
            uc,writable_start+4096-16,
            [(writable_start,writable_start+4096)]))
        self.assertEqual(len(uc.writes),2)

    def test_no_game_boot_when_entry_is_only_partial(self):
        result=probe.native_readiness(fixed_map(),[proved(0x136120)],ENTRY_RVA)
        self.assertFalse(result["native_arm64_entrypoint_can_execute_game"])
        self.assertFalse(result["native_roots"]["pe_entry"]["whole_native_function_verified"])
        self.assertEqual(result["game_main_direct_callees_in_static_map"],2)
        self.assertEqual(result["game_main_direct_callees_with_verified_native_code"],1)
        self.assertFalse(result["native_iphone_ipa_exists"])

    def test_only_complete_win64_proofs_are_eligible(self):
        attempted=proved(ENTRY_RVA)
        attempted["full_function_behavior_verified"]=False
        actual=probe.native_readiness(fixed_map(),[attempted],ENTRY_RVA)
        self.assertEqual(actual["native_verified_original_complete_functions"],0)

    def test_native_entry_requires_all_known_main_dependencies(self):
        entries=[proved(x) for x in
                 (ENTRY_RVA,CRT_RVA,MAIN_RVA,0x136120,0x136130)]
        actual=probe.native_readiness(fixed_map(),entries,ENTRY_RVA)
        self.assertTrue(actual["native_arm64_entrypoint_can_execute_game"])
        entries.pop()
        self.assertFalse(probe.native_readiness(
            fixed_map(),entries,ENTRY_RVA)["native_arm64_entrypoint_can_execute_game"])
        # This is only a necessary coverage gate; real game boot remains separate.

    def test_unknown_executable_or_duplicate_or_entry_is_rejected(self):
        with self.assertRaises(ValueError):
            probe.native_readiness(
                {"input_sha256":"bad","original_file_verified":True},
                [],ENTRY_RVA)
        with self.assertRaises(ValueError):
            probe.native_readiness(fixed_map(),[proved(ENTRY_RVA)]*2,ENTRY_RVA)
        with self.assertRaises(ValueError):
            probe.native_readiness(fixed_map(),[],ENTRY_RVA+1)

if __name__=="__main__":
    unittest.main()
