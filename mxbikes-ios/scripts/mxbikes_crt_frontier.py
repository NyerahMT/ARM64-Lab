#!/usr/bin/env python3
"""Bounded MX Bikes x64 CRT-startup frontier experiment.

Runs the real original entry and CRT instructions under Unicorn x64, with
synthetic Windows imports and TEB. Reports static addresses and diagnostics
only. No original binary/code bytes or derived source leave the private job.
"""
import collections
import json
import os
from pathlib import Path
import struct
import sys

from unicorn import UC_ARCH_X86, UC_HOOK_CODE, UC_HOOK_MEM_WRITE, UC_HOOK_MEM_INVALID, UC_MODE_64, Uc
from unicorn.x86_const import (
    UC_X86_REG_GS_BASE, UC_X86_REG_RAX, UC_X86_REG_RCX,
    UC_X86_REG_RIP, UC_X86_REG_RSP, UC_X86_REG_RDX, UC_X86_REG_R8, UC_X86_REG_R9, UC_X86_REG_RDI, UC_X86_REG_RSI,
)

from mxbikes_first_callee_emu import (
    APIS_RECOGNIZED, EXE_SHA, IMAGE_BASE, MAX_IMAGE_SIZE,
    STACK_BASE, STACK_SIZE, STUB_BASE, import_slots, round4k,
)
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "arm64-lab"))
from tools.pe_probe import PE
from tools.entry_wrapper import decode_entry_wrapper
from tools.win64_crt_trampoline import build_initializer_trampoline
from tools.win64_pointer_codec import encode_pointer, decode_pointer
from tools.guest_file_bridge import GuestFileBridge, GuestFileError
from mxbikes_private_asset import load_startup_dll
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

TEB_BASE = 0x720000000
MAX_INSNS = 5_000_000
CRT_TRAMPOLINE_START = STUB_BASE + 0x9000
MAX_SECONDS_MICRO = 120_000_000


def run_frontier(executable, private_archive):
    # The DLL bytes remain in memory on the private Actions runner, and
    # are never written to the metadata artifact or printed in diagnostics.
    files = GuestFileBridge({"steam_api64.dll": load_startup_dll(private_archive)})
    pe = PE(executable)
    meta = pe.inventory()
    if meta["sha256"] != EXE_SHA or int(meta["image_base"], 16) != IMAGE_BASE:
        raise RuntimeError("Unrecognized original MX Bikes executable")
    entry = int(meta["entry_rva"], 16)
    wrapper = decode_entry_wrapper(pe.read_rva(entry, 18), entry)
    tail = int(wrapper["tail_jmp_rva"], 16)
    first = int(wrapper["direct_call_rva"], 16)
    last_section = max(rva + max(vsize, raw) for _,vsize,rva,raw,_,_ in pe.sections)
    if last_section > MAX_IMAGE_SIZE:
        raise ValueError("Image would exceed bounded emulator memory")
    uc = Uc(UC_ARCH_X86, UC_MODE_64)
    uc.mem_map(IMAGE_BASE, round4k(last_section))
    for _,_,rva,rawsize,rawptr,_ in pe.sections:
        if rawsize:
            uc.mem_write(IMAGE_BASE + rva, pe.b[rawptr:rawptr + rawsize])
    uc.mem_map(STUB_BASE, 0x10000)
    uc.mem_map(STACK_BASE, STACK_SIZE)
    uc.mem_map(TEB_BASE, 0x1000)
    uc.mem_write(TEB_BASE + 0x30, struct.pack("<Q", TEB_BASE))
    uc.mem_write(TEB_BASE + 0x08, struct.pack("<Q", STACK_BASE + STACK_SIZE))
    uc.reg_write(UC_X86_REG_GS_BASE, TEB_BASE)
    initial_rsp = STACK_BASE + STACK_SIZE - 0x108
    uc.mem_write(initial_rsp, struct.pack("<Q", 0x12345678))
    uc.reg_write(UC_X86_REG_RSP, initial_rsp)
    uc.reg_write(UC_X86_REG_RIP, IMAGE_BASE + entry)
    mapped = {}
    data_imports = {}
    slots = import_slots(pe)
    suspect_iat = 0x3214d0
    matching_iat = [(dll, name) for rva,dll,name in slots if rva == suspect_iat]
    # Exact symbol identity is needed before changing any import-slot semantics.
    if not matching_iat:
        raise RuntimeError("Suspected CRT data import not in PE import slots")
    if len(matching_iat) != 1:
        raise RuntimeError("Ambiguous CRT data import")
    suspect_import_name = matching_iat[0][0] + "::" + matching_iat[0][1]
    if len(slots) > 2048:
        raise RuntimeError("Too many imports for deterministic stub region")
    for idx, (rva, dll, name) in enumerate(slots):
        if dll.lower() == "msvcr90.dll" and name.lower() == "_acmdln":
            # Imported MSVC CRT DATA SYMBOL (char * _acmdln), not a function.
            # The IAT points to a writable host data slot, which holds a
            # valid guest pointer to a synthetic command-line C string.
            string_va = TEB_BASE + 0x2c0
            data_slot_va = TEB_BASE + 0x380
            uc.mem_write(string_va, b"mxbikes.exe\x00")
            uc.mem_write(data_slot_va, struct.pack("<Q", string_va))
            uc.mem_write(IMAGE_BASE + rva, struct.pack("<Q", data_slot_va))
            data_imports[dll + "::" + name] = hex(rva)
            continue
        stub = STUB_BASE + idx*16
        mapped[stub] = (dll, name)
        uc.mem_write(stub, b"\xc3")
        uc.mem_write(IMAGE_BASE + rva, struct.pack("<Q", stub))
    trace = {
        "entry_rva": hex(entry),
        "suspected_crt_data_iat_rva": hex(suspect_iat),
        "suspected_crt_data_import": suspect_import_name,
        "first_callee_rva": hex(first),
        "crt_tail_rva": hex(tail),
        "original_instruction_count": 0,
        "tail_instruction_count": 0,
        "first_initializer_instruction_count": 0,
        "original_basic_entry_count": 0,
        "synthetic_import_returns": 0,
        "synthetic_steam_restart_checks": 0,
        "unimplemented_import": None,
        "unsupported_import_stack_return_rva": None,
        "crt_initializer_tables": [],
        "crt_original_callback_entries": 0,
        "crt_emitted_trampolines": 0,
        "crt_original_callbacks_expected": 0,
        "crt_trampoline_instructions": 0,
        "synthetic_crt_app_type": None,
        "synthetic_unhandled_exception_filter": 0,
        "registered_exit_callbacks": [],
        "synthetic_command_line_arguments": None,
        "synthetic_executable_path_requests": 0,
        "synthetic_crt_string_copies": 0,
        "synthetic_current_directory": None,
        "first_file_open": None,
        "guest_file_error": None,
        "synthetic_filter_installations": 0,
        "synthetic_pointer_encoding_calls": 0,
        "synthetic_pointer_decoding_calls": 0,
        "first_exception": None,
        "memory_fault": None,
        "faulting_instruction": None,
        "recent_original_instructions": [],
        "stop_reason": None,
        "globals_written": 0,
        "indirect_original_calls_observed": 0,
        "original_targets_visited": [],
        "windows_imports_called": {},
        "max_instructions": MAX_INSNS,
        "real_game_booted": False,
        "native_arm64_executed": False,
    }
    calls = collections.Counter()
    reached = []
    write_regions = collections.Counter()
    original_callback_addresses = set()
    trampoline_ranges = []
    pending_callbacks = []
    recent = collections.deque(maxlen=18)
    decoder = Cs(CS_ARCH_X86, CS_MODE_64)

    def code_hook(emulator, address, instr_size, _):
        # Fail closed before any non-image code, except controlled import stubs.
        if any(lo <= address < hi for lo,hi in trampoline_ranges):
            trace["crt_trampoline_instructions"] += 1
            return
        if address in original_callback_addresses:
            trace["crt_original_callback_entries"] += 1
        if address in mapped:
            dll, name = mapped[address]
            low = name.lower()
            calls[dll + "::" + name] += 1
            if dll.lower() == "steam_api64.dll" and low == "steamapi_restartappifnecessary":
                # Controlled test only: model Steam having launched the app
                # already. Not a working Steam SDK or production integration.
                emulator.reg_write(UC_X86_REG_RAX, 0)
                trace["synthetic_import_returns"] += 1
                trace["synthetic_steam_restart_checks"] += 1
                return
            if dll.lower() == "msvcr90.dll" and low in {
                "fopen", "fread", "fseek", "ftell", "fclose",
                "fgetc", "feof", "ferror", "rewind"
            }:
                def guest_cstring(ptr, cap):
                    if not ptr:
                        raise GuestFileError("Null guest string pointer")
                    result = bytearray()
                    for k in range(cap):
                        ch = bytes(emulator.mem_read(ptr+k, 1))
                        if ch == b"\x00":
                            return result.decode("ascii")
                        result += ch
                    raise GuestFileError("Unterminated guest string")
                try:
                    if low == "fopen":
                        filename = guest_cstring(emulator.reg_read(UC_X86_REG_RCX), 512)
                        mode = guest_cstring(emulator.reg_read(UC_X86_REG_RDX), 24)
                        if trace["first_file_open"] is None:
                            trace["first_file_open"] = {"filename": filename, "mode": mode}
                        result = files.fopen(filename, mode)
                    elif low == "fread":
                        buffer = emulator.reg_read(UC_X86_REG_RCX)
                        size = emulator.reg_read(UC_X86_REG_RDX)
                        count = emulator.reg_read(UC_X86_REG_R8)
                        # fread's fourth Win64 integer argument is in R9.
                        handle = emulator.reg_read(UC_X86_REG_R9)
                        payload, result = files.fread(handle, size, count)
                        if payload:
                            if not buffer:
                                raise GuestFileError("Null fread destination")
                            emulator.mem_write(buffer, payload)
                    elif low == "fseek":
                        handle = emulator.reg_read(UC_X86_REG_RCX)
                        raw_off = emulator.reg_read(UC_X86_REG_RDX) & 0xffffffff
                        offset = struct.unpack("<i", struct.pack("<I", raw_off))[0]
                        origin = emulator.reg_read(UC_X86_REG_R8)
                        result = files.fseek(handle, offset, origin)
                    elif low == "ftell":
                        result = files.ftell(emulator.reg_read(UC_X86_REG_RCX))
                    elif low == "fclose":
                        result = files.fclose(emulator.reg_read(UC_X86_REG_RCX))
                    elif low == "fgetc":
                        result = files.fgetc(emulator.reg_read(UC_X86_REG_RCX))
                    elif low == "feof":
                        result = files.feof(emulator.reg_read(UC_X86_REG_RCX))
                    elif low == "ferror":
                        result = files.ferror(emulator.reg_read(UC_X86_REG_RCX))
                    else:
                        files.rewind(emulator.reg_read(UC_X86_REG_RCX))
                        result = 0  # WinCRT rewind() returns void.
                    if low != "rewind":
                        emulator.reg_write(UC_X86_REG_RAX, result & 0xffffffffffffffff)
                    trace["synthetic_import_returns"] += 1
                except (GuestFileError, UnicodeDecodeError) as exc:
                    trace["stop_reason"] = "guest_file_bridge_rejected_operation"
                    trace["guest_file_error"] = str(exc)
                    emulator.emu_stop()
                return
            if dll.lower() == "msvcr90.dll" and low == "strcpy":
                # Standard null-terminated byte-copy semantics, with a hard
                # scan cap; never invent a source string or silently truncate.
                dest = emulator.reg_read(UC_X86_REG_RCX)
                source = emulator.reg_read(UC_X86_REG_RDX)
                if not dest or not source:
                    trace["stop_reason"] = "invalid_crt_string_pointer"
                    emulator.emu_stop()
                    return
                data = bytearray()
                for offset in range(4096):
                    byte = bytes(emulator.mem_read(source+offset, 1))
                    data += byte
                    if byte == b"\x00":
                        break
                else:
                    trace["stop_reason"] = "crt_string_exceeds_bound"
                    emulator.emu_stop()
                    return
                emulator.mem_write(dest, bytes(data))
                emulator.reg_write(UC_X86_REG_RAX, dest)
                trace["synthetic_crt_string_copies"] += 1
                trace["synthetic_import_returns"] += 1
                return
            if dll.lower() == "msvcr90.dll" and low == "_ismbblead":
                # ASCII bytes cannot be MBCS lead bytes. Fail closed for
                # non-ASCII bytes until a real codepage model is available.
                char_byte = emulator.reg_read(UC_X86_REG_RCX) & 0xff
                if char_byte >= 0x80:
                    trace["stop_reason"] = "non_ascii_mbc_unsupported"
                    emulator.emu_stop()
                    return
                emulator.reg_write(UC_X86_REG_RAX, 0)
                trace["synthetic_import_returns"] += 1
                return
            if dll.lower() == "msvcr90.dll" and low == "__getmainargs":
                # Synthetic one-argument Win64 CRT launch, no wildcard or
                # environment expansion. Fill argc, argv, env via guest pointers.
                argc_ptr = emulator.reg_read(UC_X86_REG_RCX)
                argv_out = emulator.reg_read(UC_X86_REG_RDX)
                env_out = emulator.reg_read(UC_X86_REG_R8)
                argv_array = TEB_BASE + 0x280
                env_array = TEB_BASE + 0x2a0
                exe_name = TEB_BASE + 0x2c0
                emulator.mem_write(exe_name, b"mxbikes.exe\x00")
                emulator.mem_write(argv_array, struct.pack("<QQ", exe_name, 0))
                emulator.mem_write(env_array, struct.pack("<Q", 0))
                emulator.mem_write(argc_ptr, struct.pack("<I", 1))
                emulator.mem_write(argv_out, struct.pack("<Q", argv_array))
                emulator.mem_write(env_out, struct.pack("<Q", env_array))
                emulator.reg_write(UC_X86_REG_RAX, 0)
                trace["synthetic_command_line_arguments"] = 1
                trace["synthetic_import_returns"] += 1
                return
            if dll.lower() == "msvcr90.dll" and low == "_onexit":
                callback = emulator.reg_read(UC_X86_REG_RCX)
                valid = any(
                    IMAGE_BASE+rva <= callback < IMAGE_BASE+rva+max(vsize,raw)
                    for _,vsize,rva,raw,_,flags in pe.sections if flags & 0x20000000
                )
                if not valid or len(trace["registered_exit_callbacks"]) >= 128:
                    trace["stop_reason"] = "invalid_onexit_registration"
                    emulator.emu_stop()
                    return
                trace["registered_exit_callbacks"].append(hex(callback-IMAGE_BASE))
                emulator.reg_write(UC_X86_REG_RAX, callback)
                trace["synthetic_import_returns"] += 1
                return
            if dll.lower() == "msvcr90.dll" and low in {"_encode_pointer", "_decode_pointer"}:
                raw = emulator.reg_read(UC_X86_REG_RCX)
                transformed = encode_pointer(raw) if low == "_encode_pointer" else decode_pointer(raw)
                emulator.reg_write(UC_X86_REG_RAX, transformed)
                trace["synthetic_import_returns"] += 1
                trace["synthetic_pointer_encoding_calls" if low == "_encode_pointer" else
                      "synthetic_pointer_decoding_calls"] += 1
                return
            if low == "__set_app_type" and dll.lower() == "msvcr90.dll":
                # Preserve CRT application-type selection as modeled host
                # state. Does not initialize the real Microsoft CRT.
                selected_type = emulator.reg_read(UC_X86_REG_RCX)
                if selected_type not in (1, 2):
                    trace["stop_reason"] = "unexpected_crt_app_type"
                    emulator.emu_stop()
                    return
                trace["synthetic_crt_app_type"] = selected_type
                trace["synthetic_import_returns"] += 1
                return
            if low in {"_initterm_e", "_initterm"} and dll.lower() == "msvcr90.dll":
                start_ptr = emulator.reg_read(UC_X86_REG_RCX)
                end_ptr = emulator.reg_read(UC_X86_REG_RDX)
                if end_ptr < start_ptr or (end_ptr - start_ptr) % 8 or (end_ptr - start_ptr) // 8 > 4096:
                    trace["stop_reason"] = "invalid_crt_initializer_table"
                    emulator.emu_stop()
                    return
                candidates = []
                for n in range((end_ptr-start_ptr)//8):
                    value = struct.unpack("<Q", emulator.mem_read(start_ptr+n*8, 8))[0]
                    if value:
                        candidates.append(hex(value - IMAGE_BASE) if IMAGE_BASE <= value < IMAGE_BASE + round4k(last_section) else "external")
                trace["crt_initializer_tables"].append({
                    "api": name, "total_slots": (end_ptr-start_ptr)//8,
                    "non_null_callbacks": len(candidates),
                    "callback_rvas_sample": candidates[:20]
                })
                if candidates:
                    # Do not fake constructor execution. Build a guest x64
                    # trampoline that actually CALLs each original callback.
                    raw_addresses = [
                        struct.unpack("<Q", emulator.mem_read(start_ptr+n*8, 8))[0]
                        for n in range((end_ptr-start_ptr)//8)
                    ]
                    raw_addresses = [a for a in raw_addresses if a]
                    valid_sections = [
                        (IMAGE_BASE+rva, IMAGE_BASE+rva+max(vsize,raw))
                        for _,vsize,rva,raw,_,flags in pe.sections
                        if flags & 0x20000000
                    ]
                    if any(not any(lo <= a < hi for lo,hi in valid_sections)
                           for a in raw_addresses):
                        trace["stop_reason"] = "crt_initializer_target_outside_code"
                        emulator.emu_stop()
                        return
                    pending_callbacks.append((raw_addresses, low == "_initterm_e"))
                    original_callback_addresses.update(raw_addresses)
                    trace["stop_reason"] = "crt_trampoline_pending"
                    emulator.emu_stop()
                    return
                if low == "_initterm_e":
                    emulator.reg_write(UC_X86_REG_RAX, 0)
                trace["synthetic_import_returns"] += 1
                return
            if low not in APIS_RECOGNIZED and low not in {"sleep", "getstartupinfoa", "setunhandledexceptionfilter", "getmodulefilenamea", "setcurrentdirectorya"}:
                trace["unimplemented_import"] = dll + "::" + name
                # Record the original executable continuation currently on the
                # Win64 guest stack. This is an *unexecuted* return location,
                # not proof that the engine can proceed past the missing DLL.
                rsp_at_import = emulator.reg_read(UC_X86_REG_RSP)
                if STACK_BASE <= rsp_at_import <= STACK_BASE + STACK_SIZE - 8:
                    return_va = struct.unpack(
                        "<Q", emulator.mem_read(rsp_at_import, 8))[0]
                    if IMAGE_BASE <= return_va < IMAGE_BASE + last_section:
                        trace["unsupported_import_stack_return_rva"] = hex(
                            return_va - IMAGE_BASE)
                trace["stop_reason"] = "unsupported_external_api"
                emulator.emu_stop()
                return
            trace["synthetic_import_returns"] += 1
            if low == "setcurrentdirectorya" and dll.lower() == "kernel32.dll":
                source = emulator.reg_read(UC_X86_REG_RCX)
                if not source:
                    trace["stop_reason"] = "invalid_working_directory_pointer"
                    emulator.emu_stop()
                    return
                data = bytearray()
                for offset in range(4096):
                    b = bytes(emulator.mem_read(source+offset, 1))
                    if b == b"\x00":
                        break
                    data += b
                else:
                    trace["stop_reason"] = "working_directory_exceeds_bound"
                    emulator.emu_stop()
                    return
                try:
                    path = data.decode("ascii")
                except UnicodeDecodeError:
                    trace["stop_reason"] = "non_ascii_working_directory"
                    emulator.emu_stop()
                    return
                if not path or ".." in path:
                    trace["stop_reason"] = "unsafe_working_directory"
                    emulator.emu_stop()
                    return
                trace["synthetic_current_directory"] = path
                # Controlled diagnostics: pretend the requested directory
                # exists, WITHOUT changing the runner filesystem or loading
                # any original assets.
                emulator.reg_write(UC_X86_REG_RAX, 1)
                trace["synthetic_import_returns"] += 1
                return
            if low == "getmodulefilenamea" and dll.lower() == "kernel32.dll":
                module = emulator.reg_read(UC_X86_REG_RCX)
                dest = emulator.reg_read(UC_X86_REG_RDX)
                max_len = emulator.reg_read(UC_X86_REG_R8) & 0xffffffff
                path_bytes = b"C:\\MXBikes\\mxbikes.exe"
                if module != 0 or max_len < len(path_bytes)+1 or max_len > 65536 or dest == 0:
                    trace["stop_reason"] = "unsupported_module_filename_query"
                    emulator.emu_stop()
                    return
                emulator.mem_write(dest, path_bytes+b"\x00")
                emulator.reg_write(UC_X86_REG_RAX, len(path_bytes))
                trace["synthetic_executable_path_requests"] += 1
                trace["synthetic_import_returns"] += 1
                return
            if low == "setunhandledexceptionfilter" and dll.lower() == "kernel32.dll":
                # Model Win32 previous-filter return, not real SEH handling.
                previous = trace["synthetic_unhandled_exception_filter"]
                trace["synthetic_unhandled_exception_filter"] = emulator.reg_read(UC_X86_REG_RCX)
                trace["synthetic_filter_installations"] += 1
                emulator.reg_write(UC_X86_REG_RAX, previous)
            elif low == "getsystemtimeasfiletime":
                emulator.mem_write(emulator.reg_read(UC_X86_REG_RCX),
                                   struct.pack("<Q",116444736012345678))
            elif low == "queryperformancecounter":
                emulator.mem_write(emulator.reg_read(UC_X86_REG_RCX),
                                   struct.pack("<Q",1234567890))
                emulator.reg_write(UC_X86_REG_RAX, 1)
            elif low == "getstartupinfoa":
                # Minimal deterministic Win64 STARTUPINFOA (104 bytes).
                # Valid for the emulator only; not a full OS implementation.
                dst = emulator.reg_read(UC_X86_REG_RCX)
                emulator.mem_write(dst, struct.pack("<I", 104) + bytes(100))
            elif low == "getcurrentprocessid":
                emulator.reg_write(UC_X86_REG_RAX, 0x1234)
            elif low == "getcurrentthreadid":
                emulator.reg_write(UC_X86_REG_RAX, 0x5678)
            elif low == "gettickcount":
                emulator.reg_write(UC_X86_REG_RAX, 0x9abc)
            return
        if not IMAGE_BASE <= address < IMAGE_BASE + round4k(last_section):
            trace["stop_reason"] = "unexpected_nonimage_code"
            trace["first_exception"] = "PC outside private original PE: " + hex(address)
            emulator.emu_stop()
            return
        rva = address - IMAGE_BASE
        trace["original_instruction_count"] += 1
        try:
            # Avoid decoding millions of repetitive CRC-like loop instructions.
            # Exact faulting instructions are still decoded in invalid_mem.
            if trace["original_instruction_count"] > 2000 and trace["original_instruction_count"] % 64 != 0:
                decoded = []
            else:
                decoded = list(decoder.disasm(emulator.mem_read(address, 15), rva))
            if decoded:
                ins = decoded[0]
                recent.append({
                    "rva": hex(rva), "instruction": ins.mnemonic + " " + ins.op_str,
                    "rax": hex(emulator.reg_read(UC_X86_REG_RAX)),
                    "rdi": hex(emulator.reg_read(UC_X86_REG_RDI)),
                    "rsi": hex(emulator.reg_read(UC_X86_REG_RSI)),
                    "rcx": hex(emulator.reg_read(UC_X86_REG_RCX)),
                })
        except Exception:
            pass
        if first <= rva < first+179:
            trace["first_initializer_instruction_count"] += 1
        if tail <= rva < tail+518:
            trace["tail_instruction_count"] += 1
        if len(reached) < 80 and (not reached or reached[-1] != rva):
            # Representative sampled original instruction RVAs, no code bytes.
            if len(reached) < 8 or trace["original_instruction_count"] % 50 == 0:
                reached.append(rva)

    def write_hook(emulator, _access, address, size, _value, _):
        if IMAGE_BASE <= address < IMAGE_BASE + round4k(last_section):
            trace["globals_written"] += 1
            write_regions[hex((address-IMAGE_BASE) & ~0xfff)] += 1

    def invalid_mem(emu, access, address, length, value, _):
        rip = emu.reg_read(UC_X86_REG_RIP)
        pc_rva = rip - IMAGE_BASE
        regs = {
            "rax": hex(emu.reg_read(UC_X86_REG_RAX)),
            "rcx": hex(emu.reg_read(UC_X86_REG_RCX)),
            "rdx": hex(emu.reg_read(UC_X86_REG_RDX)),
            "r8": hex(emu.reg_read(UC_X86_REG_R8)),
            "rsp": hex(emu.reg_read(UC_X86_REG_RSP)),
        }
        trace["memory_fault"] = {
            "access_kind": int(access), "fault_address": hex(address),
            "size_bytes": int(length),
            "pc_rva": hex(pc_rva) if 0 <= pc_rva < last_section else "outside_image",
            "guest_registers": regs,
        }
        if 0 <= pc_rva < last_section:
            try:
                decoder = Cs(CS_ARCH_X86, CS_MODE_64)
                instructions = list(decoder.disasm(pe.read_rva(pc_rva, 15), pc_rva))
                if instructions:
                    ins = instructions[0]
                    trace["faulting_instruction"] = ins.mnemonic + " " + ins.op_str
            except Exception:
                pass
        return False

    uc.hook_add(UC_HOOK_CODE, code_hook)
    uc.hook_add(UC_HOOK_MEM_WRITE, write_hook)
    uc.hook_add(UC_HOOK_MEM_INVALID, invalid_mem)
    # Resume after constructing a real callback trampoline. Do not clear a
    # blocked dependency or skip any original initializer code.
    start_va = IMAGE_BASE + entry
    for _ in range(8):
        try:
            uc.emu_start(start_va, 0, timeout=MAX_SECONDS_MICRO,
                         count=max(1, MAX_INSNS-trace["original_instruction_count"]-
                                   trace["crt_trampoline_instructions"]))
        except Exception as exc:
            trace["first_exception"] = type(exc).__name__ + ": " + str(exc)[:180]
            if not trace["stop_reason"]:
                trace["stop_reason"] = "emulator_exception"
        if trace["stop_reason"] != "crt_trampoline_pending":
            break
        if not pending_callbacks or len(trampoline_ranges) >= 6:
            trace["stop_reason"] = "crt_trampoline_capacity"
            break
        callbacks, checks_failure = pending_callbacks.pop(0)
        try:
            thunk = build_initializer_trampoline(callbacks, error_return=checks_failure)
        except Exception as exc:
            trace["first_exception"] = type(exc).__name__ + ": " + str(exc)[:180]
            trace["stop_reason"] = "crt_trampoline_generation_error"
            break
        addr = CRT_TRAMPOLINE_START + len(trampoline_ranges)*0x1000
        uc.mem_write(addr, thunk)
        trampoline_ranges.append((addr, addr+len(thunk)))
        trace["crt_emitted_trampolines"] += 1
        trace["crt_original_callbacks_expected"] += len(callbacks)
        trace["stop_reason"] = None
        start_va = addr
    if trace["stop_reason"] is None:
        trace["stop_reason"] = "instruction_count_or_timeout"
    stopped_pc = uc.reg_read(UC_X86_REG_RIP)
    trace["last_rva"] = (hex(stopped_pc-IMAGE_BASE)
                         if IMAGE_BASE <= stopped_pc < IMAGE_BASE + round4k(last_section)
                         else "external_or_unmapped")
    trace["original_targets_visited"] = [hex(rva) for rva in reached]
    trace["windows_imports_called"] = dict(calls)
    trace["file_bridge"] = files.diagnostics()
    trace["mapped_crt_data_imports"] = data_imports
    trace["recent_original_instructions"] = list(recent)
    trace["global_write_pages"] = dict(write_regions.most_common(12))
    trace["execution_bound"] = {"max_guest_instructions": MAX_INSNS, "timeout_microseconds": MAX_SECONDS_MICRO}
    # Caller must interpret this as a diagnostic, not pass of engine startup.
    return trace


def main():
    if len(sys.argv) != 4:
        raise SystemExit("usage: mxbikes_crt_frontier.py <EXE> <REPORT_DIRECTORY> <PRIVATE_GAME_ZIP>")
    reports = Path(sys.argv[2])
    reports.mkdir(parents=True, exist_ok=True)
    result = run_frontier(sys.argv[1], sys.argv[3])
    (reports/"crt-frontier.json").write_text(json.dumps(result,indent=2)+"\n")
    lines=[
        "# MX Bikes real x64 CRT execution frontier", "",
        f"- Original instructions executed: {result['original_instruction_count']}",
        f"- Fault-related CRT import slot: {result['suspected_crt_data_iat_rva']} = {result['suspected_crt_data_import']}",
        f"- Correctly mapped imported CRT data symbols: {len(result['mapped_crt_data_imports'])}",
        f"- Instructions in first CRT initializer: {result['first_initializer_instruction_count']}",
        f"- Instructions in second CRT routine: {result['tail_instruction_count']}",
        f"- Simulated import returns: {result['synthetic_import_returns']}",
        f"- Original PE global-memory writes: {result['globals_written']}",
        f"- Stop reason: {result['stop_reason']}",
        f"- Stopped near RVA: {result['last_rva']}",
        f"- First unsupported Windows import: {result['unimplemented_import'] or 'none'}",
        f"- Original guest stack return RVA at unsupported import (NOT executed): {result['unsupported_import_stack_return_rva'] or 'unknown'}",
        f"- First emulator exception: {result['first_exception'] or 'none'}",
        f"- Faulting instruction: {result['faulting_instruction'] or 'none'}",
        f"- Unmapped memory address: {(result['memory_fault'] or {}).get('fault_address', 'none')}",
        f"- Faulting guest instruction RVA: {(result['memory_fault'] or {}).get('pc_rva', 'none')}",
        f"- CRT callback tables inspected: {len(result['crt_initializer_tables'])}",
        f"- Original exit handlers registered but NOT executed: {len(result['registered_exit_callbacks'])}",
        f"- Synthetic command-line argument count: {result['synthetic_command_line_arguments']}",
        f"- Synthetic executable path requests: {result['synthetic_executable_path_requests']}",
        f"- Modeled current working directory: {result['synthetic_current_directory'] or 'not requested'}",
        f"- First requested file: {(result['first_file_open'] or {}).get('filename', 'not reached')}",
        f"- First requested file mode: {(result['first_file_open'] or {}).get('mode', 'not reached')}",
        f"- Real guest file opens: {result['file_bridge']['opens']}",
        f"- Real DLL bytes delivered to original x64 code: {result['file_bridge']['bytes_delivered_to_guest']}",
        f"- Synthetic Steam restart-check results: {result['synthetic_steam_restart_checks']}",
        f"- Guest file reads / closes: {result['file_bridge']['read_calls']} / {result['file_bridge']['closes']}",
        f"- Guest file error: {result['guest_file_error'] or 'none'}",
        f"- Bounded CRT string copies: {result['synthetic_crt_string_copies']}",
        f"- Modeled Microsoft CRT application type: {result['synthetic_crt_app_type']}",
        f"- Synthetic unhandled-exception filter registrations: {result['synthetic_filter_installations']}",
        f"- Synthetic pointer token encodes/decodes: {result['synthetic_pointer_encoding_calls']}/{result['synthetic_pointer_decoding_calls']}",
        f"- Original CRT callback entries reached: {result['crt_original_callback_entries']}",
        f"- Original callback targets requested: {result['crt_original_callbacks_expected']}",
        f"- Synthetic Win64 CRT trampolines built: {result['crt_emitted_trampolines']}",
        "", "## Imported Windows functions encountered", ""
    ]
    lines += [f"- {name} ({count})" for name,count in result["windows_imports_called"].items()]
    for table in result["crt_initializer_tables"]:
        lines += [f"- {table['api']}: {table['total_slots']} table entries; {table['non_null_callbacks']} real initializer callbacks"]
    lines += ["", "## Previous original instructions (register snapshot at entry)", ""]
    for item in result["recent_original_instructions"][-12:]:
        lines.append("- " + item["rva"] + ": " + item["instruction"] +
                     " [RDI=" + item["rdi"] + ", RAX=" + item["rax"] + "]")
    lines += ["","Nonempty CRT tables are executed via deterministic guest call trampolines; no original constructors are silently skipped.",
              "Pointer encoding is an explicitly synthetic reversible stand-in, not Microsoft's real process encoding.",
              "Only original x64 instructions were emulated. Real Windows APIs, ARM64 startup, rendering and menu boot were NOT tested.", ""]
    summary="\n".join(lines)
    (reports/"crt-frontier.md").write_text(summary)
    print(summary)
    if result["stop_reason"] in {"emulator_exception", "invalid_crt_initializer_table",
                                "invalid_onexit_registration",
                                "crt_trampoline_generation_error"}:
        raise RuntimeError("CRT trace failed: " + str(result["first_exception"] or result["stop_reason"]))


if __name__ == "__main__":
    main()
