"""Small deterministic Win64 process environment for the public demo runner.

Not a Windows loader, Steam service, or licensing implementation.
Only documented structure fields are initialized; no PEB or TLS is fabricated.
"""
import struct

STARTUPINFOA_SIZE = 104
TEB_PAGE_SIZE = 4096


def startup_info_a():
    """Minimal STARTUPINFOA with cb set; flags zero, no inherited handles."""
    info = bytearray(STARTUPINFOA_SIZE)
    struct.pack_into("<I", info, 0, STARTUPINFOA_SIZE)
    return bytes(info)


def thread_environment(teb, stack_base, stack_limit, pid, tid):
    """Minimal x64 NT_TIB and ClientId fields used by single-thread CRT."""
    if not (0 < teb <= (1 << 64) - TEB_PAGE_SIZE and teb % TEB_PAGE_SIZE == 0
            and 0 < stack_limit < stack_base < 1 << 64
            and 0 < pid < 1 << 64 and 0 < tid < 1 << 64):
        raise ValueError("invalid_thread_environment")
    page = bytearray(TEB_PAGE_SIZE)
    for off, value in ((0, (1 << 64) - 1), (8, stack_base),
                       (0x10, stack_limit), (0x30, teb),
                       (0x40, pid), (0x48, tid)):
        struct.pack_into("<Q", page, off, value)
    return bytes(page)


def checked_write(write, regions, ptr, data):
    """Never allow host writes into an RX, absent, or cross-region destination."""
    end = ptr + len(data)
    if not (0 < ptr < end <= 1 << 64 and
            any(lo <= ptr and end <= hi for lo, hi in regions)):
        raise ValueError("unmapped_or_read_only_output_pointer")
    write(ptr, data)


# A deterministic virtual Windows executable path, not a host path, account,
# Steam identity, or licensed content. Both encodings refer to the same image.
VIRTUAL_EXE_PATH = r"C:\MXBReference\mxbikes.exe"
COMMAND_LINE_A = (VIRTUAL_EXE_PATH + "\0").encode("ascii")
COMMAND_LINE_W = (VIRTUAL_EXE_PATH + "\0").encode("utf-16le")

PROCESS_ENVIRONMENT_APIS = frozenset({
    "getmodulehandlea", "getmodulehandlew", "getmodulefilenamea",
    "getmodulefilenamew", "getcommandlinea", "getcommandlinew",
    "getcurrentprocess", "getcurrentthread",
})

def process_strings(page_size=4096):
    """Immutable synthetic command-line strings; return offsets and page bytes."""
    if not 256 <= page_size <= 65536:
        raise ValueError("invalid_process_strings_page_size")
    page = bytearray(page_size)
    a, w = 0, 128
    if len(COMMAND_LINE_A) > w or w + len(COMMAND_LINE_W) > page_size:
        raise ValueError("process_strings_overflow")
    page[a:a+len(COMMAND_LINE_A)] = COMMAND_LINE_A
    page[w:w+len(COMMAND_LINE_W)] = COMMAND_LINE_W
    return a, w, bytes(page)


def process_service(name, args, *, image_base, command_a, command_w, write, writable):
    """Implement only bounded, documented current-process environment calls.

    A named DLL request or truncated filename needs a real module/error model:
    reject instead of falsely reporting success. No licensing API is handled.
    """
    rcx, rdx, r8 = args
    if name in ("getmodulehandlea", "getmodulehandlew"):
        if rcx != 0:
            raise ValueError("named_module_lookup_not_implemented")
        return image_base
    if name in ("getmodulefilenamea", "getmodulefilenamew"):
        if rcx not in (0, image_base):
            raise ValueError("foreign_module_lookup_not_implemented")
        wide = name.endswith("w")
        data = COMMAND_LINE_W if wide else COMMAND_LINE_A
        width = 2 if wide else 1
        chars = len(data) // width
        capacity = r8 & 0xffffffff
        if not chars <= capacity <= 32768:
            raise ValueError("module_filename_buffer_too_small_or_large")
        checked_write(write, writable, rdx, data)
        return chars - 1
    if name == "getcommandlinea":
        return command_a
    if name == "getcommandlinew":
        return command_w
    if name == "getcurrentprocess":
        return (1 << 64) - 1
    if name == "getcurrentthread":
        return (1 << 64) - 2
    raise ValueError("unsupported_process_environment_service")
