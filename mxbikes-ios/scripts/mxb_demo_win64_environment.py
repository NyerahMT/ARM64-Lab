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
