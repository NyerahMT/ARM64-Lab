"""Read-only, fail-closed guest CRT file bridge for controlled emulation.

Works with in-memory bytes supplied by the host. Never opens the host filesystem
from an untrusted guest path. Guest FILE* values are opaque tokens, not MSVCRT
FILE structs. Direct dereferences of those tokens must fault in the guest.
"""
from __future__ import annotations

import io
from dataclasses import dataclass

MAX_FILE_BYTES = 2 * 1024 * 1024
MAX_READ_BYTES = 512 * 1024
MAX_OPEN_FILES = 16
HANDLE_START = 0x7B00000000
HANDLE_STRIDE = 0x1000


class GuestFileError(ValueError):
    """Unsupported or invalid guest I/O operation."""


@dataclass
class _FileState:
    name: str
    stream: io.BytesIO
    eof: bool = False
    error: bool = False


class GuestFileBridge:
    def __init__(self, files: dict[str, bytes]):
        if not isinstance(files, dict):
            raise GuestFileError("Expected a static file allowlist")
        self._files = {}
        for name, contents in files.items():
            if not isinstance(name, str) or not name or "/" in name or "\\" in name or ".." in name:
                raise GuestFileError("Only explicitly named basenames are allowed")
            if not isinstance(contents, bytes) or len(contents) > MAX_FILE_BYTES:
                raise GuestFileError("Invalid/oversized allowlisted file")
            key = name.casefold()
            if key in self._files:
                raise GuestFileError("Duplicate allowlisted filename")
            self._files[key] = contents
        self._open: dict[int, _FileState] = {}
        self._next = 0
        self.read_calls = 0
        self.bytes_delivered = 0
        self.open_calls = 0
        self.close_calls = 0

    def fopen(self, guest_filename: str, mode: str) -> int:
        self.open_calls += 1
        if mode != "rb":
            raise GuestFileError("Only binary read mode is supported")
        # Fail closed on unexpected paths; do not normalize traversal/symlinks.
        if not guest_filename or "/" in guest_filename or "\\" in guest_filename or ".." in guest_filename:
            raise GuestFileError("Guest requested an unapproved path")
        contents = self._files.get(guest_filename.casefold())
        if contents is None:
            raise GuestFileError("Guest requested an unallowlisted filename")
        if len(self._open) >= MAX_OPEN_FILES:
            raise GuestFileError("Guest open-file budget exceeded")
        handle = HANDLE_START + self._next * HANDLE_STRIDE
        self._next += 1
        self._open[handle] = _FileState(guest_filename, io.BytesIO(contents))
        return handle

    def _lookup(self, handle: int) -> _FileState:
        if handle not in self._open:
            raise GuestFileError("Unknown or closed guest file handle")
        return self._open[handle]

    def fread(self, handle: int, size: int, count: int) -> tuple[bytes, int]:
        state = self._lookup(handle)
        if not (0 <= size <= MAX_READ_BYTES and 0 <= count <= MAX_READ_BYTES):
            raise GuestFileError("Invalid read size or count")
        if size == 0 or count == 0:
            return b"", 0
        if size > MAX_READ_BYTES // count:
            raise GuestFileError("Guest read exceeds per-call byte budget")
        payload = state.stream.read(size * count)
        self.read_calls += 1
        self.bytes_delivered += len(payload)
        state.eof = len(payload) < size * count
        return payload, len(payload) // size

    def fseek(self, handle: int, offset: int, whence: int) -> int:
        state = self._lookup(handle)
        if not -(1 << 31) <= offset < (1 << 31):
            raise GuestFileError("fseek expects 32-bit signed long offset")
        if whence not in (0, 1, 2):
            raise GuestFileError("Unsupported seek origin")
        target_base = (0, state.stream.tell(), len(state.stream.getbuffer()))[whence]
        if target_base + offset < 0:
            return -1
        state.stream.seek(offset, whence)
        state.eof = False
        return 0

    def ftell(self, handle: int) -> int:
        pos = self._lookup(handle).stream.tell()
        if pos > 0x7fffffff:
            return -1
        return pos

    def fgetc(self, handle: int) -> int:
        state = self._lookup(handle)
        payload = state.stream.read(1)
        self.read_calls += 1
        self.bytes_delivered += len(payload)
        if not payload:
            state.eof = True
            return -1
        return payload[0]

    def feof(self, handle: int) -> int:
        return int(self._lookup(handle).eof)

    def ferror(self, handle: int) -> int:
        return int(self._lookup(handle).error)

    def rewind(self, handle: int) -> None:
        state = self._lookup(handle)
        state.stream.seek(0)
        state.eof = False
        state.error = False

    def fclose(self, handle: int) -> int:
        state = self._lookup(handle)
        state.stream.close()
        del self._open[handle]
        self.close_calls += 1
        return 0

    def diagnostics(self) -> dict:
        return {
            "allowlisted_filenames": sorted(self._files),
            "opens": self.open_calls,
            "read_calls": self.read_calls,
            "bytes_delivered_to_guest": self.bytes_delivered,
            "closes": self.close_calls,
            "handles_still_open": len(self._open),
        }
