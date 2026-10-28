"""Private archive loader for exact file requested by MX Bikes CRT.

The original commercial DLL is read in-memory from the owner's private ZIP
during an ephemeral GitHub Actions job. Only aggregate diagnostics are exported.
"""
from pathlib import Path, PurePosixPath
import zipfile

MAX_DLL = 1024 * 1024
DLL_NAME = "steam_api64.dll"


def load_startup_dll(archive_path):
    archive = Path(archive_path)
    if not archive.is_file():
        raise FileNotFoundError("Private original game archive unavailable")
    with zipfile.ZipFile(archive) as zf:
        matches = [info for info in zf.infolist()
                   if not info.is_dir() and
                   PurePosixPath(info.filename.replace("\\", "/")).name.casefold() == DLL_NAME]
        if len(matches) != 1:
            raise RuntimeError("Expected one original Steam DLL member")
        item = matches[0]
        if item.file_size != 250656 or item.file_size > MAX_DLL:
            raise RuntimeError("Original Steam DLL size/revision mismatch")
        with zf.open(item) as handle:
            payload = handle.read(MAX_DLL+1)
    if len(payload) != item.file_size or len(payload) > MAX_DLL:
        raise RuntimeError("Private DLL read failed size verification")
    if payload[:2] != b"MZ":
        raise RuntimeError("Original DLL is not a Windows PE image")
    return payload
