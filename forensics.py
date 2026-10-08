"""
Forensics: file typing, metadata, strings extraction, archive handling.
Uses external tools when present in the sandbox (file, exiftool, binwalk,
unzip) via app.sandbox.run_tool, and falls back to pure-Python equivalents
so the system still works in a minimal container.
"""
import hashlib
import math
import re
import zipfile
import os

from app.sandbox import run_tool, tool_available

MAGIC_SIGNATURES = {
    b"\x89PNG\r\n\x1a\n": "PNG image",
    b"\xff\xd8\xff": "JPEG image",
    b"GIF87a": "GIF image",
    b"GIF89a": "GIF image",
    b"PK\x03\x04": "ZIP archive",
    b"%PDF": "PDF document",
    b"\x7fELF": "ELF binary",
    b"MZ": "PE/DOS executable",
    b"RIFF": "RIFF (WAV/AVI) container",
}


def sha256_of(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def identify_signature(path: str) -> str:
    with open(path, "rb") as f:
        head = f.read(16)
    for sig, label in MAGIC_SIGNATURES.items():
        if head.startswith(sig):
            return label
    return "unknown binary data"


def entropy(path: str, sample_bytes: int = 1_000_000) -> float:
    with open(path, "rb") as f:
        data = f.read(sample_bytes)
    if not data:
        return 0.0
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    n = len(data)
    ent = 0.0
    for c in counts:
        if c:
            p = c / n
            ent -= p * math.log2(p)
    return round(ent, 3)


def extract_strings(path: str, min_len: int = 4, limit: int = 2000) -> list[str]:
    pattern = re.compile(rb"[\x20-\x7e]{%d,}" % min_len)
    with open(path, "rb") as f:
        data = f.read()
    found = [m.decode("ascii") for m in pattern.findall(data)]
    return found[:limit]


async def run_file_cmd(path: str) -> str:
    if tool_available("file"):
        result = await run_tool(["file", "-b", path], cwd=os.path.dirname(path) or ".")
        if result.success:
            return result.stdout.strip()
    return identify_signature(path)


async def run_exiftool(path: str) -> str | None:
    if not tool_available("exiftool"):
        return None
    result = await run_tool(["exiftool", path], cwd=os.path.dirname(path) or ".")
    return result.stdout if result.success else None


def find_appended_data_after_zip_eocd(path: str) -> bytes | None:
    """A classic forensics trick: data appended after a ZIP's End Of Central
    Directory record. zipfile reads the ZIP fine but ignores trailing bytes."""
    with open(path, "rb") as f:
        data = f.read()
    eocd_sig = b"PK\x05\x06"
    idx = data.rfind(eocd_sig)
    if idx == -1:
        return None
    # EOCD record is 22 bytes + comment length (last 2 bytes of fixed part)
    comment_len = int.from_bytes(data[idx + 20:idx + 22], "little")
    end_of_zip = idx + 22 + comment_len
    trailing = data[end_of_zip:]
    return trailing if trailing else None


def find_trailing_data_after_png_iend(path: str) -> bytes | None:
    """The classic 'ZIP appended after a PNG' trick: a viewer renders the PNG
    fine and ignores everything after the IEND chunk, but that trailing data
    is still there on disk (and is often itself a valid ZIP/file)."""
    with open(path, "rb") as f:
        data = f.read()
    if not data.startswith(b"\x89PNG\r\n\x1a\n"):
        return None
    iend_sig = b"IEND"
    idx = data.find(iend_sig)
    if idx == -1:
        return None
    # IEND chunk: 4-byte length (always 0) + "IEND" + 4-byte CRC.
    end_of_iend_chunk = idx + len(iend_sig) + 4
    trailing = data[end_of_iend_chunk:]
    return trailing if trailing else None


def extract_zip(path: str, dest_dir: str, max_files: int = 500, max_total_bytes: int = 200_000_000) -> list[str]:
    """Extract a ZIP safely: guard against path traversal (zip-slip) and
    archive bombs with file-count / total-size caps."""
    os.makedirs(dest_dir, exist_ok=True)
    extracted = []
    total = 0
    with zipfile.ZipFile(path) as zf:
        for i, info in enumerate(zf.infolist()):
            if i >= max_files:
                break
            member_path = os.path.normpath(os.path.join(dest_dir, info.filename))
            if not member_path.startswith(os.path.abspath(dest_dir) + os.sep) and member_path != dest_dir:
                continue  # zip-slip guard: skip anything that would escape dest_dir
            total += info.file_size
            if total > max_total_bytes:
                break
            if info.is_dir():
                os.makedirs(member_path, exist_ok=True)
                continue
            os.makedirs(os.path.dirname(member_path), exist_ok=True)
            with zf.open(info) as src, open(member_path, "wb") as dst:
                dst.write(src.read())
            extracted.append(member_path)
    return extracted
