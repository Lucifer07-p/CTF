"""
Deterministic crypto operations. Per spec section: use code, not LLM
reasoning, for anything mathematical. Every function returns plain data the
orchestrator can feed into flag extraction.
"""
import base64
import binascii
import re
import string

PRINTABLE = set(string.printable) - set("\x0b\x0c")


def _printable_ratio(s: str) -> float:
    if not s:
        return 0.0
    return sum(c in PRINTABLE for c in s) / len(s)


def try_base64(text: str) -> list[dict]:
    results = []
    candidates = re.findall(r"[A-Za-z0-9+/]{8,}={0,2}", text)
    for c in set(candidates):
        try:
            decoded = base64.b64decode(c, validate=True)
            s = decoded.decode("utf-8", errors="replace")
            if _printable_ratio(s) > 0.6:
                results.append({"input": c, "output": s, "method": "base64"})
        except Exception:
            continue
    return results


def try_hex(text: str) -> list[dict]:
    results = []
    for c in set(re.findall(r"(?:[0-9a-fA-F]{2}){4,}", text)):
        try:
            decoded = binascii.unhexlify(c)
            s = decoded.decode("utf-8", errors="replace")
            if _printable_ratio(s) > 0.6:
                results.append({"input": c, "output": s, "method": "hex"})
        except Exception:
            continue
    return results


def caesar_all_shifts(text: str) -> list[dict]:
    out = []
    for shift in range(1, 26):
        shifted = []
        for ch in text:
            if ch.isupper():
                shifted.append(chr((ord(ch) - 65 + shift) % 26 + 65))
            elif ch.islower():
                shifted.append(chr((ord(ch) - 97 + shift) % 26 + 97))
            else:
                shifted.append(ch)
        out.append({"shift": shift, "output": "".join(shifted), "method": "caesar"})
    return out


def xor_single_byte_bruteforce(data: bytes) -> list[dict]:
    results = []
    for key in range(256):
        decoded = bytes(b ^ key for b in data)
        try:
            s = decoded.decode("utf-8", errors="strict")
        except UnicodeDecodeError:
            continue
        if _printable_ratio(s) > 0.85:
            results.append({"key": key, "output": s, "method": "xor_single_byte"})
    return results


def xor_with_key(data: bytes, key: bytes) -> bytes:
    return bytes(b ^ key[i % len(key)] for i, b in enumerate(data))
