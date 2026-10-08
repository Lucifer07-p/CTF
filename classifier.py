"""
Challenge classifier: assigns a probability-like score per category from the
description text and the artifact types present. This is intentionally
simple (keyword + artifact-type signals, normalized) rather than an LLM
call, so classification is instant, free, and reproducible -- the spec
explicitly asks not to assume category from the title alone, and not to
burn an expensive model call on this step. The orchestrator still runs
every specialist above a confidence threshold, not just the top-1.
"""
import re

CATEGORY_KEYWORDS = {
    "crypto": ["encrypt", "decrypt", "cipher", "rsa", "aes", "xor", "base64", "hash",
               "key", "modulus", "prime", "vigenere", "caesar", "rot13"],
    "forensics": ["pcap", "memory dump", "disk image", "metadata", "hidden file",
                  "recover", "deleted", "network capture", "wireshark"],
    "stego": ["image", "hidden inside", "steganography", "lsb", "spectrogram",
              "audio", "png", "jpeg", "pixel"],
    "web": ["website", "http", "login", "cookie", "api", "endpoint", "sql injection",
            "xss", "jwt", "server"],
    "reverse": ["binary", "reverse engineer", "disassemble", "elf", ".exe", "apk",
                "decompile"],
    "osint": ["social media", "username", "profile", "search engine", "public records"],
    "misc": ["puzzle", "riddle", "encode", "qr code", "math"],
}

ARTIFACT_SIGNALS = {
    ".png": "stego", ".jpg": "stego", ".jpeg": "stego", ".gif": "stego", ".bmp": "stego",
    ".wav": "stego", ".mp3": "stego",
    ".pcap": "forensics", ".pcapng": "forensics", ".img": "forensics", ".dd": "forensics",
    ".zip": "forensics", ".7z": "forensics", ".rar": "forensics",
    ".exe": "reverse", ".elf": "reverse", ".apk": "reverse", ".so": "reverse", ".bin": "reverse",
    ".py": "misc", ".txt": "misc",
}


def classify(description: str, artifact_names: list[str], has_urls: bool) -> dict[str, float]:
    text = description.lower()
    scores = {cat: 0.0 for cat in CATEGORY_KEYWORDS}

    for cat, keywords in CATEGORY_KEYWORDS.items():
        for kw in keywords:
            if kw in text:
                scores[cat] += 1.0

    for name in artifact_names:
        lower = name.lower()
        for ext, cat in ARTIFACT_SIGNALS.items():
            if lower.endswith(ext):
                scores[cat] += 1.5

    if has_urls:
        scores["web"] += 1.0
        scores["forensics"] += 0.3

    if re.search(r"flag\{", text):
        scores["misc"] += 0.2  # someone pasted an example/partial flag format

    total = sum(scores.values())
    if total == 0:
        # No signal at all: spread evenly but keep it low-confidence.
        n = len(scores)
        return {cat: round(1 / n, 3) for cat in scores}

    normalized = {cat: round(v / total, 3) for cat, v in scores.items()}
    return normalized
