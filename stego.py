"""
Image steganography: PNG ancillary chunk inspection, LSB extraction, colour
channel isolation. Pure Python + Pillow, no external binaries required.
"""
import struct
from PIL import Image

STANDARD_PNG_CHUNKS = {"IHDR", "IDAT", "IEND", "PLTE", "gAMA", "sRGB", "pHYs", "tIME", "tEXt", "zTXt", "iTXt"}


def parse_png_chunks(path: str) -> list[dict]:
    chunks = []
    with open(path, "rb") as f:
        data = f.read()
    if not data.startswith(b"\x89PNG\r\n\x1a\n"):
        return chunks
    i = 8
    while i + 8 <= len(data):
        length = struct.unpack(">I", data[i:i + 4])[0]
        ctype = data[i + 4:i + 8].decode("latin-1")
        payload_start = i + 8
        payload = data[payload_start:payload_start + length]
        chunks.append({
            "type": ctype,
            "length": length,
            "standard": ctype in STANDARD_PNG_CHUNKS,
            "preview": payload[:80].decode("latin-1", errors="replace"),
        })
        i = payload_start + length + 4  # skip CRC
        if ctype == "IEND":
            break
    return chunks


def extract_lsb_text(path: str, channel: str = "all", max_bits: int = 200_000) -> str:
    """Extract the least-significant bit of each pixel channel, in row-major
    order, and decode as ASCII bytes until a null terminator or max_bits."""
    img = Image.open(path).convert("RGBA")
    pixels = img.getdata()
    channel_idx = {"r": [0], "g": [1], "b": [2], "a": [3], "all": [0, 1, 2]}[channel]

    bits = []
    for px in pixels:
        for idx in channel_idx:
            bits.append(px[idx] & 1)
            if len(bits) >= max_bits:
                break
        if len(bits) >= max_bits:
            break

    byte_chunks = [bits[i:i + 8] for i in range(0, len(bits) - 7, 8)]
    out_bytes = bytearray()
    for chunk in byte_chunks:
        val = 0
        for bit in chunk:
            val = (val << 1) | bit
        if val == 0:
            break
        out_bytes.append(val)
    return out_bytes.decode("utf-8", errors="replace")


def split_channels(path: str, out_prefix: str) -> dict[str, str]:
    img = Image.open(path).convert("RGBA")
    r, g, b, a = img.split()
    paths = {}
    for name, channel in [("red", r), ("green", g), ("blue", b), ("alpha", a)]:
        out_path = f"{out_prefix}_{name}.png"
        channel.save(out_path)
        paths[name] = out_path
    return paths
