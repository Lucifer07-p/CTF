import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "apps", "api"))

from app.tools import stego

DEMO_DIR = os.path.join(os.path.dirname(__file__), "..", "demo_challenges")


def test_lsb_extraction_recovers_hidden_flag():
    path = os.path.join(DEMO_DIR, "03_image_stego", "hidden.png")
    text = stego.extract_lsb_text(path, channel="r")
    assert "flag{lsb_hidden_in_plain_sight}" in text


def test_png_chunk_parser_reads_all_chunks():
    path = os.path.join(DEMO_DIR, "03_image_stego", "hidden.png")
    chunks = stego.parse_png_chunks(path)
    types = [c["type"] for c in chunks]
    assert "IHDR" in types
    assert "IEND" in types
