import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "apps", "api"))

from app.tools import forensics

DEMO_DIR = os.path.join(os.path.dirname(__file__), "..", "demo_challenges")


def test_identify_signature_png():
    path = os.path.join(DEMO_DIR, "03_image_stego", "hidden.png")
    assert forensics.identify_signature(path) == "PNG image"


def test_find_appended_zip_after_png():
    path = os.path.join(DEMO_DIR, "04_zip_hidden_file", "innocent.png")
    trailing = forensics.find_trailing_data_after_png_iend(path)
    assert trailing is not None
    assert trailing.startswith(b"PK\x03\x04")


def test_extract_strings_finds_embedded_flag():
    path = os.path.join(DEMO_DIR, "05_metadata_forensics", "notes.bin")
    strings_found = forensics.extract_strings(path)
    assert any("flag{strings_find_what_grep_misses}" in s for s in strings_found)


def test_zip_extraction_rejects_path_traversal(tmp_path):
    import zipfile

    evil_zip = tmp_path / "evil.zip"
    with zipfile.ZipFile(evil_zip, "w") as zf:
        zf.writestr("../../etc/passwd_clone", "not actually /etc/passwd")
        zf.writestr("normal.txt", "fine")

    dest = tmp_path / "extracted"
    extracted = forensics.extract_zip(str(evil_zip), str(dest))

    for path in extracted:
        assert os.path.abspath(path).startswith(os.path.abspath(str(dest)))
    assert any(p.endswith("normal.txt") for p in extracted)
