import base64
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "apps", "api"))

from app.tools import crypto
from app import flags as flag_logic


def test_base64_roundtrip_finds_flag():
    flag = "flag{b4se64_is_not_encryption}"
    encoded_message = base64.b64encode(flag.encode()).decode()
    hits = crypto.try_base64(encoded_message)
    assert any(flag in h["output"] for h in hits)


def test_xor_single_byte_bruteforce_recovers_flag():
    flag = b"flag{sing1e_byte_x0r_brut3force}"
    key = 0x42
    data = bytes(b ^ key for b in flag)
    hits = crypto.xor_single_byte_bruteforce(data)
    assert any(h["key"] == key and h["output"] == flag.decode() for h in hits)


def test_caesar_all_shifts_covers_every_shift():
    shifts = crypto.caesar_all_shifts("Uryyb")
    assert len(shifts) == 25
    assert any(s["output"] == "Hello" for s in shifts)


def test_flag_extraction_from_decoded_text():
    candidates = flag_logic.extract_candidates("here is flag{example_flag} in text", "test")
    assert len(candidates) == 1
    assert candidates[0].candidate == "flag{example_flag}"


def test_flag_verification_requires_two_signals_for_confirmed():
    c = flag_logic.FlagCandidate(candidate="flag{x}", source="test", confidence=0.6, evidence=["regex match"])
    unconfirmed = flag_logic.verify(c)
    assert unconfirmed.status in ("UNCONFIRMED", "PROBABLE")

    confirmed = flag_logic.verify(c, decode_chain_succeeded=True, reproduced_independently=True)
    assert confirmed.status == "CONFIRMED"
