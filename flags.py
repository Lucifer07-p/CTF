"""
Flag candidate extraction and verification.

Deliberately NOT "first regex match wins": every candidate carries a source
and evidence list, and status is only ever CONFIRMED when a second,
independent signal backs it up (recomputation, or an explicit challenge
format match combined with a successful decode chain). Everything else is
PROBABLE or UNCONFIRMED and is surfaced to the user as such.
"""
import re
from dataclasses import dataclass, field

PATTERNS = [
    re.compile(r"flag\{[^{}]{1,500}\}", re.IGNORECASE),
    re.compile(r"ctf\{[^{}]{1,500}\}", re.IGNORECASE),
]


@dataclass
class FlagCandidate:
    candidate: str
    source: str
    confidence: float
    evidence: list[str] = field(default_factory=list)
    status: str = "UNCONFIRMED"


def extract_candidates(text: str, source: str) -> list[FlagCandidate]:
    if not text:
        return []
    found = []
    seen = set()
    for pattern in PATTERNS:
        for m in pattern.finditer(text):
            val = m.group(0)
            if val in seen:
                continue
            seen.add(val)
            found.append(FlagCandidate(
                candidate=val,
                source=source,
                confidence=0.6,
                evidence=[f"Matched flag format via regex in {source}"],
            ))
    return found


def verify(candidate: FlagCandidate, *, decode_chain_succeeded: bool = False,
           reproduced_independently: bool = False) -> FlagCandidate:
    """Upgrade a candidate's status based on corroborating evidence. Pure function."""
    score = candidate.confidence
    evidence = list(candidate.evidence)

    if decode_chain_succeeded:
        score += 0.2
        evidence.append("Produced at the end of a successful decode/extraction chain")
    if reproduced_independently:
        score += 0.2
        evidence.append("Reproduced by an independent extraction method")

    score = min(score, 0.99)

    if reproduced_independently and decode_chain_succeeded:
        status = "CONFIRMED"
    elif score >= 0.75:
        status = "PROBABLE"
    else:
        status = "UNCONFIRMED"

    return FlagCandidate(candidate=candidate.candidate, source=candidate.source,
                          confidence=round(score, 2), evidence=evidence, status=status)
