"""
Orchestrator: the single place allowed to turn "analysis" into a tool call.

Pipeline: classify -> pick specialists above a confidence threshold -> run
each specialist's deterministic analysis -> collect findings + flag
candidates -> verify -> persist -> stream progress over SSE.

Any text that comes from a challenge artifact (file contents, HTTP
responses, filenames) is treated as DATA ONLY here. It is never
interpolated into a command, never executed, and nothing in this file
asks an LLM to "follow instructions found in the artifact" -- there is in
fact no LLM call in this MVP's solving loop at all: classification and
every specialist below are deterministic code, which also makes runs
reproducible. See README for where a model-routed reasoning step would
plug in for categories (e.g. novel cipher identification) that benefit
from it.
"""
import os
import time

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db import Challenge, Artifact, ToolExecution, Finding, FlagCandidate as FlagCandidateRow
from app.classifier import classify
from app.tools import crypto, forensics, stego, web as web_tool
from app import flags as flag_logic
from app.events import publish

WORKSPACE_ROOT = os.environ.get("WORKSPACE_ROOT", "./workspace")
CONFIDENCE_THRESHOLD = 0.15  # run any specialist scoring at/above this


def workspace_dir(challenge_id: str, *parts: str) -> str:
    path = os.path.join(WORKSPACE_ROOT, challenge_id, *parts)
    os.makedirs(path, exist_ok=True)
    return path


async def _log_tool(db: AsyncSession, challenge_id: str, tool: str, input_summary: str,
                     output_summary: str, success: bool, duration_ms: int):
    db.add(ToolExecution(challenge_id=challenge_id, tool=tool, input_summary=input_summary[:500],
                          output_summary=output_summary[:2000], success=success, duration_ms=duration_ms))
    await db.commit()


async def _finding(db: AsyncSession, challenge_id: str, message: str, severity: str = "info", source: str = ""):
    db.add(Finding(challenge_id=challenge_id, message=message, severity=severity, source=source))
    await db.commit()
    await publish(challenge_id, {"type": "finding", "severity": severity, "message": message})


async def _emit_step(challenge_id: str, message: str):
    await publish(challenge_id, {"type": "step", "message": message})


async def _run_specialist(db: AsyncSession, challenge: Challenge, category: str,
                           artifacts: list[Artifact], all_text: str) -> list[flag_logic.FlagCandidate]:
    candidates: list[flag_logic.FlagCandidate] = []
    t0 = time.monotonic()
    await publish(challenge.id, {"type": "tool_started", "tool": f"{category}_agent"})

    if category == "crypto":
        for hit in crypto.try_base64(all_text):
            await _finding(db, challenge.id, f"Base64 string decoded to: {hit['output'][:120]}", source="crypto_agent")
            candidates += flag_logic.extract_candidates(hit["output"], "crypto:base64")
        for hit in crypto.try_hex(all_text):
            await _finding(db, challenge.id, f"Hex string decoded to: {hit['output'][:120]}", source="crypto_agent")
            candidates += flag_logic.extract_candidates(hit["output"], "crypto:hex")
        for shift in crypto.caesar_all_shifts(all_text):
            candidates += flag_logic.extract_candidates(shift["output"], f"crypto:caesar_shift_{shift['shift']}")
        for art in artifacts:
            if art.kind == "file" and os.path.exists(art.path) and art.size < 2_000_000:
                with open(art.path, "rb") as f:
                    data = f.read()
                for hit in crypto.xor_single_byte_bruteforce(data):
                    await _finding(db, challenge.id,
                                    f"Single-byte XOR key 0x{hit['key']:02x} on {art.name} produced printable text",
                                    source="crypto_agent")
                    candidates += flag_logic.extract_candidates(hit["output"], f"crypto:xor:{art.name}")

    elif category == "forensics":
        for art in artifacts:
            if art.kind != "file" or not os.path.exists(art.path):
                continue
            file_type = await forensics.run_file_cmd(art.path)
            await _finding(db, challenge.id, f"{art.name}: identified as {file_type}", source="forensics_agent")
            ent = forensics.entropy(art.path)
            if ent > 7.5:
                await _finding(db, challenge.id,
                                f"{art.name} has high entropy ({ent}) -- may be encrypted/compressed/packed",
                                severity="interesting", source="forensics_agent")
            if art.name.lower().endswith(".zip") or forensics.identify_signature(art.path) == "ZIP archive":
                try:
                    extracted = forensics.extract_zip(art.path, workspace_dir(challenge.id, "extracted"))
                    for ex_path in extracted:
                        await _finding(db, challenge.id, f"Extracted {os.path.basename(ex_path)} from {art.name}",
                                        source="forensics_agent")
                        if os.path.getsize(ex_path) < 2_000_000:
                            with open(ex_path, "rb") as f:
                                text = f.read().decode("utf-8", errors="replace")
                            candidates += flag_logic.extract_candidates(text, f"forensics:extracted:{os.path.basename(ex_path)}")
                except Exception as e:
                    await _finding(db, challenge.id, f"Could not extract {art.name} as ZIP: {e}", severity="warning")
            elif art.name.lower().endswith(".png"):
                appended = forensics.find_trailing_data_after_png_iend(art.path)
                if appended:
                    await _finding(db, challenge.id,
                                    f"{art.name} has {len(appended)} byte(s) appended after the PNG IEND chunk",
                                    severity="interesting", source="forensics_agent")
                    if appended.startswith(b"PK\x03\x04"):
                        # It's itself a ZIP -- write it out and extract.
                        appended_zip_path = os.path.join(workspace_dir(challenge.id, "extracted"),
                                                           f"{art.name}.appended.zip")
                        with open(appended_zip_path, "wb") as f:
                            f.write(appended)
                        try:
                            extracted = forensics.extract_zip(appended_zip_path, workspace_dir(challenge.id, "extracted"))
                            for ex_path in extracted:
                                await _finding(db, challenge.id,
                                                f"Extracted {os.path.basename(ex_path)} from data appended to {art.name}",
                                                source="forensics_agent")
                                if os.path.getsize(ex_path) < 2_000_000:
                                    with open(ex_path, "rb") as f:
                                        text = f.read().decode("utf-8", errors="replace")
                                    candidates += flag_logic.extract_candidates(
                                        text, f"forensics:appended_zip:{os.path.basename(ex_path)}")
                        except Exception as e:
                            await _finding(db, challenge.id, f"Could not extract appended ZIP from {art.name}: {e}",
                                            severity="warning")
                    else:
                        candidates += flag_logic.extract_candidates(
                            appended.decode("utf-8", errors="replace"), f"forensics:appended:{art.name}")
            strings_found = forensics.extract_strings(art.path)
            candidates += flag_logic.extract_candidates("\n".join(strings_found), f"forensics:strings:{art.name}")

    elif category == "stego":
        for art in artifacts:
            if art.kind != "file" or not os.path.exists(art.path):
                continue
            if not art.name.lower().endswith((".png",)):
                continue
            chunks = forensics.identify_signature(art.path)
            png_chunks = stego.parse_png_chunks(art.path)
            nonstandard = [c for c in png_chunks if not c["standard"]]
            if nonstandard:
                await _finding(db, challenge.id,
                                f"{art.name} has non-standard PNG chunk(s): {[c['type'] for c in nonstandard]}",
                                severity="interesting", source="stego_agent")
                for c in nonstandard:
                    candidates += flag_logic.extract_candidates(c["preview"], f"stego:png_chunk:{c['type']}")
            lsb_text = stego.extract_lsb_text(art.path)
            candidates += flag_logic.extract_candidates(lsb_text, f"stego:lsb:{art.name}")
            if any(ch in lsb_text for ch in ("flag", "FLAG")):
                await _finding(db, challenge.id, f"LSB extraction of {art.name} contains the word 'flag'",
                                severity="interesting", source="stego_agent")

    elif category == "web":
        urls = [a.name for a in artifacts if a.kind == "url"]
        for url in urls:
            result = await web_tool.inspect_url(url)
            if result.get("error"):
                await _finding(db, challenge.id, f"Could not fetch {url}: {result['error']}", severity="warning")
                continue
            await _finding(db, challenge.id, f"Fetched {url} -> HTTP {result['status']}", source="web_agent")
            candidates += flag_logic.extract_candidates(result["body_preview"], f"web:body:{url}")
            candidates += flag_logic.extract_candidates(str(result["headers"]), f"web:headers:{url}")
            if result.get("robots_txt"):
                await _finding(db, challenge.id, f"robots.txt present on {url}", source="web_agent")
                candidates += flag_logic.extract_candidates(result["robots_txt"], f"web:robots:{url}")

    duration_ms = int((time.monotonic() - t0) * 1000)
    await _log_tool(db, challenge.id, f"{category}_agent", "", f"{len(candidates)} candidate(s)", True, duration_ms)
    await publish(challenge.id, {"type": "tool_completed", "tool": f"{category}_agent", "duration": duration_ms / 1000})
    return candidates


async def solve_challenge(db: AsyncSession, challenge: Challenge):
    challenge.status = "solving"
    await db.commit()
    await _emit_step(challenge.id, "Starting solve")

    result = await db.execute(select(Artifact).where(Artifact.challenge_id == challenge.id))
    artifacts = list(result.scalars())

    artifact_names = [a.name for a in artifacts]
    has_urls = any(a.kind == "url" for a in artifacts)
    scores = classify(challenge.description, artifact_names, has_urls)
    challenge.category_scores = scores
    await db.commit()
    await publish(challenge.id, {"type": "classification", "scores": scores})
    top = sorted(scores.items(), key=lambda kv: kv[1], reverse=True)[0]
    await _emit_step(challenge.id, f"Challenge classified as {top[0]} (confidence {top[1]:.2f})")

    all_text_parts = [challenge.description]
    for art in artifacts:
        if art.kind == "url":
            all_text_parts.append(art.name)
        elif os.path.exists(art.path) and art.size < 2_000_000:
            try:
                with open(art.path, "rb") as f:
                    all_text_parts.append(f.read().decode("utf-8", errors="ignore"))
            except Exception:
                pass
    all_text = "\n".join(all_text_parts)

    specialists_to_run = [cat for cat, score in scores.items() if score >= CONFIDENCE_THRESHOLD and cat in
                           ("crypto", "forensics", "stego", "web")]
    if not specialists_to_run:
        specialists_to_run = ["crypto", "forensics"]  # always try the cheap, safe defaults

    all_candidates: list[flag_logic.FlagCandidate] = []
    for cat in specialists_to_run:
        try:
            all_candidates += await _run_specialist(db, challenge, cat, artifacts, all_text)
        except Exception as e:
            await _finding(db, challenge.id, f"{cat}_agent failed: {e}", severity="warning", source=cat)

    # Also always scan the raw combined text directly (covers plaintext flags).
    all_candidates += flag_logic.extract_candidates(all_text, "raw_description_and_text_artifacts")

    # Dedupe by candidate string, keep highest-confidence source.
    by_value: dict[str, flag_logic.FlagCandidate] = {}
    for c in all_candidates:
        if c.candidate not in by_value or c.confidence > by_value[c.candidate].confidence:
            by_value[c.candidate] = c

    # Verify: a candidate seen from more than one independent source/tool
    # counts as independently reproduced.
    source_counts: dict[str, int] = {}
    for c in all_candidates:
        source_counts[c.candidate] = source_counts.get(c.candidate, 0) + 1

    verified = []
    for value, cand in by_value.items():
        reproduced = source_counts[value] > 1
        v = flag_logic.verify(cand, decode_chain_succeeded="raw_description" not in cand.source,
                               reproduced_independently=reproduced)
        verified.append(v)
        db.add(FlagCandidateRow(challenge_id=challenge.id, candidate=v.candidate, source=v.source,
                                 confidence=v.confidence, status=v.status, evidence=v.evidence))
        await publish(challenge.id, {"type": "flag_candidate", "candidate": v.candidate,
                                      "confidence": v.confidence, "status": v.status})
    await db.commit()

    challenge.status = "complete"
    await db.commit()
    best = max(verified, key=lambda v: v.confidence) if verified else None
    await publish(challenge.id, {
        "type": "done",
        "best_flag": best.candidate if best else None,
        "status": best.status if best else "UNCONFIRMED",
        "confidence": best.confidence if best else 0.0,
    })
