# CTF Copilot

An assistant for **authorized** CTF challenges: paste a description, upload files
and/or a challenge URL, and an orchestrator runs deterministic specialist
agents (crypto / forensics / stego / passive-web) against it, streams
progress live, and surfaces flag candidates with evidence and a
CONFIRMED / PROBABLE / UNCONFIRMED verdict — never just "first regex match wins."

## What's real vs. what the original spec asked for

This is a genuinely working MVP, not mocked screens — every button here does
what it says, and it's been tested against 5 real demo challenges (see
"Running the tests" below) with actual recovered flags, not hand-waved. It
deliberately narrows the original 37-section spec in a few places:

| Spec asked for | This build has | Why |
|---|---|---|
| Postgres + Redis + Celery | SQLite + asyncio background tasks + in-process pub/sub | Zero external services to stand up; swap `DATABASE_URL` for Postgres and the SQLAlchemy models work unchanged. Redis pub/sub is a drop-in replacement for `app/events.py` if you scale the API horizontally. |
| Docker-container-per-tool-execution sandbox | Process-level sandbox (`app/sandbox.py`): no shell, timeout, CPU/memory/process rlimits, output caps | A real per-execution container sandbox is the right answer for untrusted multi-tenant input; `run_tool()`'s signature is written so you can swap the implementation without touching callers. See `infra/docker/sandbox.Dockerfile` for a starting point. |
| Web CTF agent with nmap/sqlmap/ffuf/gobuster/nikto | Passive-only `inspect_url()`: GET + robots.txt/sitemap.xml on a URL you explicitly paste in, nothing else | There's no automatic target-authorization check that's actually enforceable — `AUTHORIZED_TARGET` is a label a user sets, not something verified. Rather than ship scanners behind a checkbox that's trivially set to "yes," this build only ever touches a URL a human pasted into that exact request. Active scanning against infra you're genuinely authorized to test belongs in a separate, explicitly-audited tool. |
| Reverse-engineering, OSINT agents, LLM model routing | Not implemented | No LLM call is in the solving loop at all yet — classification and every specialist are deterministic code (explicitly requested by the spec for crypto math, applied everywhere here for reproducibility). Reverse/OSINT need real binaries/tools this environment doesn't have; model routing has a clear slot (`app/orchestrator.py`) once you add a reasoning step, e.g. for novel cipher identification. |
| Kubernetes manifests, 10 demo challenges, full test matrix | Docker Compose only; 5 demo challenges; targeted pytest suite | Scoped to keep everything in this delivery actually working end-to-end rather than partially mocked. |
| `/cancel` stopping an in-flight solve | Marks status `cancelled` in the DB, but the background `asyncio.Task` keeps running to completion | A real cancel needs a cooperative cancellation token threaded through the orchestrator loop; flagged here rather than silently pretended. |

Nothing above is secretly stubbed in the UI — if a feature isn't implemented,
it isn't on a button.

## Architecture

```
apps/
  api/            FastAPI backend
    app/
      main.py          REST + SSE endpoints
      orchestrator.py  the only component allowed to trigger tool actions
      classifier.py    keyword/artifact-signal based category scoring
      sandbox.py        process-level sandboxed external-tool runner
      flags.py          flag regex extraction + evidence-based verification
      db.py             SQLAlchemy models (SQLite dev / Postgres-ready)
      events.py          in-memory pub/sub -> SSE
      tools/
        crypto.py       base64/hex/caesar/xor -- all deterministic, no LLM
        forensics.py    file typing, entropy, strings, zip (zip-slip guarded)
        stego.py        PNG chunk parsing, LSB extraction, channel split
        web.py           PASSIVE-ONLY url inspection
  web/            Next.js + TypeScript + Tailwind frontend
    app/page.tsx              challenge submission form
    app/challenge/[id]/page.tsx  live SSE solving view + results
demo_challenges/  5 working demo challenges with expected flags
tests/            pytest suite exercising the tools against those demos
docker-compose.yml
.env.example
```

### Agent loop

```
POST /api/challenges        -> create challenge + URL artifacts
POST /.../artifacts          -> upload files (size-capped, hashed)
POST /.../solve               -> kicks off orchestrator as a background task
GET  /.../events (SSE)        -> classification, tool_started/completed,
                                   finding, flag_candidate, done
GET  /.../results             -> final candidates, findings, tools used
```

`orchestrator.solve_challenge()`: classify -> run every specialist scoring
above a confidence threshold -> each specialist runs deterministic analysis
and returns `FlagCandidate`s with a `source` -> dedupe -> a candidate is only
`CONFIRMED` when it's both produced by a successful decode/extraction chain
*and* reproduced by an independent method/source, not on first regex match.

### Target authorization

Every challenge carries a `target_scope`: `LOCAL_ARTIFACT`, `CTF_PLATFORM`,
or `AUTHORIZED_TARGET`. In this MVP it's recorded for audit purposes, but the
only thing that actually gates network access is that the web agent is
passive and only ever touches a URL pasted into that specific request — it
never crawls, expands scope, or runs active tooling regardless of the scope
label. Don't treat the label alone as an enforcement mechanism if you extend
this.

## Running it

```bash
git clone <this-repo>
cd ctf-copilot
cp .env.example .env
docker compose up --build
```

Then open http://localhost:3000, paste a challenge (try one of
`demo_challenges/*/README.md`), optionally upload the matching artifact, and
click **SOLVE CHALLENGE**.

> This was built and unit-tested in a sandboxed environment without
> container/network access, so the Docker Compose build itself hasn't been
> run end-to-end here — the Python tool logic has been (see below). Please
> run `docker compose up --build` yourself and open an issue/fix PR if
> anything doesn't come up cleanly; the two most likely rough edges are
> frontend `npm install` resolution and the `file`/`exiftool`/`binwalk`
> apt package names on your base image.

## Running the tests

```bash
cd ctf-copilot
pip install -r apps/api/requirements.txt pytest
pytest tests/ -v
```

Every test in `tests/` runs the actual tool code against a real artifact in
`demo_challenges/` and asserts the real flag comes out — e.g.
`test_lsb_extraction_recovers_hidden_flag` opens `03_image_stego/hidden.png`
and checks the LSB-extracted text contains
`flag{lsb_hidden_in_plain_sight}`. These were run against the implementation
during development (via a manual harness, since `pytest` itself wasn't
installable in that sandbox) and all passed, including a regression caught
along the way: the first version of "detect appended data" only looked for
a ZIP's own trailing bytes and missed the much more common CTF trick of data
appended after a PNG's `IEND` chunk — fixed as
`find_trailing_data_after_png_iend`.

## Security notes

- Tool execution: no shell, argv-only, timeout + CPU/memory/process rlimits,
  output truncation (`app/sandbox.py`). For multi-tenant production use,
  replace with a container-per-execution sandbox (non-root, read-only
  rootfs, no network by default, dropped capabilities, no Docker socket).
- ZIP extraction is zip-slip guarded and caps file count / total size
  against archive bombs (`forensics.extract_zip`).
- Uploads are size-capped (`MAX_UPLOAD_BYTES`, admin-configurable) and
  content-hashed.
- The web agent never executes challenge-artifact text as instructions —
  everything pulled from a file or HTTP response is treated as data for
  regex/decoding, never interpolated into a command or a prompt that could
  redirect agent behavior.
- No LLM calls exist in the solving path in this build, so prompt-injection
  surface via artifact content is currently not applicable; if you add a
  reasoning step, keep artifact text out of any system/instruction channel.

## Extending

- **Add a tool**: drop a function in `app/tools/<agent>.py`, call it from
  `orchestrator._run_specialist`, emit `_finding`/candidates as the others do.
- **Add a specialist category**: add keywords to `classifier.py`, add a
  branch in `_run_specialist`.
- **Swap SQLite -> Postgres**: set `DATABASE_URL`, add a `db` service to
  `docker-compose.yml`; no model code changes needed.
- **Add model routing**: the natural seam is inside `_run_specialist` for
  categories that benefit from reasoning (novel cipher ID, OCR). Keep
  artifact-derived text as a user/data message, never as system instructions.
