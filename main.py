import asyncio
import hashlib
import os

from fastapi import FastAPI, Depends, UploadFile, File, Form, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sse_starlette.sse import EventSourceResponse
from pydantic import BaseModel

from app.db import init_db, get_session, Challenge, Artifact, Finding, ToolExecution, FlagCandidate
from app.orchestrator import solve_challenge, workspace_dir
from app.events import subscribe

MAX_UPLOAD_BYTES = int(os.environ.get("MAX_UPLOAD_BYTES", 25 * 1024 * 1024))  # 25MB default, admin-configurable
ALLOWED_TARGET_SCOPES = {"LOCAL_ARTIFACT", "CTF_PLATFORM", "AUTHORIZED_TARGET"}

app = FastAPI(title="CTF Copilot API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=os.environ.get("CORS_ORIGINS", "http://localhost:3000").split(","),
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.on_event("startup")
async def _startup():
    await init_db()


class ChallengeCreate(BaseModel):
    title: str = ""
    description: str
    urls: list[str] = []
    target_scope: str = "LOCAL_ARTIFACT"


class ChallengeOut(BaseModel):
    id: str
    title: str
    description: str
    status: str
    target_scope: str
    category_scores: dict

    class Config:
        from_attributes = True


@app.post("/api/challenges", response_model=ChallengeOut)
async def create_challenge(body: ChallengeCreate, db: AsyncSession = Depends(get_session)):
    if body.target_scope not in ALLOWED_TARGET_SCOPES:
        raise HTTPException(400, f"target_scope must be one of {sorted(ALLOWED_TARGET_SCOPES)}")
    challenge = Challenge(title=body.title or "Untitled challenge", description=body.description,
                           target_scope=body.target_scope, status="created")
    db.add(challenge)
    await db.commit()
    await db.refresh(challenge)

    for url in body.urls:
        db.add(Artifact(challenge_id=challenge.id, kind="url", name=url))
    await db.commit()

    return challenge


@app.post("/api/challenges/{challenge_id}/artifacts")
async def upload_artifact(challenge_id: str, file: UploadFile = File(...),
                           db: AsyncSession = Depends(get_session)):
    challenge = await db.get(Challenge, challenge_id)
    if not challenge:
        raise HTTPException(404, "challenge not found")

    dest_dir = workspace_dir(challenge_id, "input")
    safe_name = os.path.basename(file.filename or "upload.bin")
    dest_path = os.path.join(dest_dir, safe_name)

    size = 0
    hasher = hashlib.sha256()
    with open(dest_path, "wb") as out:
        while chunk := await file.read(1024 * 1024):
            size += len(chunk)
            if size > MAX_UPLOAD_BYTES:
                out.close()
                os.remove(dest_path)
                raise HTTPException(413, f"file exceeds {MAX_UPLOAD_BYTES} byte limit")
            hasher.update(chunk)
            out.write(chunk)

    artifact = Artifact(challenge_id=challenge_id, kind="file", name=safe_name, path=dest_path,
                         sha256=hasher.hexdigest(), mime=file.content_type or "", size=size)
    db.add(artifact)
    await db.commit()
    return {"id": artifact.id, "name": artifact.name, "size": artifact.size, "sha256": artifact.sha256}


@app.post("/api/challenges/{challenge_id}/solve")
async def solve(challenge_id: str, db: AsyncSession = Depends(get_session)):
    challenge = await db.get(Challenge, challenge_id)
    if not challenge:
        raise HTTPException(404, "challenge not found")
    if challenge.status == "solving":
        raise HTTPException(409, "already solving")

    asyncio.create_task(_solve_in_background(challenge_id))
    return {"status": "started"}


async def _solve_in_background(challenge_id: str):
    # New session because this runs outside the request's dependency scope.
    from app.db import SessionLocal
    async with SessionLocal() as db:
        challenge = await db.get(Challenge, challenge_id)
        if challenge:
            try:
                await solve_challenge(db, challenge)
            except Exception as e:
                challenge.status = "error"
                db.add(Finding(challenge_id=challenge_id, message=f"Solving failed: {e}", severity="error"))
                await db.commit()


@app.get("/api/challenges/{challenge_id}", response_model=ChallengeOut)
async def get_challenge(challenge_id: str, db: AsyncSession = Depends(get_session)):
    challenge = await db.get(Challenge, challenge_id)
    if not challenge:
        raise HTTPException(404, "challenge not found")
    return challenge


@app.get("/api/challenges/{challenge_id}/events")
async def events(challenge_id: str):
    async def event_generator():
        async for event in subscribe(challenge_id):
            yield {"event": event.get("type", "message"), "data": _json(event)}

    return EventSourceResponse(event_generator())


def _json(obj) -> str:
    import json
    return json.dumps(obj)


@app.get("/api/challenges/{challenge_id}/results")
async def results(challenge_id: str, db: AsyncSession = Depends(get_session)):
    challenge = await db.get(Challenge, challenge_id)
    if not challenge:
        raise HTTPException(404, "challenge not found")

    findings = (await db.execute(select(Finding).where(Finding.challenge_id == challenge_id))).scalars().all()
    tool_runs = (await db.execute(select(ToolExecution).where(ToolExecution.challenge_id == challenge_id))).scalars().all()
    candidates = (await db.execute(select(FlagCandidate).where(FlagCandidate.challenge_id == challenge_id))).scalars().all()

    best = max(candidates, key=lambda c: c.confidence, default=None)

    return {
        "challenge_id": challenge_id,
        "status": challenge.status,
        "category_scores": challenge.category_scores,
        "best_flag": {
            "candidate": best.candidate, "confidence": best.confidence, "status": best.status,
            "evidence": best.evidence, "source": best.source,
        } if best else None,
        "all_candidates": [
            {"candidate": c.candidate, "confidence": c.confidence, "status": c.status, "source": c.source}
            for c in sorted(candidates, key=lambda c: c.confidence, reverse=True)
        ],
        "findings": [{"severity": f.severity, "message": f.message, "source": f.source} for f in findings],
        "tools_used": sorted({t.tool for t in tool_runs}),
        "steps_completed": len(tool_runs),
    }


@app.post("/api/challenges/{challenge_id}/cancel")
async def cancel(challenge_id: str, db: AsyncSession = Depends(get_session)):
    challenge = await db.get(Challenge, challenge_id)
    if not challenge:
        raise HTTPException(404, "challenge not found")
    challenge.status = "cancelled"
    await db.commit()
    return {"status": "cancelled"}


@app.get("/api/health")
async def health():
    return {"status": "ok"}
