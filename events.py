"""
Minimal pub/sub for streaming solving progress to the frontend over SSE.

This is in-memory and per-process, which is the right tradeoff for a single
backend instance. If you scale the API horizontally, swap this for a Redis
pub/sub channel keyed by challenge_id -- the publish/subscribe call sites
below don't need to change, only this module's internals.
"""
import asyncio
import time
from collections import defaultdict
from typing import AsyncIterator

_queues: dict[str, list[asyncio.Queue]] = defaultdict(list)


async def publish(challenge_id: str, event: dict) -> None:
    event = {"ts": time.time(), **event}
    for q in list(_queues.get(challenge_id, [])):
        await q.put(event)


async def subscribe(challenge_id: str) -> AsyncIterator[dict]:
    q: asyncio.Queue = asyncio.Queue()
    _queues[challenge_id].append(q)
    try:
        while True:
            event = await q.get()
            yield event
            if event.get("type") == "done":
                break
    finally:
        _queues[challenge_id].remove(q)
