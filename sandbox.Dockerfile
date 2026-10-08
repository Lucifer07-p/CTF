# Starting point for a container-per-tool-execution sandbox.
#
# NOT currently wired up -- apps/api/app/sandbox.py runs tools as
# resource-limited subprocesses of the API container instead (see the
# README's "What's real vs spec" table for why). To actually use this:
#   1. docker build -t ctf-copilot-sandbox -f infra/docker/sandbox.Dockerfile .
#   2. Replace app/sandbox.run_tool()'s subprocess call with a call that
#      launches `docker run --rm --network none --read-only --cap-drop=ALL
#      --pids-limit=32 --memory=512m --cpus=1 -v <workspace>:/work:ro
#      ctf-copilot-sandbox <argv...>` (or the equivalent via the Docker SDK),
#      and never mount the Docker socket or host root into it.

FROM python:3.12-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    file \
    exiftool \
    binwalk \
    unzip \
    xxd \
    && rm -rf /var/lib/apt/lists/*

RUN useradd -m -u 1000 sandboxuser
USER sandboxuser
WORKDIR /work

ENTRYPOINT []
