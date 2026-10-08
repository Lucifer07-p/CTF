"""
Sandboxed execution of external CLI tools (file, strings, exiftool, binwalk, unzip...).

This process-level sandbox is the honest MVP version of section 28/7 of the
spec. It is NOT a container-per-execution sandbox -- it runs tools as
subprocesses of the API container with:

  - no shell (argv list, never a shell string)
  - a hard wall-clock timeout
  - CPU and address-space limits via `resource` (POSIX only)
  - output truncated to a byte cap
  - executed inside the challenge's own workspace directory only

For a real multi-tenant deployment, replace `run_tool` with a call that
launches a short-lived, network-restricted, read-only-rootfs Docker
container per execution (see infra/docker/sandbox.Dockerfile for a starting
point) instead of a subprocess. The call signature below is written so that
swap doesn't ripple through the rest of the codebase.
"""
import asyncio
import resource
import shutil
import time
from dataclasses import dataclass

MAX_OUTPUT_BYTES = 200_000
DEFAULT_TIMEOUT = 20
MAX_CPU_SECONDS = 10
MAX_MEMORY_BYTES = 512 * 1024 * 1024  # 512MB


@dataclass
class ToolResult:
    tool: str
    success: bool
    stdout: str
    stderr: str
    duration_ms: int
    error: str | None = None


def _limit_resources():
    # Runs in the child process after fork, before exec.
    resource.setrlimit(resource.RLIMIT_CPU, (MAX_CPU_SECONDS, MAX_CPU_SECONDS))
    resource.setrlimit(resource.RLIMIT_AS, (MAX_MEMORY_BYTES, MAX_MEMORY_BYTES))
    resource.setrlimit(resource.RLIMIT_NPROC, (32, 32))


def tool_available(binary: str) -> bool:
    return shutil.which(binary) is not None


async def run_tool(argv: list[str], cwd: str, timeout: int = DEFAULT_TIMEOUT) -> ToolResult:
    """Run one external tool with argv (never a shell string) inside cwd."""
    name = argv[0]
    if not tool_available(name):
        return ToolResult(tool=name, success=False, stdout="", stderr="",
                           duration_ms=0, error=f"tool '{name}' not installed in sandbox")

    start = time.monotonic()
    try:
        proc = await asyncio.create_subprocess_exec(
            *argv,
            cwd=cwd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            preexec_fn=_limit_resources,
        )
        try:
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
        except asyncio.TimeoutError:
            proc.kill()
            await proc.wait()
            return ToolResult(tool=name, success=False, stdout="", stderr="",
                               duration_ms=int((time.monotonic() - start) * 1000),
                               error=f"timed out after {timeout}s")
        duration_ms = int((time.monotonic() - start) * 1000)
        return ToolResult(
            tool=name,
            success=proc.returncode == 0,
            stdout=stdout[:MAX_OUTPUT_BYTES].decode("utf-8", errors="replace"),
            stderr=stderr[:MAX_OUTPUT_BYTES].decode("utf-8", errors="replace"),
            duration_ms=duration_ms,
        )
    except Exception as e:  # never let a tool crash the solving process
        return ToolResult(tool=name, success=False, stdout="", stderr="",
                           duration_ms=int((time.monotonic() - start) * 1000), error=str(e))
