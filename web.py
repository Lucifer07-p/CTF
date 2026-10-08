"""
Web CTF inspection -- PASSIVE ONLY.

By design this module never runs a scanner, fuzzer, or exploit tool
(sqlmap/nikto/ffuf/gobuster/nmap are intentionally not implemented here).
It only performs a GET against a URL the user explicitly supplied in the
current request, plus well-known static paths (robots.txt, sitemap.xml) on
the same origin. That's the "authorization" boundary for this MVP: a human
pasted this exact URL into this exact request, every time, rather than the
agent choosing and expanding targets on its own.

If you need active scanning against infrastructure you are genuinely
authorized to test, that belongs in a separate, explicitly-opt-in tool with
its own audit trail -- not bolted on here.
"""
import httpx
from urllib.parse import urljoin, urlparse

MAX_BODY_BYTES = 500_000
TIMEOUT = 10


def _same_origin(base: str, candidate: str) -> bool:
    b, c = urlparse(base), urlparse(candidate)
    return (b.scheme, b.netloc) == (c.scheme, c.netloc)


async def inspect_url(url: str) -> dict:
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        return {"url": url, "error": "only http/https URLs are supported"}

    result = {"url": url, "headers": {}, "status": None, "body_preview": "",
              "robots_txt": None, "sitemap_xml": None, "error": None}

    async with httpx.AsyncClient(follow_redirects=True, timeout=TIMEOUT) as client:
        try:
            resp = await client.get(url)
            result["status"] = resp.status_code
            result["headers"] = dict(resp.headers)
            result["body_preview"] = resp.text[:MAX_BODY_BYTES]
        except Exception as e:
            result["error"] = str(e)
            return result

        for well_known, key in [("/robots.txt", "robots_txt"), ("/sitemap.xml", "sitemap_xml")]:
            try:
                wk_url = urljoin(f"{parsed.scheme}://{parsed.netloc}", well_known)
                if not _same_origin(url, wk_url):
                    continue
                wk_resp = await client.get(wk_url)
                if wk_resp.status_code == 200:
                    result[key] = wk_resp.text[:MAX_BODY_BYTES]
            except Exception:
                continue  # best-effort only

    return result
